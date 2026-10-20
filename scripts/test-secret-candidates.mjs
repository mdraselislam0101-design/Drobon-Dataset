/**
 * test-secret-candidates.mjs — Phase 8 Work B regression suite.
 *
 * GROUND TRUTH IS DECLARED IN THE CASES ARRAY BELOW BEFORE ANY EVALUATION
 * RUNS. All values are original synthetic markers (never real credentials).
 * Value/context strings are assembled from segments so that no source line
 * forms a credential shape (leak-scanner discipline).
 *
 * Proves: entropy alone never escalates; structural non-secrets (hashes,
 * UUIDs, placeholders, templates, short/low-entropy strings) are REJECTED;
 * contextual evidence is required for CANDIDATE; CANDIDATE != confirmed
 * secret; raw values never appear in outputs; deterministic; malformed
 * records fail closed as UNASSESSED.
 *
 * The measured population is THIS synthetic set only — never real-world
 * accuracy. No network, no model, no source modification.
 */
import {
  CANDIDATE_STATES,
  SECRET_CANDIDATE_SCHEMA,
  evaluateSecretCandidate,
  fingerprint,
  promoteCandidate,
  shannonEntropy,
  validateCandidate,
} from './secret-candidates.mjs';

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

// Leak-safe builders (no single line forms a secret shape).
const KW = ['PASS', 'WORD'].join('');
const eq = String.fromCharCode(61);
function assignmentEvidence(value) {
  return ['DB_', KW, eq, value].join('');
}
function headerEvidence(value) {
  return ['Author', 'ization', ': Bea', 'rer ', value].join('');
}

// --- DECLARED GROUND TRUTH (authored before execution) -----------------------
// truth: 'escalate' => expect CANDIDATE; 'reject' => expect REJECTED;
// 'unassessed' => expect UNASSESSED (excluded from TP/FP/FN/TN).
const CASES = [
  {
    id: 'SYN-CAND-001', truth: 'escalate',
    make: (v) => ({ schemaVersion: SECRET_CANDIDATE_SCHEMA, id: 'SYN-CAND-001', synthetic: true, testOnly: true, text: v, contextKind: 'assignment', contextEvidence: assignmentEvidence(v), provenance: { origin: 'original-authored', expectationAuthoredBeforeFirstRun: true } }),
    value: 'Zq7mK9xW4pL2nR8vT6yB3cD5',
    why: '24-char mixed-class synthetic marker in an assignment line — the classic hardcoded-value shape.',
  },
  {
    id: 'SYN-CAND-002', truth: 'escalate',
    make: (v) => ({ schemaVersion: SECRET_CANDIDATE_SCHEMA, id: 'SYN-CAND-002', synthetic: true, testOnly: true, text: v, contextKind: 'url-userinfo', contextEvidence: ['https://svc:', v, '@host.test/'].join(''), provenance: { origin: 'original-authored', expectationAuthoredBeforeFirstRun: true } }),
    value: 'Wk8pR4nM7xQ2vB6zL9cT3yH5',
    why: 'URL-userinfo password shape (cf. DPK-SEC-107 family) with context evidence.',
  },
  {
    id: 'SYN-CAND-003', truth: 'escalate',
    make: (v) => ({ schemaVersion: SECRET_CANDIDATE_SCHEMA, id: 'SYN-CAND-003', synthetic: true, testOnly: true, text: v, contextKind: 'header', contextEvidence: headerEvidence(v), provenance: { origin: 'original-authored', expectationAuthoredBeforeFirstRun: true } }),
    value: 'hG5nM2kP8rQ1wE7zX4cV6bN3mL9',
    why: 'Authorization-header value shape with context evidence.',
  },
  {
    id: 'SYN-CAND-004', truth: 'escalate',
    make: (v) => ({ schemaVersion: SECRET_CANDIDATE_SCHEMA, id: 'SYN-CAND-004', synthetic: true, testOnly: true, text: v, contextKind: 'config', contextEvidence: assignmentEvidence(v), provenance: { origin: 'original-authored', expectationAuthoredBeforeFirstRun: true } }),
    value: 'zxcvbnmasdfghjk',
    why: 'BOUNDARY: 15-char single-class value — entropy passes, class diversity low => CANDIDATE at LOW confidence (not MEDIUM).',
  },
  {
    id: 'SYN-CAND-005', truth: 'reject',
    make: (v) => ({ schemaVersion: SECRET_CANDIDATE_SCHEMA, id: 'SYN-CAND-005', synthetic: true, testOnly: true, text: v, contextKind: 'assignment', contextEvidence: assignmentEvidence(v), provenance: { origin: 'original-authored', expectationAuthoredBeforeFirstRun: true } }),
    value: 'd41d8cd98f00b204e9800998ecf8427ed41d8cd98f00b204e9800998ecf8427e',
    why: 'High-entropy NON-secret: 64-char hex digest shape (sha256-class).',
  },
  {
    id: 'SYN-CAND-006', truth: 'reject',
    make: (v) => ({ schemaVersion: SECRET_CANDIDATE_SCHEMA, id: 'SYN-CAND-006', synthetic: true, testOnly: true, text: v, contextKind: 'assignment', contextEvidence: assignmentEvidence(v), provenance: { origin: 'original-authored', expectationAuthoredBeforeFirstRun: true } }),
    value: '123e4567-e89b-12d3-a456-426614174000',
    why: 'High-entropy NON-secret: UUID public identifier.',
  },
  {
    id: 'SYN-CAND-007', truth: 'reject',
    make: (v) => ({ schemaVersion: SECRET_CANDIDATE_SCHEMA, id: 'SYN-CAND-007', synthetic: true, testOnly: true, text: v, contextKind: 'assignment', contextEvidence: assignmentEvidence(v), provenance: { origin: 'original-authored', expectationAuthoredBeforeFirstRun: true } }),
    value: 'EXAMPLE-NOT-A-REAL-VALUE',
    why: 'Placeholder vocabulary must veto even with context.',
  },
  {
    id: 'SYN-CAND-008', truth: 'reject',
    make: (v) => ({ schemaVersion: SECRET_CANDIDATE_SCHEMA, id: 'SYN-CAND-008', synthetic: true, testOnly: true, text: v, contextKind: 'assignment', contextEvidence: assignmentEvidence(v), provenance: { origin: 'original-authored', expectationAuthoredBeforeFirstRun: true } }),
    value: 'aB3xK9',
    why: 'Short random string — below the 12-char floor.',
  },
  {
    id: 'SYN-CAND-009', truth: 'reject',
    make: (v) => ({ schemaVersion: SECRET_CANDIDATE_SCHEMA, id: 'SYN-CAND-009', synthetic: true, testOnly: true, text: v, contextKind: 'assignment', contextEvidence: assignmentEvidence(v), provenance: { origin: 'original-authored', expectationAuthoredBeforeFirstRun: true } }),
    value: '1.2.3-beta.4',
    why: 'Semver identifier, not a credential.',
  },
  {
    id: 'SYN-CAND-010', truth: 'reject',
    make: (v) => ({ schemaVersion: SECRET_CANDIDATE_SCHEMA, id: 'SYN-CAND-010', synthetic: true, testOnly: true, text: v, contextKind: 'assignment', contextEvidence: assignmentEvidence(v), provenance: { origin: 'original-authored', expectationAuthoredBeforeFirstRun: true } }),
    value: '2026-10-17T00:00:00Z',
    why: 'ISO timestamp identifier, not a credential.',
  },
  {
    id: 'SYN-CAND-011', truth: 'reject',
    make: (v) => ({ schemaVersion: SECRET_CANDIDATE_SCHEMA, id: 'SYN-CAND-011', synthetic: true, testOnly: true, text: v, contextKind: 'other', provenance: { origin: 'original-authored', expectationAuthoredBeforeFirstRun: true } }),
    value: '${API_' + 'TOKEN}',
    why: 'Template/placeholder reference shape must reject outright.',
  },
  {
    id: 'SYN-CAND-012', truth: 'reject',
    make: (v) => ({ schemaVersion: SECRET_CANDIDATE_SCHEMA, id: 'SYN-CAND-012', synthetic: true, testOnly: true, text: v, contextKind: 'assignment', contextEvidence: assignmentEvidence(v), provenance: { origin: 'original-authored', expectationAuthoredBeforeFirstRun: true } }),
    value: 'aabbaabbaabbaabbaabb',
    why: 'Long but low-entropy repetition — entropy floor rejects.',
  },
  {
    id: 'SYN-CAND-013', truth: 'unassessed',
    make: (v) => ({ schemaVersion: SECRET_CANDIDATE_SCHEMA, id: 'SYN-CAND-013', synthetic: true, testOnly: true, text: v, contextKind: 'other', provenance: { origin: 'original-authored', expectationAuthoredBeforeFirstRun: true } }),
    value: 'Jn7bV2xC5mQ8wR1zT4yH6kP3',
    why: 'High-entropy shape but NO contextual evidence — must stay UNASSESSED (entropy alone is never a credential claim).',
  },
  {
    id: 'SYN-CAND-014', truth: 'unassessed',
    make: (v) => ({ schemaVersion: SECRET_CANDIDATE_SCHEMA, id: 'SYN-CAND-014', synthetic: true, testOnly: true, text: v, contextKind: 'assignment', contextEvidence: assignmentEvidence(v) }),
    value: 'Pp4mN8xR2vC6zB9wL3qT7yH5',
    why: 'Malformed provenance (missing flags) — must fail closed as invalid, never evaluate to a detection.',
  },
];

// --- execute against declared ground truth ------------------------------------
const results = CASES.map((c) => ({ ...c, result: evaluateSecretCandidate(c.make(c.value)) }));
const assessed = results.filter((r) => r.truth !== 'unassessed');
const unassessed = results.filter((r) => r.truth === 'unassessed');
let tp = 0; let fp = 0; let fn = 0; let tn = 0;
for (const r of assessed) {
  const predicted = r.result.state === 'CANDIDATE';
  const actual = r.truth === 'escalate';
  if (predicted && actual) tp += 1;
  else if (predicted && !actual) fp += 1;
  else if (!predicted && actual) fn += 1;
  else tn += 1;
}
const recall = tp + fn > 0 ? (tp / (tp + fn)).toFixed(4) : null;
const precision = tp + fp > 0 ? (tp / (tp + fp)).toFixed(4) : null;

assert(tp === 4 && fp === 0 && fn === 0 && tn === 8,
  `metrics: synthetic population 4 TP / 0 FP / 0 FN / 8 TN (assessed ${assessed.length}, unassessed ${unassessed.length})`,
  JSON.stringify({ tp, fp, fn, tn }));
assert(precision === '1.0000' && recall === '1.0000',
  'metrics: precision/recall over the assessed synthetic population only',
  JSON.stringify({ precision, recall }));

// --- state semantics ----------------------------------------------------------
assert(results.find((r) => r.id === 'SYN-CAND-001').result.state === 'CANDIDATE',
  'states: assignment + high-entropy + context => CANDIDATE');
assert(results.find((r) => r.id === 'SYN-CAND-004').result.confidence === 'LOW',
  'boundary: low class diversity caps confidence at LOW');
assert(results.find((r) => r.id === 'SYN-CAND-013').result.state === 'UNASSESSED'
  && results.find((r) => r.id === 'SYN-CAND-013').result.reason === 'no-contextual-evidence',
  'states: entropy without context => UNASSESSED (never a detection)');
assert(results.find((r) => r.id === 'SYN-CAND-014').result.reason === 'invalid-candidate',
  'states: malformed provenance => invalid, fail closed');
assert(results.every((r) => r.result.state !== 'CONFIRMED'),
  'invariant: no output state is ever CONFIRMED (candidate != confirmed secret)');
assert(CANDIDATE_STATES.length === 3, 'states: exactly CANDIDATE/REJECTED/UNASSESSED');

// --- structural non-secrets ---------------------------------------------------
assert(results.find((r) => r.id === 'SYN-CAND-005').result.reason === 'hex-digest-shape',
  'non-secrets: hex digest rejected despite high entropy + context');
assert(results.find((r) => r.id === 'SYN-CAND-006').result.reason === 'uuid-shape',
  'non-secrets: UUID rejected despite high entropy + context');
assert(results.find((r) => r.id === 'SYN-CAND-007').result.reason.startsWith('placeholder-veto'),
  'non-secrets: placeholder vocabulary rejected');
assert(results.find((r) => r.id === 'SYN-CAND-011').result.reason === 'template-or-placeholder-ref',
  'non-secrets: template reference rejected');
assert(results.find((r) => r.id === 'SYN-CAND-012').result.reason === 'low-entropy',
  'non-secrets: repetitive string rejected on entropy floor');

// --- redaction: raw values never leave ----------------------------------------
{
  const serialized = results.map((r) => JSON.stringify(r.result)).join('');
  assert(!serialized.includes('Zq7mK9xW4pL2nR8vT6yB3cD5')
    && !serialized.includes('hG5nM2kP8rQ1wE7zX4cV6bN3mL9')
    && !serialized.includes('d41d8cd98f00b204e9800998ecf8427e'),
    'redaction: raw candidate values never appear in results', '');
  assert(results.find((r) => r.id === 'SYN-CAND-001').result.fingerprint === 'Zq7m…(len=24)',
    'redaction: outputs carry only prefix+length fingerprints',
    results.find((r) => r.id === 'SYN-CAND-001').result.fingerprint);
}

// --- determinism + schema validation ------------------------------------------
{
  const again = CASES.map((c) => evaluateSecretCandidate(c.make(c.value)));
  assert(JSON.stringify(results.map((r) => r.result)) === JSON.stringify(again),
    'determinism: evaluation is pure and repeatable');
  assert(Math.abs(shannonEntropy('abcd') - 2) < 1e-9, 'entropy: uniform 4-ary string = 2 bits/char');
  assert(shannonEntropy('aaaaaaaa') === 0, 'entropy: constant string = 0');
  assert(validateCandidate({}).length > 0, 'schema: empty candidate rejected');
  assert(fingerprint('abcdef').startsWith('abcd…(len=6)'), 'redaction: fingerprint helper bounded');
}

// --- Phase 9: candidate -> finding promotion contract -------------------------
// Ground truth: only method 'independent-rule-evidence' with rule identity and
// exact span evidence may reach VERIFIED. Every other path is UNRESOLVED or
// REJECTED. Expected outcomes declared here before execution.
{
  const good = CASES.find((c) => c.id === 'SYN-CAND-001');
  const evaluation = evaluateSecretCandidate(good.make(good.value));
  const base = good.make(good.value);
  const R = (v) => promoteCandidate(base, evaluation, v);

  // VERIFIED: independent rule family + exact span (matchedText inside excerpt).
  const verified = R({
    method: 'independent-rule-evidence', ruleId: 'DPK-SEC-106', ruleVersion: 1,
    evidencePath: 'svc/config.py', evidenceLineNo: 3,
    matchedText: 'DB_', evidenceExcerpt: assignmentEvidence('…redacted…'),
  });
  assert(verified.findingState === 'VERIFIED' && verified.verification.ruleId === 'DPK-SEC-106',
    'promotion: independent rule evidence with exact span => VERIFIED', JSON.stringify(verified));
  // Re-running the same heuristic is NOT independent verification.
  for (const method of ['re-run-heuristic', 'entropy', 'model-assertion', 'test-label']) {
    const un = R({ method });
    assert(un.findingState === 'UNRESOLVED' && un.reason === 'not-independent-verification',
      `promotion: ${method} is never independent verification`, JSON.stringify(un));
  }
  // Liveness is not implemented — contract boundary only.
  const live = R({ method: 'liveness' });
  assert(live.findingState === 'UNRESOLVED' && live.reason === 'verification-not-implemented',
    'promotion: liveness verification NOT IMPLEMENTED (boundary only)', JSON.stringify(live));
  // Incomplete independent evidence => UNRESOLVED (never invents).
  assert(R(null).findingState === 'UNRESOLVED', 'promotion: absent verification => UNRESOLVED');
  assert(R({ method: 'independent-rule-evidence', ruleId: 'DPK-SEC-106' }).reason === 'independent-evidence-incomplete',
    'promotion: missing span/path/line => UNRESOLVED');
  assert(R({ method: 'independent-rule-evidence', ruleId: 'DPK-SEC-106', evidencePath: 'a.py', evidenceLineNo: 1, matchedText: 'other', evidenceExcerpt: assignmentEvidence('…') }).reason === 'independent-evidence-incomplete',
    'promotion: matchedText not inside excerpt => UNRESOLVED (exact-span required)');
  // Unredacted evidence is refused.
  assert(R({ method: 'independent-rule-evidence', ruleId: 'DPK-SEC-106', evidencePath: 'a.py', evidenceLineNo: 1, matchedText: 'DB_', evidenceExcerpt: assignmentEvidence(good.value) }).reason === 'evidence-not-redacted',
    'promotion: raw value inside evidence excerpt => UNRESOLVED (redaction enforced)');
  // REJECTED candidates stay rejected.
  const bad = CASES.find((c) => c.id === 'SYN-CAND-005');
  const badEval = evaluateSecretCandidate(bad.make(bad.value));
  assert(promoteCandidate(bad.make(bad.value), badEval, { method: 'independent-rule-evidence', ruleId: 'DPK-SEC-1', evidencePath: 'a.py', evidenceLineNo: 1, matchedText: 'x', evidenceExcerpt: 'x' }).findingState === 'REJECTED',
    'promotion: rejected candidate can never be promoted');
  // Candidate state cannot be confused: unassessed evaluation never promotes.
  const noCtx = CASES.find((c) => c.id === 'SYN-CAND-013');
  const noCtxEval = evaluateSecretCandidate(noCtx.make(noCtx.value));
  assert(promoteCandidate(noCtx.make(noCtx.value), noCtxEval, { method: 'independent-rule-evidence', ruleId: 'DPK-SEC-106', evidencePath: 'a.py', evidenceLineNo: 1, matchedText: 'DB_', evidenceExcerpt: assignmentEvidence('…') }).findingState === 'UNRESOLVED',
    'promotion: UNASSESSED evaluation (no context) never reaches VERIFIED');
  // Determinism + leakage on failure paths and serialization.
  const a1 = JSON.stringify(R({ method: 'model-assertion' }));
  const a2 = JSON.stringify(R({ method: 'model-assertion' }));
  assert(a1 === a2, 'promotion: deterministic across identical inputs');
  const leakScan = [
    JSON.stringify(verified), JSON.stringify(R(null)), JSON.stringify(live),
    JSON.stringify(R({ method: 'independent-rule-evidence', ruleId: 'bad!', evidencePath: 'a.py', evidenceLineNo: 1, matchedText: 'x', evidenceExcerpt: 'x' })),
  ].join('');
  assert(!leakScan.includes(good.value) && !leakScan.includes('hG5nM2kP8rQ1wE7zX4cV6bN3mL9'),
    'promotion: failure paths and outputs never contain raw values', '');
  // Unknown/absent evaluation objects fail closed.
  assert(promoteCandidate(base, null, { method: 'liveness' }).reason === 'invalid-evaluation',
    'promotion: invalid evaluation fails closed');
}

process.stdout.write(`\nsecret-candidates: ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
