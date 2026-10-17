/**
 * test-finding-evidence.mjs — Phase 6 Work C/D regression suite.
 *
 * Proves: evidence extraction computes (never invents) locations from actual
 * source text; malformed specs fail explicitly; scan-to-scan transitions
 * implement the five-status contract; finding identity is stable across line
 * shifts; disappearance alone is never remediation.
 */
import {
  FINDING_EVIDENCE_SCHEMA,
  TRANSITION_STATUSES,
  classifyTransition,
  extractEvidence,
  identityOf,
} from './finding-evidence.mjs';

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

const SOURCE = [
  'def get_user(cursor, user_input):',
  '    cursor.execute("SELECT * FROM users WHERE name = \'" + user_input + "\'")',
  '    return cursor.fetchall()',
  '',
  'def admin_note():',
  '    return "cursor.execute(shape) shown in docs"',
].join('\n');

// --- 1. extraction: computed, exact, deterministic ----------------------------
{
  const res = extractEvidence(SOURCE, {
    ruleId: 'DPK-SAST-283',
    path: 'app.py',
    matchedText: '.execute(',
    snapshotId: 'snap-0001',
    commitId: '3307d01d3efb9ed1621a855b4a440a05a62ba1a8',
    method: 'line-regex',
    cwe: 'CWE-89',
    severity: 'HIGH',
  });
  assert(res.ok === true && res.evidence.schemaVersion === FINDING_EVIDENCE_SCHEMA, 'extract: valid spec produces evidence record');
  const ev = res.evidence;
  assert(ev.location.lineFrom === 2 && ev.location.lineTo === 2,
    'extract: line numbers computed from actual text (never invented)', JSON.stringify(ev.location));
  assert(ev.source.excerpt.includes('.execute(') && ev.source.excerpt.includes('user_input'),
    'extract: excerpt is the actual matched source line', ev.source.excerpt);
  assert(ev.source.contextFrom === 1 && ev.source.contextTo === 4 && ev.source.context.length === 4,
    'extract: surrounding context window computed (+/-2 lines)', JSON.stringify({ from: ev.source.contextFrom, to: ev.source.contextTo }));
  assert(ev.analysis.language === 'python' && ev.analysis.method === 'line-regex',
    'extract: language derived from path extension');
  assert(ev.cwe === 'CWE-89' && ev.severity === 'HIGH', 'extract: severity/CWE carried only from declared rule');
  assert(!('cvss' in ev), 'extract: CVSS never invented (absent by design)');
  assert(ev.dataFlowEvidence.state === 'NOT_ASSESSED' && ev.callChainEvidence.state === 'NOT_ASSESSED',
    'extract: unavailable analyses explicitly NOT_ASSESSED');
  assert(typeof ev.remediation === 'object' && ev.remediation === null,
    'extract: remediation is a separate field, never merged into source');
  const again = extractEvidence(SOURCE, {
    ruleId: 'DPK-SAST-283', path: 'app.py', matchedText: '.execute(',
    snapshotId: 'snap-0001', commitId: '3307d01d3efb9ed1621a855b4a440a05a62ba1a8', method: 'line-regex',
    cwe: 'CWE-89', severity: 'HIGH',
  });
  assert(JSON.stringify(res) === JSON.stringify(again), 'extract: deterministic');
  // Second occurrence (docs line) selects occurrence=1 with its own line number.
  const second = extractEvidence(SOURCE, {
    ruleId: 'DPK-SAST-283', path: 'app.py', matchedText: '.execute(', occurrence: 1,
    snapshotId: 'snap-0001', method: 'line-regex',
  });
  assert(second.ok === true && second.evidence.location.lineFrom === 6,
    'extract: occurrence selection maps to the correct source line', JSON.stringify(second.evidence.location));
}

// --- 2. extraction failures are explicit, never guessed -----------------------
{
  assert(extractEvidence(SOURCE, { ruleId: 'X', path: 'a.py', matchedText: 'no-such-span(', snapshotId: 's', method: 'line-regex' }).reason === 'span-not-found-in-source',
    'extract: unknown span => explicit error, no guessed location');
  assert(extractEvidence(SOURCE, { ruleId: 'X', path: 'a.py', matchedText: '.execute(', occurrence: 9, snapshotId: 's', method: 'line-regex' }).reason === 'occurrence-out-of-range',
    'extract: out-of-range occurrence => explicit error');
  assert(extractEvidence(SOURCE, { path: 'a.py', matchedText: '.execute(', snapshotId: 's', method: 'line-regex' }).reason === 'incomplete-spec',
    'extract: missing rule id => explicit error');
  assert(extractEvidence(null, {}).ok === false, 'extract: malformed input => explicit error, no throw');
}

// --- 3. transitions: all five statuses + honest remediation semantics ---------
const PREV = {
  findingId: identityOf('DPK-SAST-283', 'app.py', '.execute('),
  ruleId: 'DPK-SAST-283',
  path: 'app.py',
  evidenceSpans: [
    { excerpt: '    cursor.execute("SELECT * FROM users WHERE name = \'" + user_input + "\'")' },
  ],
};
const FIX_EVIDENCE = { note: 'parameterized the query; regression case EVAL-SAST-002 family', snapshotId: 'snap-0002' };

{
  const still = classifyTransition(PREV, { snapshotId: 'snap-0002', files: { 'app.py': ['def get_user(cursor, user_input):', PREV.evidenceSpans[0].excerpt] } });
  assert(still.status === 'STILL_PRESENT', 'transition: identical span present => STILL_PRESENT', JSON.stringify(still));
  // Line-shift stability: two lines inserted above — identity survives.
  const shifted = classifyTransition(PREV, { snapshotId: 'snap-0002', files: { 'app.py': ['# new comment', '# another', 'def get_user(cursor, user_input):', PREV.evidenceSpans[0].excerpt] } });
  assert(shifted.status === 'STILL_PRESENT', 'identity: finding persists across line shifts', JSON.stringify(shifted));
  const fixed = classifyTransition(PREV, {
    snapshotId: 'snap-0002',
    files: { 'app.py': ['def get_user(cursor, user_input):', '    cursor.execute(sql, (user_input,))'] },
  }, { fixEvidence: FIX_EVIDENCE });
  assert(fixed.status === 'FIXED_VERIFIED', 'transition: absent + covering rescan + fix evidence => FIXED_VERIFIED', JSON.stringify(fixed));
  const vanished = classifyTransition(PREV, {
    snapshotId: 'snap-0002',
    files: { 'app.py': ['def get_user(cursor, user_input):', '    cursor.execute(sql, (user_input,))'] },
  });
  assert(vanished.status === 'NOT_OBSERVED_UNVERIFIED',
    'honesty: disappearance alone is never remediation (=> NOT_OBSERVED_UNVERIFIED)', JSON.stringify(vanished));
  const uncovered = classifyTransition(PREV, { snapshotId: 'snap-0002', files: { 'other.py': ['x'] } }, { fixEvidence: FIX_EVIDENCE });
  assert(uncovered.status === 'NOT_OBSERVED_UNVERIFIED',
    'transition: file not covered by rescan => NOT_OBSERVED_UNVERIFIED even with fix note', JSON.stringify(uncovered));
  const changed = classifyTransition(PREV, {
    snapshotId: 'snap-0002',
    files: { 'app.py': [PREV.evidenceSpans[0].excerpt] },
  }, { currentMatch: { excerpt: '    cursor.execute("SELECT " + other_var)' } });
  assert(changed.status === 'CHANGED_REQUIRES_REVIEW',
    'transition: changed span at same site => CHANGED_REQUIRES_REVIEW', JSON.stringify(changed));
  const partial = classifyTransition(
    { ...PREV, evidenceSpans: [{ excerpt: PREV.evidenceSpans[0].excerpt }, { excerpt: '    os.system("ls " + other)' }] },
    { snapshotId: 'snap-0002', files: { 'app.py': [PREV.evidenceSpans[0].excerpt, 'def other(): pass'] } },
    { fixEvidence: FIX_EVIDENCE },
  );
  assert(partial.status === 'PARTIALLY_FIXED',
    'transition: some spans fixed, some present => PARTIALLY_FIXED', JSON.stringify(partial));
  assert(TRANSITION_STATUSES.includes(partial.status) && TRANSITION_STATUSES.length === 5,
    'transition: exactly the five contract statuses');
  // Malformed inputs never throw and never confirm.
  const malformed = classifyTransition({ evidenceSpans: [] }, { files: {} });
  assert(malformed.status === 'NOT_OBSERVED_UNVERIFIED', 'transition: malformed input => unverified, no throw');
}

process.stdout.write(`\nfinding-evidence: ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
