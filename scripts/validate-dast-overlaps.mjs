/**
 * validate-dast-overlaps.mjs — fail-closed duplicate-evidence gate for the DAST pack.
 *
 * Why this exists
 * ---------------
 * Two DAST rules can ask the same question in different wording and nobody
 * notices, because each rule's own tests still pass. The corpus already has
 * five such pairs (recorded in docs/DAST_OVERLAP_LEDGER.json), and one of them
 * was found only by recomputation. This gate recomputes the relation from the
 * rule files on every run and refuses a run where a new pair appears without a
 * reviewed ledger entry and a sentence in the affected rule's limitation.
 *
 * Relation
 * --------
 * A ⊆ B when A and B read the same response header, every positive observation
 * example of A also matches B, and B matches at least one positive example that
 * A does not. A pair whose wider rule observes absence (a missing header or a
 * missing directive, or a rule listed in absenceLike) is EXPECTED: a missing
 * header makes every per-directive rule true, which is documented corpus
 * behaviour rather than duplication.
 *
 * Determinism: reads only rule files and the ledger; no clock, no network.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evalDastCheck } from './validate-packs.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const RULES = join(ROOT, 'packs', 'dast', 'v1', 'rules');
const LEDGER = join(ROOT, 'docs', 'DAST_OVERLAP_LEDGER.json');

const ABSENCE_TYPES = new Set(['missing-response-header', 'response-header-missing-directive']);

let passed = 0;
const failures = [];
function assert(condition, label, detail) {
  if (condition) {
    passed += 1;
    return;
  }
  failures.push(`${label}${detail === undefined ? '' : `\n    ${detail}`}`);
}

const rules = readdirSync(RULES)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => JSON.parse(readFileSync(join(RULES, f), 'utf8')));
const byId = new Map(rules.map((r) => [r.id, r]));
const ledger = JSON.parse(readFileSync(LEDGER, 'utf8'));

assert(ledger.schemaVersion === 'drobon.dast.overlap-ledger/v1', 'ledger: schemaVersion pinned');
assert(/^\d{4}-\d{2}-\d{2}$/.test(ledger.asOf ?? ''), 'ledger: carries an ISO asOf date');
assert(typeof ledger.method === 'string' && ledger.method.length > 80, 'ledger: states the subset method it records');
assert(rules.length >= 100, `ledger: DAST pack present (${rules.length} rules)`);

// --- absenceLike entries must name real value rules -------------------------
const absenceLike = new Set();
for (const entry of ledger.absenceLike ?? []) {
  const rule = byId.get(entry.ruleId);
  assert(rule !== undefined, `absenceLike: ${entry.ruleId} exists`);
  if (rule === undefined) continue;
  assert(!ABSENCE_TYPES.has(rule.check.type), `absenceLike: ${entry.ruleId} is a value-pattern rule`);
  assert(typeof entry.reason === 'string' && entry.reason.length > 40, `absenceLike: ${entry.ruleId} carries a reason`);
  absenceLike.add(entry.ruleId);
}

// --- recompute every subset pair --------------------------------------------
const headerOf = (rule) => (rule.check.header ?? '').toLowerCase();
const pairs = [];
for (const a of rules) {
  for (const b of rules) {
    if (a.id === b.id || headerOf(a) === '' || headerOf(a) !== headerOf(b)) continue;
    const positives = a.tests.filter((t) => t.match === true);
    if (positives.length === 0) continue;
    if (!positives.every((t) => evalDastCheck(b.check, t.observation) === true)) continue;
    const widerOnly = b.tests.filter((t) => t.match === true && evalDastCheck(a.check, t.observation) !== true);
    if (widerOnly.length === 0) continue;
    const expected = ABSENCE_TYPES.has(b.check.type) || absenceLike.has(b.id);
    pairs.push({ narrow: a.id, wide: b.id, header: a.check.header, kind: expected ? 'EXPECTED_ABSENCE_COVERAGE' : 'EVIDENCE_SUBSET' });
  }
}
assert(pairs.length > 0, 'overlap: the relation is computable from the rule corpus', 'no pair found, the corpus or the evaluator changed shape');

// --- reviewed ledger pairs --------------------------------------------------
const seen = new Set();
for (const entry of ledger.pairs ?? []) {
  const key = `${entry.narrow} ${entry.wide}`;
  assert(!seen.has(key), `ledger: ${key} is recorded once`);
  seen.add(key);
  const narrow = byId.get(entry.narrow);
  const wide = byId.get(entry.wide);
  assert(narrow !== undefined && wide !== undefined, `ledger: ${key} references existing rules`);
  if (narrow === undefined || wide === undefined) continue;
  assert(entry.kind === 'EVIDENCE_SUBSET', `ledger: ${key} uses the reviewed kind`, String(entry.kind));
  assert(['REVIEWED_RETAINED', 'BLOCKED_PENDING_OWNER_DECISION'].includes(entry.status),
    `ledger: ${key} carries a reviewed status`, String(entry.status));
  assert(typeof entry.rationale === 'string' && entry.rationale.length > 80, `ledger: ${key} states a rationale`);
  assert(typeof entry.action === 'string' && entry.action.length > 40, `ledger: ${key} states the action`);
  assert(entry.header.toLowerCase() === headerOf(narrow), `ledger: ${key} header matches the rules`, entry.header);

  // The pair must still exist: a stale ledger entry is drift, not history.
  const live = pairs.some((p) => p.narrow === entry.narrow && p.wide === entry.wide);
  assert(live, `ledger: ${key} still describes the tree`, 'pair no longer recomputes');

  // The overlap must be discoverable from the rule it affects.
  const documented = byId.get(entry.documentedIn);
  assert(documented !== undefined, `ledger: ${key} names an existing documentedIn rule`, String(entry.documentedIn));
  if (documented !== undefined) {
    const partner = documented.id === entry.narrow ? entry.wide : entry.narrow;
    assert(documented.limitation.includes(partner),
      `ledger: ${key} is stated in ${documented.id}'s limitation`,
      `${documented.id} does not mention ${partner}`);
    assert([entry.narrow, entry.wide].includes(documented.id),
      `ledger: ${key} is documented in one of the pair`, documented.id);
  }
}

// --- every non-absence pair must be reviewed --------------------------------
const unreviewed = pairs
  .filter((p) => p.kind === 'EVIDENCE_SUBSET')
  .filter((p) => !seen.has(`${p.narrow} ${p.wide}`));
assert(unreviewed.length === 0,
  'overlap: every evidence-subset pair has a reviewed ledger entry',
  unreviewed.map((p) => `${p.narrow} ⊆ ${p.wide} (${p.header})`).join('; '));

// --- the reviewed set must not exceed the computed set ----------------------
const computedKeys = new Set(pairs.map((p) => `${p.narrow} ${p.wide}`));
for (const key of seen) assert(computedKeys.has(key), `ledger: ${key} is a real subset pair`, 'entry has no computed counterpart');

// --- no exact duplicate detection signal ------------------------------------
const signals = new Map();
for (const rule of rules) {
  const key = JSON.stringify(rule.check);
  if (signals.has(key)) failures.push(`duplicate check definition: ${rule.id} == ${signals.get(key)}`);
  else signals.set(key, rule.id);
  passed += 1;
}

const reviewed = (ledger.pairs ?? []).length;
process.stdout.write(`\ndast-overlaps: ${passed} checks; ${pairs.length} subset pairs (${pairs.length - reviewed} expected absence, ${reviewed} reviewed)\n`);
if (failures.length > 0) {
  process.stdout.write(`dast-overlaps: FAIL (${failures.length})\n`);
  for (const f of failures) process.stdout.write(`  NOT OK - ${f}\n`);
  process.exit(1);
}
process.stdout.write('dast-overlaps: PASS\n');
