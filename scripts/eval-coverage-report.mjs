/**
 * eval-coverage-report.mjs — independent-evaluation breadth, measured honestly.
 *
 * Read-only, deterministic. Answers one question: of the detection rules the
 * Dataset ships, how many are exercised by the INDEPENDENT evaluation layer
 * (data/eval-cases, ground truth authored before execution) rather than only by
 * the rule's own bundled pack tests?
 *
 * Pack tests prove a rule matches its own examples. They do not prove the rule
 * was reviewed against independently written fixtures. This report keeps that
 * distinction visible so evaluation breadth is never implied by rule counts.
 *
 * Usage: node scripts/eval-coverage-report.mjs [--json]
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => JSON.parse(readFileSync(join(ROOT, rel), 'utf8'));
const list = (rel) => (existsSync(join(ROOT, rel)) ? readdirSync(join(ROOT, rel)).filter((f) => f.endsWith('.json')).sort() : []);

// Every rule family that has a pack must be in this list. SCA was added to the
// tree on 2026-10-23 and is measured here too: a family missing from this array
// shows up as 1000 "unknown rule ids" and an impossible >100% ratio.
const FAMILIES = ['sast', 'secrets', 'dast', 'sca'];
// Guard: a pack directory that this report does not read would silently leave
// that family out of both numerator and denominator (the 2026-10-23 SCA bug).
const packDirs = existsSync(join(ROOT, 'packs'))
  ? readdirSync(join(ROOT, 'packs'), { withFileTypes: true }).filter((d) => d.isDirectory())
    .map((d) => d.name).filter((name) => existsSync(join(ROOT, 'packs', name, 'v1', 'rules'))).sort()
  : [];
const unmeasured = packDirs.filter((name) => !FAMILIES.includes(name));

const rules = FAMILIES.flatMap((fam) =>
  list(`packs/${fam}/v1/rules`).map((f) => ({ fam, ...read(`packs/${fam}/v1/rules/${f}`) })));
const byId = new Map(rules.map((r) => [r.id, r]));

const cases = list('data/eval-cases').map((f) => read(`data/eval-cases/${f}`));
const exercised = new Map(); // ruleId -> {cases, outcomes:Set, cohorts:Set}
for (const c of cases) {
  const ids = [
    ...(c.expected.detections ?? []).map((d) => d.ruleId),
    ...(c.expected.forbiddenDetections ?? []),
  ];
  for (const id of new Set(ids)) {
    if (!exercised.has(id)) exercised.set(id, { cases: [], assessed: 0, unassessed: 0, cohorts: new Set() });
    const e = exercised.get(id);
    e.cases.push(c.id);
    if (c.groundTruth.state === 'ASSESSED') e.assessed += 1; else e.unassessed += 1;
    e.cohorts.add(c.cohort ?? 'core');
  }
}

const perFamily = {};
for (const r of rules) {
  perFamily[r.fam] = perFamily[r.fam] ?? { rules: 0, exercised: 0 };
  perFamily[r.fam].rules += 1;
  if (exercised.has(r.id)) perFamily[r.fam].exercised += 1;
}
const perCategory = {};
for (const r of rules) {
  perCategory[r.category] = perCategory[r.category] ?? { rules: 0, exercised: 0 };
  perCategory[r.category].rules += 1;
  if (exercised.has(r.id)) perCategory[r.category].exercised += 1;
}
const positiveOnly = [...exercised.entries()].filter(([id]) =>
  !cases.some((c) => (c.expected.forbiddenDetections ?? []).includes(id)));
const unknown = [...exercised.keys()].filter((id) => !byId.has(id));

const summary = {
  schemaVersion: 'drobon.eval.coverage/v1',
  population: 'packs/{sast,secrets,dast,sca}/v1/rules exercised by data/eval-cases (independent ground truth)',
  countingRule: 'a rule counts as exercised when any case names it in expected.detections or expected.forbiddenDetections, whether the case is ASSESSED or UNASSESSED',
  notCounted: 'pack-bundled positive/negative tests prove the rule matches its own examples; they are NOT counted here',
  rulesTotal: rules.length,
  rulesExercised: exercised.size,
  coveragePct: Math.round((exercised.size / rules.length) * 10000) / 100,
  casesTotal: cases.length,
  casesAssessed: cases.filter((c) => c.groundTruth.state === 'ASSESSED').length,
  casesUnassessed: cases.filter((c) => c.groundTruth.state === 'UNASSESSED').length,
  rulesWithPositiveCase: exercised.size - positiveOnly.length,
  rulesWithNoIssueCaseOnly: positiveOnly.length,
  unknownRuleReferences: unknown,
  unmeasuredPackFamilies: unmeasured,
  perFamily,
  perCategory,
  exercisedRules: [...exercised.keys()].sort(),
  limitation: 'Synthetic breadth only. A high count here does not establish real-world detection effectiveness, and the percentage describes this authored population, not the vulnerability landscape.',
};

// A closed downstream pipe (e.g. `| head`) is not a failure of this report.
process.stdout.on('error', (err) => { if (err.code === 'EPIPE') process.exit(0); });

if (process.argv.includes('--json')) {
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
} else {
  process.stdout.write(`independent eval coverage: ${summary.rulesExercised}/${summary.rulesTotal} rules (${summary.coveragePct}%)\n`);
  for (const [fam, v] of Object.entries(perFamily)) process.stdout.write(`  ${fam}: ${v.exercised}/${v.rules}\n`);
  process.stdout.write(`  cases: ${summary.casesTotal} (${summary.casesAssessed} assessed, ${summary.casesUnassessed} UNASSESSED)\n`);
  const top = Object.entries(perCategory).sort((a, b) => b[1].rules - a[1].rules).slice(0, 6);
  process.stdout.write(`  largest categories (exercised/total): ${top.map(([k, v]) => `${k} ${v.exercised}/${v.rules}`).join(', ')}\n`);
  if (unmeasured.length) process.stdout.write(`  ERROR unmeasured pack families (add them to FAMILIES): ${unmeasured.join(', ')}\n`);
  if (unknown.length) process.stdout.write(`  WARNING unknown rule ids: ${unknown.slice(0, 10).join(', ')}${unknown.length > 10 ? ` … (${unknown.length} total)` : ''}\n`);
}
if (unknown.length > 0 || unmeasured.length > 0) process.exit(1);
