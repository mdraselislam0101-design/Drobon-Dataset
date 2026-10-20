#!/usr/bin/env node
/**
 * completion-ledger.mjs — the answer to "is the Dataset done?", computed rather
 * than asserted.
 *
 *   node scripts/completion-ledger.mjs --write   # regenerate docs/DATASET_COMPLETION_LEDGER.{json,md}
 *   node scripts/completion-ledger.mjs --check   # fail if either file no longer reproduces
 *
 * Design rules (deliberate):
 *   - every number is recomputed from the tree or from a committed register;
 *   - dimensions are never averaged into one percentage (the repository's own
 *     methodology forbids mixing denominators);
 *   - a dimension that is not complete must name a blocker class from a closed
 *     vocabulary and a next action that is actually executable by that owner;
 *   - a dimension claiming COMPLETE must name a verification command that exists
 *     in package.json.
 *
 * No network, no writes unless --write. Runs in `npm test` (check mode).
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const JSON_OUT = 'docs/DATASET_COMPLETION_LEDGER.json';
const MD_OUT = 'docs/DATASET_COMPLETION_LEDGER.md';
const WRITE = process.argv.includes('--write');

const read = (rel) => readFileSync(join(ROOT, rel), 'utf8');
const readJson = (rel) => JSON.parse(read(rel));
const inventory = readJson('docs/CURRENT_INVENTORY.json');
const conformance = readJson('interop/app-conformance.json');
const dastSurface = readJson('interop/app-dast-reachability.json');
const targets = readJson('docs/CORPUS_TARGETS.json');
const pkg = readJson('package.json');

const counts = inventory.counts;
// --- evaluation depth (independent of the validator's namespace counting) ---
const evalCases = [];
{
  const fs = await import('node:fs');
  for (const file of fs.readdirSync(join(ROOT, 'data/eval-cases')).filter((f) => f.endsWith('.json')).sort()) {
    evalCases.push(JSON.parse(read(`data/eval-cases/${file}`)));
  }
}
const positiveRules = new Set();
const negativeRules = new Set();
for (const testCase of evalCases) {
  for (const d of testCase.expected?.detections ?? []) positiveRules.add(d.ruleId);
  for (const r of testCase.expected?.forbiddenDetections ?? []) negativeRules.add(typeof r === 'string' ? r : r.ruleId);
}
const packRules = [];
{
  const fs = await import('node:fs');
  for (const family of ['sast', 'secrets', 'dast']) {
    for (const file of fs.readdirSync(join(ROOT, 'packs', family, 'v1', 'rules')).filter((f) => f.endsWith('.json')).sort()) {
      packRules.push({ family, ...JSON.parse(read(`packs/${family}/v1/rules/${file}`)) });
    }
  }
}
const sastRules = packRules.filter((r) => r.family === 'sast');
const universalRules = sastRules.filter((r) => (r.languages ?? []).length === 0);
const universalBoth = universalRules.filter((r) => positiveRules.has(r.id) && negativeRules.has(r.id));

// Rules named by an authored case, restricted to ids that exist in a pack. Counting
// the raw set would let a stale or typo'd id inflate the numerator.
const packRuleIds = new Set(packRules.map((r) => r.id));
const positiveRuleCount = [...positiveRules].filter((id) => packRuleIds.has(id)).length;
const negativeRuleCount = [...negativeRules].filter((id) => packRuleIds.has(id)).length;
const pctOf = (a, b) => (b === 0 ? null : Math.round((a / b) * 1000) / 10);

// The knowledge graph is only complete when the three parallel trees cover exactly the
// rule set, so the numerator is the *weakest* of the three, not any one of them.
const graphCoverage = Math.min(counts.patterns, counts.records, counts.remediation);

// CWE: distinct ids required by the pack rules vs entries present in knowledge/cwe.
const cweIdsInPacks = new Set();
const cweEntriesOnDisk = new Set();
{
  const fs = await import('node:fs');
  for (const rule of packRules) {
    const ids = Array.isArray(rule.cwe) ? rule.cwe : rule.cwe ? [rule.cwe] : [];
    for (const id of ids) cweIdsInPacks.add(id);
  }
  for (const file of fs.readdirSync(join(ROOT, 'knowledge/cwe')).filter((f) => f.endsWith('.json'))) {
    cweEntriesOnDisk.add(file.replace(/\.json$/, ''));
  }
}
const cweCovered = [...cweIdsInPacks].filter((id) => cweEntriesOnDisk.has(id)).length;

// --- declared test totals (pack-level) ---
const declaredTests = packRules.reduce((n, r) => n + (r.tests ?? []).length, 0);

// Release readiness gates are read from the matrix, never restated by hand, so the
// ledger cannot claim a verdict the matrix does not carry.
const readiness = readJson('docs/RELEASE_READINESS_MATRIX.json');
const readinessPass = readiness.gates.filter((g) => g.status === 'PASS').length;
const rulesWithPosAndNegTest = packRules.filter((r) => {
  const tests = r.tests ?? [];
  return tests.some((t) => t.match === true) && tests.some((t) => t.match === false);
}).length;

const advisoryItems = targets.categories.find((c) => c.id === 'advisory-record')?.validatedCount ?? 0;
const targetItems = targets.targetMinUniqueItems;
const advisoryPct = Math.round((advisoryItems / targetItems) * 10000) / 100;

const licenseAbsent = !(() => {
  try {
    read('LICENSE');
    return true;
  } catch {
    return false;
  }
})();

// --- generated-artefact freshness -------------------------------------------
// The ledger must not record a world it cannot reproduce: every committed
// generated artefact is re-checked here, and a stale one turns the row PARTIAL
// as well as failing this script.
const freshnessChecks = [
  ['docs/CURRENT_INVENTORY.json', 'scripts/inventory.mjs', ['--check']],
  ['docs/CAPABILITY_COVERAGE_MATRIX.md', 'scripts/render-capability-coverage.mjs', ['--check']],
  ['docs/APP_LANGUAGE_ID_MAPPING.md', 'scripts/validate-app-language-ids.mjs', []],
  ['interop/app-conformance.json', 'scripts/gen-app-conformance.mjs', ['--check']],
  ['DROBON_COVERAGE_EVIDENCE.json', 'scripts/originality-report.mjs', ['--check']],
];
const staleArtefacts = [];
{
  const { execFileSync } = await import('node:child_process');
  for (const [artefact, script, args] of freshnessChecks) {
    try {
      execFileSync(process.execPath, [join(ROOT, script), ...args], { cwd: ROOT, stdio: 'pipe' });
    } catch {
      staleArtefacts.push(artefact);
    }
  }
}

const dim = (id, title, o) => ({ id, title, ...o });

const dimensions = [
  dim('packs.sast', 'SAST rule pack against its planning target', {
    measured: counts.sastRules,
    denominator: 1000,
    unit: 'rules',
    pct: Math.round((counts.sastRules / 1000) * 1000) / 10,
    status: 'PARTIAL',
    blocker: 'EVIDENCE_GATED',
    detail: 'Every added rule needs published evidence and its own tests; padding is forbidden by docs/PACKS.md. 50 rules remain against the 1000-rule planning target (docs/EVAL_ID_CAPACITY_AND_FINAL_GAP_CLOSURE_2026-10-19.md §H found no reachable candidate that is not padding).',
    nextAction: 'Author the next evidence-backed batch (one cell file per batch, pos+neg tests, remediation + CWE), then regenerate.',
    verification: 'npm run validate:packs',
  }),
  dim('packs.dast', 'DAST check pack against its 500 target', {
    measured: counts.dastRules,
    denominator: 500,
    unit: 'checks',
    pct: Math.round((counts.dastRules / 500) * 1000) / 10,
    status: 'PARTIAL',
    blocker: 'EVIDENCE_GATED',
    detail: `The check vocabulary is closed at seven types; every new check must be semantically distinct, tested against observations and independently evaluated. ${500 - counts.dastRules} remain.`,
    nextAction: 'Author the next capability-aligned batch inside the closed check vocabulary (docs/DAST_CAPABILITY_ALIGNED_500_2026-10-20.md pattern), never as variants of one question.',
    verification: 'npm run validate:packs',
  }),
  dim('packs.secrets', 'Secrets rule pack', {
    measured: counts.secretsRules,
    denominator: null,
    unit: 'rules',
    pct: null,
    status: 'COMPLETE',
    blocker: null,
    detail: 'No planning target is documented for this family; completion is defined as schema-valid, tested and CWE-linked, which holds for all 97.',
    nextAction: 'None unless a new credential format is documented by its vendor.',
    verification: 'npm run validate:packs',
  }),
  dim('knowledge.graph', 'Rule ↔ pattern ↔ record ↔ remediation graph', {
    measured: graphCoverage,
    denominator: counts.packRules,
    unit: 'entries (weakest of the three trees)',
    pct: pctOf(graphCoverage, counts.packRules),
    status: 'COMPLETE',
    blocker: null,
    detail: `patterns ${counts.patterns} / records ${counts.records} / remediation ${counts.remediation} against ${counts.packRules} rules: strict 1:1:1:1 in both directions, 0 orphans, enforced by the consistency suite.`,
    nextAction: 'None.',
    verification: 'node scripts/test-consistency.mjs',
  }),
  dim('cwe.reference', 'CWE reference coverage', {
    measured: cweCovered,
    denominator: cweIdsInPacks.size,
    unit: 'CWE ids required by the pack rules',
    pct: pctOf(cweCovered, cweIdsInPacks.size),
    status: 'COMPLETE',
    blocker: null,
    detail: 'Every pack rule CWE resolves to a knowledge/cwe entry with a pinned MITRE URL and cweVersion.',
    nextAction: 'None; a new CWE id is added with the rule that needs it.',
    verification: 'npm run validate:cwe',
  }),
  dim('tests.pack-level', 'Declared pack tests executed', {
    measured: rulesWithPosAndNegTest,
    denominator: counts.packRules,
    unit: 'rules',
    pct: pctOf(rulesWithPosAndNegTest, counts.packRules),
    status: 'COMPLETE',
    blocker: null,
    detail: `${rulesWithPosAndNegTest} of ${counts.packRules} rules declare at least one positive and one negative test; ${declaredTests} declared tests execute in the validator, with ReDoS lint and CWE checks.`,
    nextAction: 'None.',
    verification: 'npm run validate:packs',
  }),
  dim('eval.positive', 'Independent evaluation: rules with a positive case', {
    measured: positiveRuleCount,
    denominator: counts.packRules,
    unit: 'rules',
    pct: pctOf(positiveRuleCount, counts.packRules),
    status: 'PARTIAL',
    blocker: 'OWNER_DECISION_REQUIRED',
    detail: '8 SAST rules match 2–3 characters while the evidence contract requires mustContain >= 4, so no authored positive case can satisfy the validator (BLK-EVAL-01). Every other rule has one.',
    nextAction: 'Owner picks: (a) allow the full match as evidence when it is shorter than 4 characters, (b) extend those 8 detectors with context, or (c) accept the gap in writing as a permanent limitation.',
    verification: 'npm run test:eval',
  }),
  dim('eval.negative', 'Independent evaluation: rules with a negative control', {
    measured: negativeRuleCount,
    denominator: counts.packRules,
    unit: 'rules',
    pct: pctOf(negativeRuleCount, counts.packRules),
    status: 'PARTIAL',
    blocker: 'EVIDENCE_GATED',
    detail: 'A negative control has to be an authored fixture that the rule must not fire on; deriving them mechanically from each rule\'s own negative test would be circular and is explicitly not counted (counting rule in scripts/eval-coverage-report.mjs). Closed on 2026-10-21: all 11 universal rules (EVAL-SAST-256…264) and one ordinary-code control per language (EVAL-SAST-265…270: python, javascript, java, php, ruby, csharp), where every language-gated detector is named and must stay silent on benign, idiomatic code.',
    nextAction: 'Continue in batches, highest false-positive risk first: high-severity lexical rules with short literals, then one control per category.',
    verification: 'npm run test:eval',
  }),
  dim('eval.universal', 'Universal rules with both a positive case and a negative control', {
    measured: universalBoth.length,
    denominator: universalRules.length,
    unit: 'rules',
    pct: universalRules.length === 0 ? 100 : Math.round((universalBoth.length / universalRules.length) * 1000) / 10,
    status: universalBoth.length === universalRules.length ? 'COMPLETE' : 'PARTIAL',
    blocker: null,
    detail: 'Universal rules run on every analysed file, so they carry the highest false-positive cost. All 11 now have an independent positive case and an independent negative control.',
    nextAction: 'Keep the invariant: a new universal rule ships with both.',
    verification: 'npm run test:eval',
  }),
  dim('eval.quality', 'Evaluation outcome quality on assessed cases', {
    measured: null,
    denominator: null,
    unit: 'cases',
    pct: null,
    status: 'POLICY_BOUND',
    blocker: 'POLICY_DECISION',
    detail: `${counts.evalCasesTotal} cases (${counts.evalCasesAssessed} assessed, ${counts.evalCasesUnassessed} UNASSESSED). The UNASSESSED cases are excluded from scoring by policy and the one preserved false positive (EVAL-SAST-008) stays visible. Precision/recall are reported by the runner, not stored here, so they cannot go stale.`,
    nextAction: 'None until the scoring policy for the 11 UNASSESSED shapes is decided (GAP-038).',
    verification: 'node scripts/run-eval.mjs',
  }),
  dim('runtime.advisories', 'Production vulnerability intelligence', {
    measured: advisoryItems,
    denominator: targetItems,
    unit: 'identity items',
    pct: advisoryPct,
    status: 'BLOCKED_OWNER',
    blocker: 'LICENSE_AND_PRODUCTION_AUTH',
    detail: `The seed is ${advisoryItems} identity items (${counts.advisoryRealFiles} reviewed files, ${counts.advisoryIds} advisory ids), all validated-only. verifiedProductionCount stays 0 until a licence grant and a written production-stage approval exist (GATE-1…GATE-4).`,
    nextAction: 'Owner: choose the licence (GATE-2), approve a named production batch with a reviewer (GATE-1/GATE-3), then run the importer in 10k steps.',
    verification: 'npm run validate:corpus',
  }),
  dim('rights.license', 'Licence grant', {
    measured: licenseAbsent ? 0 : 1,
    denominator: 1,
    unit: 'grant file',
    pct: licenseAbsent ? 0 : 100,
    status: licenseAbsent ? 'BLOCKED_OWNER' : 'COMPLETE',
    blocker: licenseAbsent ? 'OWNER_DECISION_REQUIRED' : null,
    detail: 'No LICENSE file exists, so no rights are granted. Since the App reads this corpus at runtime (App 9360dd1), this blocks any deployment, not only redistribution.',
    nextAction: 'Owner installs an approved grant (proprietary draft or an open licence) with the matrix + licence-record updates the validators require.',
    verification: 'npm run validate:matrix',
  }),
  dim('app.reachability', 'SAST rules reachable through the App language gate', {
    measured: conformance.languageReachability.rulesReachable,
    denominator: counts.sastRules,
    unit: 'rules',
    pct: Math.round((conformance.languageReachability.rulesReachable / counts.sastRules) * 1000) / 10,
    status: 'BLOCKED_APP',
    blocker: 'APP_CATALOG',
    detail: `${conformance.languageReachability.needsAppFamily} pack language ids have no App family (sshd, k8s, nginx, ini, properties, config formats), so ${conformance.languageReachability.rulesUnreachable} rules cannot fire. Two aliases (shell→shell-posix, gha→github-actions) are already declared and would restore 36 rules once the App accepts the dataset id.`,
    nextAction: 'App adds the config-format families or accepts the dataset ids; this repository keeps docs/APP_LANGUAGE_ID_MAPPING.md + the gate green.',
    verification: 'node scripts/validate-app-language-ids.mjs',
  }),
  dim('app.dast-reachability', 'DAST rules evaluable through the App response surface', {
    measured: dastSurface.totals.reachable,
    denominator: dastSurface.totals.dastRules,
    unit: 'rules',
    pct: dastSurface.totals.reachablePct,
    status: 'BLOCKED_APP',
    blocker: 'APP_RESPONSE_SURFACE',
    detail: `Both App DAST engines hand the evaluator only ${dastSurface.surface.inspectedResponseHeaders.length} response headers (apps/api/src/scans/dast/engine.ts, activeEngine.ts) and clip the body to ${dastSurface.surface.bodyInspectionBytes} bytes, so ${dastSurface.totals.unreachable} rules can never fire in the product even though they are correct: ${dastSurface.headerActions.slice(0, 4).map((h) => `${h.header} (${h.rulesThatBecomeReachable})`).join(', ')} and ${Math.max(0, dastSurface.headerActions.length - 4)} more headers. Body rules are reachable but bounded by the clip.`,
    nextAction: `App forwards the header names in interop/app-dast-reachability.json (headerActions) or the dataset stops counting those rules as product coverage; the register is machine-checked by scripts/validate-app-dast-reachability.mjs.`,
    verification: 'node scripts/validate-app-dast-reachability.mjs --check',
  }),
  dim('app.loader-conformance', 'App loader checklist steps implemented', {
    measured: conformance.loaderChecklist.filter((s) => s.status === 'DONE').length,
    denominator: conformance.loaderChecklist.length,
    unit: 'steps',
    pct: Math.round((conformance.loaderChecklist.filter((s) => s.status === 'DONE').length / conformance.loaderChecklist.length) * 1000) / 10,
    status: 'BLOCKED_APP',
    blocker: 'APP_LOADER',
    detail: 'Steps 2 (language gate) and 5 (secrets redaction) are done; step 1 is partial; steps 3 (ReDoS budget), 4 (execute declared tests at load) and 6 (pack version on findings) are missing.',
    nextAction: 'App implements steps 1, 3, 4 and 6; interop/app-conformance.json gives the exact failing set to test against.',
    verification: 'node scripts/gen-app-conformance.mjs --check',
  }),
  dim('app.dast-parity', 'DAST declared-test parity in the App evaluator', {
    measured: conformance.parity.dast.declaredTests - conformance.parity.dast.mismatches,
    denominator: conformance.parity.dast.declaredTests,
    unit: 'declared tests',
    pct: Math.round(((conformance.parity.dast.declaredTests - conformance.parity.dast.mismatches) / conformance.parity.dast.declaredTests) * 1000) / 10,
    status: 'BLOCKED_APP',
    blocker: 'APP_EVALUATOR',
    detail: `${conformance.parity.dast.mismatches} divergences on ${conformance.parity.dast.mismatchedRules.length} rules (cookie model, blank header values, cross-value array joins), measured by replaying every declared test through scripts/lib/app-evaluator-profile.mjs (a port of the App evaluator at 9360dd1), not by driving a running App. The dataset keeps the browser-accurate semantics; the App must port them.`,
    nextAction: 'App ports scripts/lib/set-cookie.mjs semantics and fixes the blank-value branch; interop/app-conformance.json lists every affected test.',
    verification: 'node scripts/gen-app-conformance.mjs --check',
  }),
  dim('app.remediation-surface', 'Remediation entries surfaced to users', {
    measured: 0,
    denominator: counts.remediation,
    unit: 'entries',
    pct: 0,
    status: 'BLOCKED_APP',
    blocker: 'APP_LOADER',
    detail: `All ${counts.remediation} entries load into the App dataset service, but getRemediationMap has no caller and remediationGuidanceForFinding still returns UNAVAILABLE.`,
    nextAction: 'App wires the resolver into findings, reports and the assistant (GAP-008).',
    verification: 'node scripts/test-consistency.mjs',
  }),
  dim('integrity.determinism', 'Deterministic generation and whole-tree digest', {
    measured: 'pass',
    denominator: null,
    unit: 'gate (no percentage applies)',
    pct: null,
    status: 'COMPLETE',
    blocker: null,
    detail: 'Generation + validation logs are byte-identical across fresh copies and the tree digest reproduces.',
    nextAction: 'None.',
    verification: 'npm run test:determinism',
  }),
  dim('integrity.tests', 'Dataset test suite', {
    measured: 'pass',
    denominator: null,
    unit: 'gate (no percentage applies)',
    pct: null,
    status: 'COMPLETE',
    blocker: null,
    detail: 'npm test chains every gate: validators, pack/asset/audience suites, consistency, evaluation, importers, capability coverage, app conformance, completion ledger, originality, determinism.',
    nextAction: 'None.',
    verification: 'npm test',
  }),
  dim('artefacts.freshness', 'Committed generated artefacts reproduce from the tree', {
    measured: freshnessChecks.length - staleArtefacts.length,
    denominator: freshnessChecks.length,
    unit: 'generated artefacts',
    pct: pctOf(freshnessChecks.length - staleArtefacts.length, freshnessChecks.length),
    status: staleArtefacts.length === 0 ? 'COMPLETE' : 'PARTIAL',
    blocker: staleArtefacts.length === 0 ? null : 'ARTEFACT_STALE',
    detail: staleArtefacts.length === 0
      ? `All ${freshnessChecks.length} generated artefacts reproduce byte-for-byte: inventory, capability matrix, App language mapping, App conformance and coverage evidence. This check exists because a stale CURRENT_INVENTORY.json survived unnoticed until the ledger was written.`
      : `Stale: ${staleArtefacts.join(', ')}. A generated file that no longer matches the tree is treated as a defect, not a snapshot.`,
    nextAction: staleArtefacts.length === 0
      ? 'Keep regenerating through the documented --write commands; the check runs inside npm test.'
      : `Run the generator for each stale artefact (${staleArtefacts.length} file(s)) and commit the result.`,
    verification: 'npm run completion:check',
  }),
  dim('publication', 'Repository publication readiness', {
    measured: 0,
    denominator: 1,
    unit: 'release',
    pct: 0,
    status: 'BLOCKED_OWNER',
    blocker: 'LICENSE_AND_PRODUCTION_AUTH',
    detail: `Release readiness is ${readiness.verdict}: ${readinessPass} of ${readiness.gates.length} gates PASS, ${readiness.gates.length - readinessPass} blocked (G6 licence, G8 production lock, G16 owner decisions, G17 production eligibility). Passing tests are not a legal conclusion.`,
    nextAction: 'Owner completes the four blocked gates (docs/OWNER_DECISION_PACKET.md).',
    verification: 'npm run validate:matrix',
  }),
];

const STATUS_VOCAB = ['COMPLETE', 'PARTIAL', 'POLICY_BOUND', 'BLOCKED_OWNER', 'BLOCKED_APP', 'BLOCKED_EVIDENCE'];
const BLOCKER_VOCAB = [
  'OWNER_DECISION_REQUIRED',
  'LICENSE_AND_PRODUCTION_AUTH',
  'POLICY_DECISION',
  'EVIDENCE_GATED',
  'APP_CATALOG',
  'APP_LOADER',
  'APP_EVALUATOR',
  'APP_RESPONSE_SURFACE',
  'ARTEFACT_STALE',
];

const summary = {
  dimensions: dimensions.length,
  complete: dimensions.filter((d) => d.status === 'COMPLETE').length,
  partial: dimensions.filter((d) => d.status === 'PARTIAL').length,
  policyBound: dimensions.filter((d) => d.status === 'POLICY_BOUND').length,
  blockedOwner: dimensions.filter((d) => d.status === 'BLOCKED_OWNER').length,
  blockedApp: dimensions.filter((d) => d.status === 'BLOCKED_APP').length,
};

const out = {
  schemaVersion: 'drobon.completion.ledger/v1',
  note: 'Computed completion ledger. One row per dimension; no composite percentage is derived by averaging denominators (docs/COVERAGE_METHODOLOGY.md forbids it). Regenerate with node scripts/completion-ledger.mjs --write; staleness fails npm test.',
  asOf: '2026-10-21',
  appReference: conformance.generatedFrom.appProfile,
  statusVocabulary: STATUS_VOCAB,
  blockerVocabulary: BLOCKER_VOCAB,
  summary,
  dimensions,
};

// ------------------------------------------------------------- validate ----
const errors = [];
for (const d of dimensions) {
  if (!STATUS_VOCAB.includes(d.status)) errors.push(`${d.id}: status ${d.status} not in vocabulary`);
  if (d.status !== 'COMPLETE') {
    if (!BLOCKER_VOCAB.includes(d.blocker)) errors.push(`${d.id}: blocker ${d.blocker} not in vocabulary`);
    if (typeof d.nextAction !== 'string' || d.nextAction.length < 20) errors.push(`${d.id}: next action must be executable and specific`);
  } else if (d.blocker !== null) {
    errors.push(`${d.id}: a COMPLETE dimension must not name a blocker`);
  }
  if (typeof d.verification !== 'string' || d.verification.length === 0) errors.push(`${d.id}: verification command required`);
  const scriptName = d.verification.startsWith('npm run ') ? d.verification.slice(8)
    : d.verification.startsWith('npm test') ? 'test'
      : null;
  if (scriptName !== null && pkg.scripts[scriptName] === undefined) {
    errors.push(`${d.id}: verification script "${scriptName}" is not in package.json`);
  }
  if (d.pct !== null && (d.pct < 0 || d.pct > 100)) errors.push(`${d.id}: pct out of range`);
  // Every referenced repository path must exist: a ledger that points at a deleted
  // document is a dead end for the person doing the next action.
  for (const [, ref] of `${d.detail} ${d.nextAction}`.matchAll(/((?:docs|interop|scripts|data)\/[A-Za-z0-9_./-]+)/g)) {
    const clean = ref.replace(/[.,;:)]+$/, '');
    if (!existsSync(join(ROOT, clean))) errors.push(`${d.id}: references missing path ${clean}`);
  }
  if (d.status === 'COMPLETE' && d.pct !== null && d.pct !== 100) {
    errors.push(`${d.id}: COMPLETE with pct ${d.pct} — close it or mark the status honestly`);
  }
  if (d.pct === 100 && d.measured !== d.denominator && typeof d.measured === 'number') {
    errors.push(`${d.id}: claims 100% but measured ${d.measured} of ${d.denominator}`);
  }
}
if (errors.length > 0) {
  process.stderr.write(`completion-ledger: ${errors.length} invalid dimension(s):\n${errors.map((e) => `  - ${e}`).join('\n')}\n`);
  process.exit(1);
}

// --------------------------------------------------------------- render ----
const md = [];
md.push('# DATASET_COMPLETION_LEDGER.md — what is done, what is not, and who owns the rest');
md.push('');
md.push('Generated by `scripts/completion-ledger.mjs` from the tree, the registers and');
md.push('`interop/app-conformance.json`. Do not edit by hand: `npm test` fails when this file');
md.push('stops reproducing. As of **2026-10-21**, against Main App');
md.push(`\`${out.appReference.repo}\` @ \`${out.appReference.commit}\`.`);
md.push('');
md.push('**No composite percentage is reported.** The repository forbids averaging unrelated');
md.push('denominators; a single "we are X% done" number would hide which half of the work is');
md.push('waiting on a legal decision rather than on engineering.');
md.push('');
md.push('| Status | Dimensions |');
md.push('|---|---|');
md.push(`| COMPLETE | ${summary.complete} |`);
md.push(`| PARTIAL (evidence-gated) | ${summary.partial} |`);
md.push(`| POLICY_BOUND (documented limitation) | ${summary.policyBound} |`);
md.push(`| BLOCKED_OWNER (licence / production / owner decision) | ${summary.blockedOwner} |`);
md.push(`| BLOCKED_APP (Main App repository) | ${summary.blockedApp} |`);
md.push('');
md.push('## The ledger');
md.push('');
md.push('| Dimension | Measured | Denominator | % | Status | Blocker |');
md.push('|---|---|---|---|---|---|');
for (const d of dimensions) {
  const measured = d.measured === null ? '—' : String(d.measured);
  const denom = d.denominator === null ? '—' : String(d.denominator);
  const pct = d.pct === null ? '—' : `${d.pct}%`;
  md.push(`| ${d.title} | ${measured} | ${denom} | ${pct} | **${d.status}** | ${d.blocker ?? '—'} |`);
}
md.push('');
md.push('## Detail and next action, per dimension');
md.push('');
for (const d of dimensions) {
  md.push(`### ${d.id} — ${d.title}`);
  md.push('');
  md.push(`- Status: **${d.status}**${d.blocker ? ` (blocker: \`${d.blocker}\`)` : ''}`);
  if (d.pct !== null) md.push(`- Measured: ${d.measured} of ${d.denominator} ${d.unit} (${d.pct}%)`);
  else md.push(`- Measured: ${d.measured ?? 'see note'} ${d.unit}`);
  md.push(`- Why: ${d.detail}`);
  md.push(`- Next action: ${d.nextAction}`);
  md.push(`- Verify: \`${d.verification}\``);
  md.push('');
}
md.push('## What "100%" can and cannot mean here');
md.push('');
md.push('Three of the five completion classes cannot be closed by any amount of dataset work:');
md.push('');
md.push('1. **Licence and production intelligence** (`runtime.advisories`, `rights.license`,');
md.push('   `publication`) need the owner\'s legal decision and a written production-stage');
md.push('   approval. Until then the corpus is validated-only, `verifiedProductionCount` is 0 and');
md.push('   release is NO-GO.');
md.push('2. **App-side conformance** (`app.*`) lives in the other repository: the language');
md.push('   catalog, the loader checklist, the DAST evaluator parity and the remediation');
md.push('   resolver are App code. This repository measures them and publishes the failing set');
md.push('   (`interop/app-conformance.json`) so the App workstream has a precise target.');
md.push('3. **Rule breadth** (`packs.sast`, `packs.dast`) is evidence-gated by policy: the');
md.push('   remaining rules must come from published evidence, not from padding.');
md.push('');
md.push('What *is* closed, and enforced on every push: the knowledge graph, CWE coverage,');
md.push('declared pack tests, every universal rule\'s positive + negative evaluation,');
md.push('determinism, and the full test suite.');
md.push('');
const mdOut = `${md.join('\n')}`;
const jsonOut = `${JSON.stringify(out, null, 2)}\n`;

if (WRITE) {
  writeFileSync(join(ROOT, JSON_OUT), jsonOut);
  writeFileSync(join(ROOT, MD_OUT), mdOut);
  process.stdout.write(`wrote ${JSON_OUT} and ${MD_OUT}\n`);
  process.stdout.write(`  ${summary.complete} complete · ${summary.partial} partial · ${summary.policyBound} policy-bound · ${summary.blockedOwner} owner-blocked · ${summary.blockedApp} app-blocked\n`);
  process.exit(0);
}

for (const [file, expected] of [[JSON_OUT, jsonOut], [MD_OUT, mdOut]]) {
  let current = '';
  try {
    current = read(file);
  } catch {
    process.stderr.write(`completion-ledger: MISSING ${file}\n`);
    process.exit(1);
  }
  if (current !== expected) {
    process.stderr.write(`completion-ledger: STALE ${file} — run node scripts/completion-ledger.mjs --write\n`);
    process.exit(1);
  }
}
if (staleArtefacts.length > 0) {
  process.stderr.write(`completion-ledger: ${staleArtefacts.length} generated artefact(s) are stale: ${staleArtefacts.join(', ')}\n`);
  process.exit(1);
}
process.stdout.write(`completion-ledger: OK — ${dimensions.length} dimensions reproduce\n`);
process.stdout.write(`  ${summary.complete} complete · ${summary.partial} partial · ${summary.policyBound} policy-bound · ${summary.blockedOwner} owner-blocked · ${summary.blockedApp} app-blocked\n`);
