/**
 * test-current-state.mjs — current-state register integrity + count drift gate.
 *
 * Scope (why this file exists): the existing doc-drift gate pinned README,
 * CORPUS_GAP_REPORT, CAPABILITY_COVERAGE, REQUIREMENTS_MATRIX inventory,
 * CORPUS_TARGETS, COVERAGE_MAP numeric fields and two matrices' vocabulary.
 * It did NOT cover the root-level registers (remaining-work / traceability /
 * coverage CSVs) nor the numeric claims inside COMPLETION_MATRIX and
 * RELEASE_READINESS_MATRIX. Those drifted after the Phase 9 rule additions
 * (953 -> 954 rules, 96 -> 97 secrets, 913 -> 914 records) and after the
 * 2026-10-17 D-ORIG decision (5/5 -> 4/5 owner decisions pending).
 *
 * This gate:
 *   1. verifies docs/CURRENT_INVENTORY.json matches the tree byte-for-byte;
 *   2. verifies owner-decision state is internally consistent (no fabricated
 *      approvals: exactly one APPROVED entry, with a recorded decider/date);
 *   3. verifies the root CSV registers (uniqueness, vocabulary, arithmetic,
 *      cross-references);
 *   4. pins the count/status claims that current-state docs make, deriving
 *      every inventory count from computeInventory() so a doc cannot agree
 *      with a stale literal that the tree has outgrown;
 *   5. fails on known-stale tokens in files that must not carry them.
 *
 * Read-only. Runs in `npm test` and in CI.
 *
 * Usage: node scripts/test-current-state.mjs
 */
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import {
  CLASSIFICATIONS,
  FINAL_STATUSES,
  PRIORITIES,
  SCOPE_CLASSES,
  WORK_CLASSES,
  computeInventory,
  currentSnapshot,
  parseCsv,
  serialize,
} from './inventory.mjs';

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

const read = (rel) => readFileSync(join(ROOT, rel), 'utf8');
const readJson = (rel) => JSON.parse(read(rel));
const readCsv = (rel) => parseCsv(read(rel));

const inv = computeInventory();
const c = inv.counts;

// --- 1. inventory snapshot freshness ----------------------------------------
{
  assert(existsSync(join(ROOT, 'docs/CURRENT_INVENTORY.json')), 'CURRENT_INVENTORY.json exists');
  if (existsSync(join(ROOT, 'docs/CURRENT_INVENTORY.json'))) {
    assert(currentSnapshot() === serialize(inv),
      'CURRENT_INVENTORY.json matches a fresh recomputation (run `node scripts/inventory.mjs --write` if this fails)');
    const snap = readJson('docs/CURRENT_INVENTORY.json');
    assert(snap.schemaVersion === 'drobon.current-inventory/v1', 'inventory schemaVersion pinned');
    assert(!/\d{4}-\d{2}-\d{2}T/.test(currentSnapshot()), 'inventory carries no timestamps (deterministic)');
    assert(snap.counts.packRules === snap.counts.sastRules + snap.counts.secretsRules + snap.counts.dastRules,
      'inventory: packRules equals sast+secrets+dast');
    assert(snap.counts.evalCasesTotal === snap.counts.evalCasesAssessed + snap.counts.evalCasesUnassessed,
      'inventory: eval total equals assessed+unassessed');
  }
}

// --- 2. owner decisions: no fabricated approval ------------------------------
{
  const decisions = readJson('docs/OWNER_DECISIONS.json').decisions ?? [];
  assert(decisions.length === 5, `owner decisions: 5 subjects recorded (got ${decisions.length})`);
  const approved = decisions.filter((d) => d.status === 'APPROVED');
  const pending = decisions.filter((d) => d.status !== 'APPROVED');
  assert(pending.length === 4, `owner decisions: 4 subjects still OWNER_DECISION_REQUIRED (got ${pending.length})`);
  assert(approved.length === 1 && approved[0].subject === 'ORIGINAL_CONTENT',
    'owner decisions: only ORIGINAL_CONTENT is APPROVED (D-ORIG 2026-10-17)');
  assert(approved.every((d) => typeof d.decidedAt === 'string' && d.decidedAt.length > 0 && typeof d.decider === 'string' && d.decider.length > 0),
    'owner decisions: the APPROVED entry records decider + date');
  assert(pending.every((d) => d.decidedAt === null && d.decider === null),
    'owner decisions: pending entries carry null decidedAt/decider (no invented approvals)');
  assert(decisions.every((d) => typeof d.subject === 'string' && typeof d.requiredDecision === 'string' && typeof d.licenseOrTerms === 'string'),
    'owner decisions: every entry carries subject/requiredDecision/licenseOrTerms');
}

// --- 3. ingestion gates stay fail-closed ------------------------------------
{
  const gates = readJson('docs/INGESTION_GATES.json').gates ?? [];
  assert(gates.length === 4 && gates.map((g) => g.id).join(',') === 'GATE-1,GATE-2,GATE-3,GATE-4',
    'ingestion gates: GATE-1..4 present in order');
  assert(gates.every((g) => g.status === 'BLOCKED'),
    'ingestion gates: all four remain BLOCKED (no unrecorded approval)');
  assert(gates.every((g) => typeof g.evidenceRequired === 'string' && g.decidedAt === null),
    'ingestion gates: evidence requirements stated, no decision timestamp invented');
}

// --- 4. root remaining-work register ---------------------------------------
{
  const rows = readCsv('DROBON_REMAINING_WORK.csv');
  const trace = readCsv('DROBON_REQUIREMENT_TRACEABILITY.csv');
  const traceIds = new Set(trace.map((r) => r.reqId));
  const ids = rows.map((r) => r.gapId);
  assert(rows.length === 44, `remaining-work: 44 rows (got ${rows.length})`);
  assert(new Set(ids).size === ids.length, 'remaining-work: every gapId is unique');
  assert(ids.every((id) => /^GAP-[0-9]{3}$/.test(id)), 'remaining-work: gapId grammar GAP-NNN');
  assert(rows.every((r) => traceIds.has(r.reqId)),
    'remaining-work: every reqId resolves to DROBON_REQUIREMENT_TRACEABILITY.csv',
    rows.filter((r) => !traceIds.has(r.reqId)).map((r) => `${r.gapId}->${r.reqId}`).join(','));
  assert(rows.every((r) => CLASSIFICATIONS.includes(r.classification)),
    'remaining-work: classification uses the controlled vocabulary',
    rows.filter((r) => !CLASSIFICATIONS.includes(r.classification)).map((r) => r.gapId).join(','));
  assert(rows.every((r) => PRIORITIES.includes(r.priority)),
    'remaining-work: priority uses P0..P3',
    rows.filter((r) => !PRIORITIES.includes(r.priority)).map((r) => r.gapId).join(','));
  assert(rows.every((r) => r.safeNextAction.length > 0 && r.acceptanceCriteria.length > 0
    && r.verificationTests.length > 0 && r.dependencies.length > 0),
    'remaining-work: dependencies, next action, acceptance criteria and tests are all stated');
  const resolved = rows.filter((r) => r.classification === 'RESOLVED');
  assert(resolved.every((r) => r.canDoNow.startsWith('done (closed')),
    'remaining-work: RESOLVED rows are marked done in canDoNow');
  assert(rows.filter((r) => r.canDoNow.startsWith('done (closed')).every((r) => r.classification === 'RESOLVED'),
    'remaining-work: rows marked done are classified RESOLVED');
  const canDoNow = rows.filter((r) => r.canDoNow === 'no' || r.canDoNow.startsWith('no ('));
  assert(canDoNow.length === rows.length - resolved.length,
    'remaining-work: every open row is explicitly not-doable-now (owner/app/evidence gate)');
}

// --- 5. requirement traceability ledger ------------------------------------
{
  const rows = readCsv('DROBON_REQUIREMENT_TRACEABILITY.csv');
  const ids = rows.map((r) => r.reqId);
  assert(rows.length === 64, `traceability: 64 requirement rows (got ${rows.length})`);
  assert(new Set(ids).size === ids.length, 'traceability: every reqId is unique');
  assert(rows.every((r) => FINAL_STATUSES.includes(r.finalStatus)),
    'traceability: finalStatus uses the controlled vocabulary',
    [...new Set(rows.filter((r) => !FINAL_STATUSES.includes(r.finalStatus)).map((r) => r.finalStatus))].join(','));
  assert(rows.every((r) => SCOPE_CLASSES.includes(r.scopeClass)),
    'traceability: scopeClass is REQUIRED|SUPPLEMENTAL|NONE');
  assert(rows.every((r) => WORK_CLASSES.includes(r.workClass)),
    'traceability: workClass is one of A..G');
  assert(rows.every((r) => PRIORITIES.includes(r.priority)), 'traceability: priority is P0..P3');
  const badFraction = rows.filter((r) => {
    const n = Number(r.verifiedFraction);
    return !Number.isFinite(n) || n < 0 || n > 1 || !/^[01]\.\d{3}$/.test(r.verifiedFraction);
  });
  assert(badFraction.length === 0, 'traceability: verifiedFraction is a 0.000..1.000 value',
    badFraction.map((r) => r.reqId).join(','));
  assert(rows.every((r) => r.evidence.length > 0 && r.remainingDependency.length > 0),
    'traceability: evidence and remaining dependency stated on every row');
  const counts = inv.registers.traceability.byFinalStatus;
  assert(counts.CLOSED_VERIFIED === 36,
    `traceability: CLOSED_VERIFIED = 36 (got ${counts.CLOSED_VERIFIED})`);
}

// --- 6. engine / user-type / report-outcome coverage arithmetic ------------
{
  const engine = readCsv('DROBON_ENGINE_COVERAGE.csv');
  assert(engine.length === 8, `engine coverage: 8 engines (got ${engine.length})`);
  for (const row of engine) {
    const parts = ['full', 'partial', 'implementedNotVerified', 'missing', 'blocked', 'notAssessed']
      .reduce((n, k) => n + Number(row[k]), 0);
    assert(parts === Number(row.applicableReq),
      `engine coverage ${row.engine}: status buckets sum to applicableReq ${row.applicableReq}`,
      String(parts));
    assert(Number(row.denominator) === Number(row.applicableReq),
      `engine coverage ${row.engine}: denominator equals applicableReq`);
    const pct = Math.round((Number(row.points) / Number(row.denominator)) * 1000) / 10;
    assert(Math.abs(pct - Number(row.verifiedCoveragePct)) <= 0.15,
      `engine coverage ${row.engine}: verifiedCoveragePct consistent with points/denominator`,
      `${pct} vs ${row.verifiedCoveragePct}`);
  }
  const users = readCsv('DROBON_USERTYPE_COVERAGE.csv');
  assert(users.length === 4, `user-type coverage: 4 audiences (got ${users.length})`);
  for (const row of users) {
    const parts = ['full', 'partial', 'missingOrBlocked'].reduce((n, k) => n + Number(row[k]), 0);
    assert(parts === Number(row.applicableReq),
      `user-type coverage ${row.userType}: buckets sum to applicableReq`);
    const pct = Math.round((Number(row.points) / Number(row.denominator)) * 1000) / 10;
    assert(Math.abs(pct - Number(row.verifiedCoveragePct)) <= 0.15,
      `user-type coverage ${row.userType}: percentage arithmetic holds`);
  }
  const reports = readCsv('DROBON_REPORT_OUTCOME_COVERAGE.csv');
  const reportStatuses = ['VERIFIED_FULL', 'VERIFIED_PARTIAL', 'MISSING_ENGINE_OR_INTEGRATION', 'NOT_IMPLEMENTED', 'NOT_ASSESSED'];
  assert(reports.length === 13, `report outcome: 13 report requirements (got ${reports.length})`);
  assert(reports.every((r) => reportStatuses.includes(r.status)),
    'report outcome: status vocabulary respected');
  assert(reports.every((r) => Number(r.subreqsPassing) <= Number(r.subreqsTotal)),
    'report outcome: passing subrequirements never exceed total');
  assert(reports.every((r) => {
    const frac = Number(r.fraction);
    const want = Number(r.subreqsTotal) === 0 ? 0 : Math.round((Number(r.subreqsPassing) / Number(r.subreqsTotal)) * 1000) / 1000;
    return Math.abs(frac - want) <= 0.001;
  }), 'report outcome: fraction equals passing/total (3 dp)');
}

// --- 7. completion matrix: frozen requirement IDs + acceptance criteria ----
{
  const comp = readJson('docs/COMPLETION_MATRIX.json');
  const items = comp.items ?? [];
  assert(comp.frozenAt === '2026-10-18', 'completion matrix is frozen with frozenAt 2026-10-18');
  assert(items.length === 22, `completion matrix: 22 frozen requirement ids (got ${items.length})`);
  assert(new Set(items.map((i) => i.id)).size === items.length, 'completion matrix: ids unique');
  assert(items.every((i) => /^[A-Z][A-Z0-9-]+$/.test(i.id)), 'completion matrix: id grammar stable');
  const vocab = ['PASS', 'FAIL', 'BLOCKED', 'NOT_IMPLEMENTED', 'NOT_ASSESSED', 'NOT_APPLICABLE',
    'BLOCKED_OWNER_DECISION', 'BLOCKED_PRODUCTION_LOCK'];
  assert(items.every((i) => vocab.includes(i.status)), 'completion matrix: status vocabulary respected');
  assert(items.every((i) => typeof i.acceptanceCriteria === 'string' && i.acceptanceCriteria.length >= 20),
    'completion matrix: every item states acceptanceCriteria');
  assert(items.every((i) => typeof i.verificationCommand === 'string' && i.verificationCommand.length > 0),
    'completion matrix: every item states a verificationCommand');
  assert(items.every((i) => typeof i.dependency === 'string' && i.dependency.length > 0),
    'completion matrix: every item states its dependency (or "none")');
  assert(items.every((i) => typeof i.evidence === 'string' && i.evidence.length > 0),
    'completion matrix: every item carries evidence');
  assert(items.filter((i) => i.status === 'NOT_ASSESSED').every((i) => typeof i.limitations === 'string' && i.limitations.length > 0),
    'completion matrix: NOT_ASSESSED items state their limitation');
  const counts = inv.registers.completionMatrix.byStatus;
  assert((counts.PASS ?? 0) === 19, `completion matrix: 19 PASS items (got ${counts.PASS ?? 0})`);
  assert(comp.denominator?.items === items.length,
    'completion matrix: declared denominator equals the frozen item count');
  const text = read('docs/COMPLETION_MATRIX.json');
  for (const [claim, label] of [
    ['934/934', 'sast 934/934'],
    ['97/97', 'secrets 97/97'],
    ['72/72', 'dast 72/72'],
    ['1103/1103', 'linkage 1103/1103'],
    ['Lessons (6)', 'audiences: 6 lessons'],
    ['1114 files', 'audiences: 1114 files'],
  ]) {
    assert(text.includes(claim), `completion matrix states current count: ${label}`);
  }
}

// --- 8. release-readiness gates -------------------------------------------
{
  const rel = readJson('docs/RELEASE_READINESS_MATRIX.json');
  const gates = rel.gates ?? [];
  assert(gates.length === 17, `release gates: 17 (got ${gates.length})`);
  assert(new Set(gates.map((g) => g.id)).size === gates.length, 'release gates: ids unique');
  assert(gates.every((g) => typeof g.acceptanceCriteria === 'string' && g.acceptanceCriteria.length >= 20),
    'release gates: every gate states acceptanceCriteria');
  assert(gates.every((g) => typeof g.verificationCommand === 'string' && g.verificationCommand.length > 0),
    'release gates: every gate states a verificationCommand');
  assert(gates.every((g) => Array.isArray(g.evidence) && g.evidence.length > 0),
    'release gates: every gate carries evidence');
  // Baseline verification is 2026-10-18. The 2026-10-21 App-connection audit
  // re-verified the gates whose scope it widened (G3 conformance, G6 licensing),
  // so those two carry the newer date; nothing may be older than the baseline.
  const VERIFIED_DATES = ['2026-10-18', '2026-10-21'];
  assert(gates.every((g) => VERIFIED_DATES.includes(g.lastVerified)),
    'release gates: every gate carries a documented verification date',
    [...new Set(gates.map((g) => g.lastVerified))].join(','));
  const rescoped = gates.filter((g) => g.lastVerified === '2026-10-21').map((g) => g.id).sort();
  assert(JSON.stringify(rescoped) === JSON.stringify(['G3', 'G6']),
    'release gates: exactly the re-scoped gates carry the 2026-10-21 date', rescoped.join(','));
  assert(rel.asOf === '2026-10-18', 'release matrix asOf = 2026-10-18');
  const byId = Object.fromEntries(gates.map((g) => [g.id, g]));
  assert(byId.G6.status === 'BLOCKED_OWNER_DECISION', 'release gate G6 stays BLOCKED_OWNER_DECISION');
  assert(byId.G8.status === 'BLOCKED_PRODUCTION_LOCK', 'release gate G8 stays BLOCKED_PRODUCTION_LOCK');
  assert(byId.G16.status === 'BLOCKED_OWNER_DECISION', 'release gate G16 stays BLOCKED_OWNER_DECISION');
  assert(byId.G17.status === 'BLOCKED_OWNER_DECISION', 'release gate G17 stays BLOCKED_OWNER_DECISION');
  const pass = gates.filter((g) => g.status === 'PASS').length;
  assert(pass === 13, `release gates: 13 PASS, 4 blocked (got ${pass} PASS)`);
  const text = read('docs/RELEASE_READINESS_MATRIX.json');
  for (const [claim, label] of [
    ['1106 files', 'validate-packs 1106 files'],
    ['2166 files', 'validate-assets 2166 files'],
    ['1114 files', 'validate-audiences 1114 files'],
    ['1103/1103 rules pos+neg executed', 'all 1103 rules executed'],
    ['linkage: 1103 rules <-> 1103 patterns', 'linkage 1103<->1103'],
    ['4 of 5 owner decisions pending', 'owner decisions 4/5 pending'],
  ]) {
    assert(text.includes(claim), `release matrix states current fact: ${label}`);
  }
  assert(!text.includes('5/5 OWNER_DECISION_REQUIRED'),
    'release matrix does not repeat the stale 5/5 owner-decision claim');
}

// --- 9. blocker register consistency --------------------------------------
{
  const reg = readJson('docs/BLOCKER_REGISTER.json');
  const open = reg.blockers ?? [];
  assert(open.length === 4, `blockers: 4 open (got ${open.length})`);
  assert(reg.counts?.open === open.length, 'blockers: declared open count matches the list');
  assert(reg.counts?.resolvedForRecord === (reg.resolvedForRecord ?? []).length,
    'blockers: declared resolved count matches the list');
  assert(open.every((b) => ['BLOCKED_OWNER_DECISION', 'BLOCKED_PRODUCTION_LOCK', 'BLOCKED_SOURCE_EVIDENCE'].includes(b.status)),
    'blockers: status vocabulary respected');
  assert(open.every((b) => typeof b.acceptanceCriteria === 'string' && typeof b.verifyCommand === 'string'),
    'blockers: every open blocker states acceptance criteria + verify command');
  const text = read('docs/BLOCKER_REGISTER.json');
  assert(!text.includes('5 decisions, all OWNER_DECISION_REQUIRED'),
    'blockers: stale "5 decisions all OWNER_DECISION_REQUIRED" claim removed');
  assert(text.includes('4 pending of 5'),
    'blockers: accurate owner-decision state recorded (4 pending of 5)');
  assert(new Set((reg.resolvedForRecord ?? []).map((r) => r.id)).size === (reg.resolvedForRecord ?? []).length,
    'blockers: resolved ids unique');
}

// --- 10. current-state documentation claims -------------------------------
{
  // Every inventory number below is derived from the tree, never typed in, so
  // "the doc agrees with the gate" can no longer mean "both are stale".
  const plain = (n) => String(n);
  const comma = (n) => Number(n).toLocaleString('en-US');
  const asset = read('docs/ASSET_METHODOLOGY.md');
  assert(asset.includes(`(${plain(c.packRules)} pack rules, ${plain(c.patterns)} patterns, ${plain(c.records)} generated records)`),
    'ASSET_METHODOLOGY title states current generated-set counts',
    `expected (${c.packRules} pack rules, ${c.patterns} patterns, ${c.records} generated records)`);
  const coverage = read('docs/COVERAGE_MAP.json');
  assert(coverage.includes(`Pattern/record alignment: ${comma(c.patterns)} patterns and ${comma(c.records)} records`),
    'COVERAGE_MAP states current pattern/record counts',
    `expected ${comma(c.patterns)}/${comma(c.records)}`);
  assert(coverage.includes('every pattern referenced by exactly one record'),
    'COVERAGE_MAP states the pattern->record alignment that the tree now satisfies');
  assert(coverage.includes('4 of 5 owner decisions pending'),
    'COVERAGE_MAP states accurate owner-decision state');
  const matrix = read('docs/REQUIREMENTS_MATRIX.json');
  assert(matrix.includes(`Current breadth (${plain(c.secretsRules)} rules`),
    `REQUIREMENTS_MATRIX notes state ${c.secretsRules} secrets rules`);
  assert(matrix.includes('4/5 OWNER_DECISION_REQUIRED'), 'REQUIREMENTS_MATRIX evidence states 4/5 pending');
  assert(!matrix.includes('Current breadth (94 rules'), 'REQUIREMENTS_MATRIX no longer claims 94 secrets rules');
  const flow = read('docs/PACK_FLOW_DSL_PROPOSAL.md');
  assert(flow.includes('counts stay 1103'), 'PACK_FLOW_DSL_PROPOSAL states current rule count');
  const source = read('docs/SOURCE_RELEASE_GATE.md');
  assert(source.includes(`Original (${comma(c.packRules)} rules etc.)`),
    'SOURCE_RELEASE_GATE states current rule count', `expected ${comma(c.packRules)}`);
  const semantic = read('docs/SEMANTIC_ANALYSIS_ASSESSMENT.md');
  assert(semantic.includes(`${plain(c.packRules)} rules`),
    'SEMANTIC_ANALYSIS_ASSESSMENT states current rule count', `expected ${c.packRules}`);
  assert(!semantic.includes('953 rules'), 'SEMANTIC_ANALYSIS_ASSESSMENT carries no stale 953 rule claim');
  const cgm = read('docs/CAPABILITY_GAP_MATRIX.md');
  assert(cgm.includes(`"${plain(c.packRules)} rules" is breadth`),
    'CAPABILITY_GAP_MATRIX CGM-B1 states current breadth', `expected ${c.packRules}`);
  assert(!cgm.includes('"953 rules" is breadth'), 'CAPABILITY_GAP_MATRIX carries no stale breadth claim');
  assert(cgm.includes(`linkage ${plain(c.packRules)}/${plain(c.patterns)}`),
    'CAPABILITY_GAP_MATRIX states current linkage', `expected ${c.packRules}/${c.patterns}`);
  assert(/PASS \d+\/\d+/.test(cgm), 'CAPABILITY_GAP_MATRIX states a consistency total');
  assert(cgm.includes(`remediation ${plain(c.remediation)} entries`),
    'CAPABILITY_GAP_MATRIX states current remediation count', `expected ${c.remediation}`);
  const audiences = read('docs/AUDIENCES.md');
  assert(audiences.includes(`packs ${plain(c.packRules)} rules`) && audiences.includes(`records ${plain(c.records)}`)
    && audiences.includes(`remediation ${plain(c.remediation)}`),
    'AUDIENCES.md states current audience-base counts',
    `expected packs ${c.packRules} / records ${c.records} / remediation ${c.remediation}`);
  const audLine = /^matrix-counts: (.+)$/m.exec(audiences);
  assert(audLine !== null && audLine[1].includes(`remediation=${plain(c.remediation)}`)
    && audLine[1].includes(`patterns=${plain(c.patterns)}`) && audLine[1].includes(`records=${plain(c.records)}`)
    && audLine[1].includes(`cwe=${plain(c.cweEntries)}`),
    'AUDIENCES.md matrix-counts tripwire line matches the tree',
    audLine?.[1] ?? 'missing');
  const evidenceContract = read('docs/FINDING_EVIDENCE_CONTRACT.md');
  assert(evidenceContract.includes('(31/31)'), 'FINDING_EVIDENCE_CONTRACT states current test total');
  assert(cgm.includes('test-eval` 43/43'), 'CAPABILITY_GAP_MATRIX states current eval-test total');
  assert(cgm.includes('test-finding-evidence` 31/31'), 'CAPABILITY_GAP_MATRIX states current evidence-test total');
  assert(cgm.includes('`validate-audiences` 1174 files'), 'CAPABILITY_GAP_MATRIX states current audiences file count');
  const cap = read('docs/CAPABILITY_COVERAGE.md');
  assert(cap.includes(`DAST ${plain(c.dastRules)}`) && cap.includes(`pack total ${plain(c.packRules)}`),
    'CAPABILITY_COVERAGE states the current DAST and pack totals',
    `expected DAST ${c.dastRules} / pack total ${c.packRules}`);
  const remaining = read('DROBON_REMAINING_WORK.csv');
  // Since 2026-10-21 the App actually loads these packs (connection verified), so the
  // register must state integration, not "unreachable". The counts stay drift-pinned.
  assert(remaining.includes(`${plain(c.sastRules)} dataset SAST rules integrated`),
    `remaining-work states ${c.sastRules} SAST rules as integrated`, `expected ${c.sastRules}`);
  assert(remaining.includes(`${plain(c.secretsRules)} dataset secrets rules integrated`),
    `remaining-work states ${c.secretsRules} secrets rules as integrated`, `expected ${c.secretsRules}`);
  assert(remaining.includes(`${plain(c.dastRules)} dataset DAST checks integrated`),
    `remaining-work states ${c.dastRules} DAST checks as integrated`, `expected ${c.dastRules}`);
  assert(remaining.includes(`${plain(c.remediation)} remediation entries loaded`),
    `remaining-work states ${c.remediation} remediation entries as loaded`, `expected ${c.remediation}`);
  assert(!remaining.includes('dataset rules unreachable'), 'remaining-work carries no stale "unreachable" claim');
  assert(!remaining.includes('94 dataset rules'), 'remaining-work carries no stale 94-secret claim');
  const trace = read('DROBON_REQUIREMENT_TRACEABILITY.csv');
  assert(trace.includes(`${plain(c.secretsRules)} rules;`),
    `traceability states ${c.secretsRules} secrets rules`, `expected ${c.secretsRules}`);
  assert(!trace.includes('96 rules;'), 'traceability carries no stale 96-rule claim');
  const bench = read('DROBON_PAID_TOOL_BENCHMARK.csv');
  assert(!bench.includes('dataset 94 rules'), 'paid-tool benchmark carries no stale 94-secret claim');
  assert(bench.includes(`dataset ${plain(c.secretsRules)} rules`),
    `paid-tool benchmark states ${c.secretsRules} secrets rules`, `expected ${c.secretsRules}`);
}

// --- 11. repo-state record structure --------------------------------------
{
  const record = readJson('docs/REPO_STATE_VERIFICATION.json');
  assert(record.schemaVersion === 'drobon.repo-state.verification/v1', 'repo-state record schema pinned');
  const baselines = Array.isArray(record.baselines) ? record.baselines : [];
  const latest = baselines[0] ?? {};
  assert(baselines.length >= 2, 'repo-state record keeps prior baselines as history');
  assert(/^[0-9a-f]{40}$/.test(String(latest.head ?? '')),
    'repo-state: latest baseline head is a full commit sha');
  assert(typeof latest.branch === 'string' && latest.branch.startsWith('arena/'),
    'repo-state: latest baseline names the working branch');
  assert(typeof latest.worktreeClean === 'boolean' && typeof latest.trackedFiles === 'number',
    'repo-state: latest baseline records worktree state + tracked file count');
  assert(baselines.slice(1).every((b) => typeof b.verifiedAt === 'string'),
    'repo-state: historical baselines keep their verification dates');
}

process.stdout.write(`\ncurrent-state: ${passed} passed, ${failed} failed\n`);
if (failed > 0) {
  process.stderr.write('current-state: FAIL — current-state registers or counts drifted from the tree\n');
  process.exitCode = 1;
}
