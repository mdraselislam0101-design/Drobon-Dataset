/**
 * validate-capability-coverage.mjs — gate for the canonical Main App
 * capability <-> Dataset coverage matrix (docs/CAPABILITY_COVERAGE_MATRIX.json).
 *
 * Enforces, read-only and deterministically:
 *   - closed status/requirement/integration vocabularies (the eight approved
 *     statuses only; NOT_APPLICABLE needs an evidence-backed reason);
 *   - stable unique capability ids and a closed app-inventory mapping, so every
 *     in-scope App capability has a row and every row maps back to App evidence;
 *   - declared asset paths exist in this repo and their file counts reproduce
 *     from the tree (no hand-written counts);
 *   - COVERED_VERIFIED rows carry a contract, relationships, executable
 *     evaluation evidence and a verification basis -- rule counts alone never
 *     pass this gate;
 *   - blocked/unassessed rows are never silently recorded as complete, and no
 *     row claims production eligibility while the production lock holds;
 *   - the UserType view references only existing capability ids, exactly the
 *     four documented profiles, with no per-profile duplicate asset sets;
 *   - the matrix never asserts blanket 100% coverage while any dataset-relevant
 *     row is not COVERED_VERIFIED.
 *
 * No network, no writes. Runs in `npm test`.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FILE = 'docs/CAPABILITY_COVERAGE_MATRIX.json';

const STATUSES = ['COVERED_VERIFIED', 'PARTIAL', 'MISSING', 'APP_INTEGRATION_BLOCKED', 'RIGHTS_BLOCKED', 'OWNER_DECISION_BLOCKED', 'NOT_ASSESSED', 'NOT_APPLICABLE'];
const REQUIREMENTS = ['REQUIRED', 'SUPPLEMENTAL', 'NONE'];
const INTEGRATION = ['INTEGRATED', 'CONTRACT_READY_NOT_INTEGRATED', 'BLOCKED_PROVIDER_LOCKED', 'NOT_APPLICABLE'];
const BASES = ['DATASET_SIDE_EXECUTABLE', 'APP_CONSUMER_VERIFIED_WITH_GAPS', 'ASSET_VALIDATED_NO_CONSUMER', 'ASSET_VALIDATED_PRODUCTION_BLOCKED', 'NONE'];
const PROFILES = ['DEVELOPER', 'STUDENT', 'SECURITY_PROFESSIONAL', 'PENTESTER'];
const ALLOWED_ASSET_ROOTS = ['packs/', 'knowledge/', 'learning/', 'assessments/', 'engagements', 'interop/', 'vuln-intel/'];

let passed = 0;
let failed = 0;
function assert(condition, name, detail = '') {
  if (condition) {
    passed += 1;
    process.stdout.write(`ok - ${name}\n`);
  } else {
    failed += 1;
    process.stdout.write(`FAIL - ${name}${detail ? ` (${detail})` : ''}\n`);
  }
}

const raw = readFileSync(join(ROOT, FILE), 'utf8');
const m = JSON.parse(raw);

assert(m.schemaVersion === 'drobon.capability-coverage/v1', 'matrix schemaVersion is drobon.capability-coverage/v1');
assert(/^\d{4}-\d{2}-\d{2}$/.test(m.asOf), 'matrix carries an ISO asOf date');
assert(/^[0-9a-f]{40}$/.test(m.app?.commit ?? ''), 'App reference is a full 40-char commit sha');
assert((m.app?.verificationMethod ?? '').includes('read-only'), 'App verification method records read-only status');

const caps = m.capabilities ?? [];
assert(Array.isArray(caps) && caps.length >= 20, 'capability inventory is populated', `${caps.length} rows`);

const ids = caps.map((c) => c.id);
assert(new Set(ids).size === ids.length, 'capability ids are unique');
assert(ids.every((id) => /^DCC-[A-Z0-9-]+$/.test(id)), 'capability ids follow DCC-<AREA> convention');

for (const c of caps) {
  assert(STATUSES.includes(c.coverageStatus), `${c.id}: status is in the approved eight-value vocabulary`, String(c.coverageStatus));
  assert(REQUIREMENTS.includes(c.datasetRequirement), `${c.id}: dataset requirement is in vocabulary`);
  assert(INTEGRATION.includes(c.appIntegration), `${c.id}: app integration is in vocabulary`);
  assert(BASES.includes(c.verificationBasis), `${c.id}: verification basis is declared`);
  assert(Array.isArray(c.appInventoryRefs) && c.appInventoryRefs.length > 0, `${c.id}: cites App inventory evidence`);
  assert(Array.isArray(c.appSources) && c.appSources.length > 0, `${c.id}: cites App source evidence`);
  assert(typeof c.dataContract === 'string' && c.dataContract.length > 20, `${c.id}: states the required data contract or boundary`);
  assert(typeof c.remainingWork === 'string' && c.remainingWork.length > 3, `${c.id}: states remaining work`);

  if (c.coverageStatus === 'NOT_APPLICABLE') {
    assert(typeof c.notApplicableReason === 'string' && c.notApplicableReason.length > 70, `${c.id}: NOT_APPLICABLE carries an evidence-backed reason`);
    assert(c.datasetRequirement === 'NONE', `${c.id}: NOT_APPLICABLE does not claim a Dataset requirement`);
  }
  if (c.coverageStatus === 'COVERED_VERIFIED') {
    assert(c.datasetRequirement !== 'NONE', `${c.id}: COVERED_VERIFIED has a Dataset requirement`);
    assert(c.verificationBasis === 'DATASET_SIDE_EXECUTABLE', `${c.id}: COVERED_VERIFIED basis is executable Dataset-side evidence`);
    assert(Array.isArray(c.relationships) && c.relationships.length > 0, `${c.id}: COVERED_VERIFIED records validated relationships`);
    assert(Array.isArray(c.evaluationEvidence) && c.evaluationEvidence.length > 0, `${c.id}: COVERED_VERIFIED records evaluation evidence`);
    assert(Array.isArray(c.verification) && c.verification.length > 0, `${c.id}: COVERED_VERIFIED names re-runnable verification commands`);
    assert(Array.isArray(c.assetRefs) && c.assetRefs.length > 0, `${c.id}: COVERED_VERIFIED names concrete asset paths`);
  }
  if (['PARTIAL', 'MISSING', 'APP_INTEGRATION_BLOCKED', 'RIGHTS_BLOCKED', 'OWNER_DECISION_BLOCKED', 'NOT_ASSESSED'].includes(c.coverageStatus)) {
    assert(c.verificationBasis !== 'DATASET_SIDE_EXECUTABLE', `${c.id}: blocked/partial rows are not labelled fully verified`);
    assert(typeof c.remainingWork === 'string' && c.remainingWork.length > 10, `${c.id}: blocked/partial row states exact remaining work`);
  }
  assert(c.productionEligibility !== 'ELIGIBLE', `${c.id}: no row claims production eligibility under the lock`);
  if (c.appIntegration === 'INTEGRATED') {
    assert((c.evaluationEvidence ?? []).some((e) => /App-side verified/.test(e)),
      `${c.id}: INTEGRATED rows carry App-side executed evidence`);
  }
  if (c.verificationBasis === 'APP_CONSUMER_VERIFIED_WITH_GAPS') {
    assert(c.coverageStatus === 'PARTIAL', `${c.id}: WITH_GAPS basis is only used on PARTIAL rows`);
    assert(typeof c.remainingWork === 'string' && c.remainingWork.length > 60,
      `${c.id}: WITH_GAPS basis names the measured gaps`);
  }

  for (const ref of c.assetRefs ?? []) {
    assert(ALLOWED_ASSET_ROOTS.some((p) => String(ref.path).startsWith(p)), `${c.id}: asset path stays inside the Dataset tree`, String(ref.path));
    const abs = join(ROOT, ref.path);
    assert(existsSync(abs), `${c.id}: declared asset path exists`, String(ref.path));
    if (existsSync(abs) && ref.count !== undefined) {
      let actual;
      if (ref.countUnit === 'cases') {
        const doc = JSON.parse(readFileSync(abs, 'utf8'));
        actual = Array.isArray(doc) ? doc.length : (doc.vectors ?? doc.cases ?? []).length;
      } else {
        actual = readdirSync(abs).filter((f) => f.endsWith('.json')).length;
      }
      assert(actual === ref.count, `${c.id}: declared count reproduces from the tree`, `${ref.path}: declared ${ref.count}, actual ${actual}`);
    }
    assert(typeof ref.countingRule === 'string' && ref.countingRule.length > 5, `${c.id}: every count states its counting rule`);
  }
}

// --- Evaluation coverage: recomputed from data/eval-cases -------------------
// The matrix may not state a coverage number that the tree does not reproduce.
// These are the same numbers a reviewer would derive by hand; keeping them here
// means a batch that adds rules without cases, or cases without rules, fails the
// matrix instead of quietly lowering real coverage.
{
  const loadRules = (fam) => readdirSync(join(ROOT, 'packs', fam, 'v1', 'rules'))
    .filter((f) => f.endsWith('.json'))
    .map((f) => JSON.parse(readFileSync(join(ROOT, 'packs', fam, 'v1', 'rules', f), 'utf8')));
  const evalDir = join(ROOT, 'data', 'eval-cases');
  const cases = readdirSync(evalDir).filter((f) => f.endsWith('.json'))
    .map((f) => JSON.parse(readFileSync(join(evalDir, f), 'utf8')));
  const prefix = { sast: 'EVAL-SAST-', secrets: 'EVAL-SEC-', dast: 'EVAL-DAST-' };
  const rows = { sast: 'DCC-SAST', secrets: 'DCC-SECRETS', dast: 'DCC-DAST' };
  for (const fam of ['sast', 'secrets', 'dast']) {
    const rules = loadRules(fam);
    const ids = new Set(rules.map((r) => r.id));
    const mine = cases.filter((c) => c.id.startsWith(prefix[fam]));
    const pos = new Set();
    const neg = new Set();
    let assessed = 0;
    let unassessed = 0;
    for (const c of mine) {
      if (c.groundTruth?.state === 'ASSESSED') assessed += 1; else unassessed += 1;
      for (const d of c.expected?.detections ?? []) if (ids.has(d.ruleId)) pos.add(d.ruleId);
      for (const d of c.expected?.forbiddenDetections ?? []) if (ids.has(d)) neg.add(d);
    }
    const actual = {
      engine: fam.toUpperCase(),
      rules: rules.length,
      rulesWithPositiveCase: pos.size,
      rulesWithNegativeCase: neg.size,
      cases: mine.length,
      assessed,
      unassessed,
    };
    const cap = caps.find((c) => c.id === rows[fam]);
    assert(cap !== undefined, `${fam}: capability row exists for the evaluation recount`, rows[fam]);
    const declared = cap?.evaluationCoverage;
    assert(declared !== undefined, `${rows[fam]}: declares machine-checked evaluationCoverage`);
    for (const [k, v] of Object.entries(actual)) {
      assert(declared?.[k] === v, `${rows[fam]}: evaluationCoverage.${k} reproduces`, `declared ${declared?.[k]}, actual ${v}`);
    }
    assert(declared?.assessed + declared?.unassessed === declared?.cases, `${rows[fam]}: assessed + unassessed = cases`);
    assert(actual.assessed + actual.unassessed === mine.length, `${fam}: every case is scored or declared UNASSESSED`);
    // The prose summary must carry the same numbers, so a reader and the gate agree.
    const prose = (cap?.evaluationEvidence ?? []).join(' ');
    const fmt = (n) => Number(n).toLocaleString('en-US');
    const positiveStated = prose.includes(`${fmt(actual.rulesWithPositiveCase)} rules appear in a positive detection`)
      || prose.includes(`${actual.rulesWithPositiveCase}/${actual.rules}`);
    assert(positiveStated, `${rows[fam]}: evaluation prose states the recomputed positive-rule count`,
      `expected ${actual.rulesWithPositiveCase} of ${actual.rules}`);
    assert(prose.includes(fmt(actual.cases)), `${rows[fam]}: evaluation prose states the recomputed case count`,
      `expected ${fmt(actual.cases)}`);
  }
}

const computed = {
  capabilities: caps.length,
  coveredVerified: caps.filter((c) => c.coverageStatus === 'COVERED_VERIFIED').length,
  partial: caps.filter((c) => c.coverageStatus === 'PARTIAL').length,
  missing: caps.filter((c) => c.coverageStatus === 'MISSING').length,
  appIntegrationBlocked: caps.filter((c) => c.coverageStatus === 'APP_INTEGRATION_BLOCKED').length,
  rightsBlocked: caps.filter((c) => c.coverageStatus === 'RIGHTS_BLOCKED').length,
  ownerDecisionBlocked: caps.filter((c) => c.coverageStatus === 'OWNER_DECISION_BLOCKED').length,
  notAssessed: caps.filter((c) => c.coverageStatus === 'NOT_ASSESSED').length,
  notApplicable: caps.filter((c) => c.coverageStatus === 'NOT_APPLICABLE').length,
  required: caps.filter((c) => c.datasetRequirement === 'REQUIRED').length,
  supplemental: caps.filter((c) => c.datasetRequirement === 'SUPPLEMENTAL').length,
  none: caps.filter((c) => c.datasetRequirement === 'NONE').length,
  datasetRelevant: caps.filter((c) => c.datasetRequirement !== 'NONE').length,
};
for (const [k, v] of Object.entries(computed)) {
  assert(m.counts?.[k] === v, `counts.${k} reproduces`, `declared ${m.counts?.[k]}, actual ${v}`);
}
const statusSum = ['coveredVerified', 'partial', 'missing', 'appIntegrationBlocked', 'rightsBlocked',
  'ownerDecisionBlocked', 'notAssessed', 'notApplicable'].reduce((n, k) => n + computed[k], 0);
assert(statusSum === computed.capabilities, 'every row is classified exactly once',
  `status buckets sum to ${statusSum} of ${computed.capabilities}`);

// Closed app-inventory mapping.
const map = m.appInventoryCoverage ?? [];
assert(map.length >= 15, 'App inventory mapping is populated');
const covered = new Set();
for (const entry of map) {
  assert(typeof entry.sourceRef === 'string' && entry.sourceRef.length > 8, `${entry.id}: names the App document/evidence`);
  assert(Array.isArray(entry.rowIds) && entry.rowIds.length > 0, `${entry.id}: maps to at least one capability row`);
  for (const id of entry.rowIds ?? []) {
    assert(ids.includes(id), `${entry.id}: references an existing capability id`, String(id));
    covered.add(id);
  }
}
for (const id of ids) assert(covered.has(id), `${id}: appears in the App inventory mapping`);

// UserType view.
const ut = m.userTypeMatrix ?? [];
assert(ut.length === 4, 'UserType view covers exactly four profiles');
assert(PROFILES.every((p) => ut.some((u) => u.userType === p)), 'UserType view names DEVELOPER, STUDENT, SECURITY_PROFESSIONAL, PENTESTER');
for (const u of ut) {
  assert(PROFILES.includes(u.userType), `${u.userType}: is a documented profile`);
  assert(u.sharedCore === true, `${u.userType}: states the shared-core model`);
  assert(Array.isArray(u.capabilities) && u.capabilities.length > 5, `${u.userType}: maps workflows to capabilities`);
  assert(new Set(u.capabilities).size === u.capabilities.length, `${u.userType}: has no duplicate capability entries`);
  for (const id of u.capabilities ?? []) assert(ids.includes(id), `${u.userType}: references an existing capability id`, String(id));
  assert(Array.isArray(u.userTypeSpecificDatasetAssets) && u.userTypeSpecificDatasetAssets.length === 0, `${u.userType}: declares no per-profile duplicate Dataset assets`);
}

// No blanket-completion claim while a dataset-relevant row is not covered.
const coveredAll = caps.filter((c) => c.datasetRequirement !== 'NONE').every((c) => c.coverageStatus === 'COVERED_VERIFIED');
const claimsFull = /100%\s+(dataset\s+)?coverage/i.test(raw);
assert(!claimsFull || coveredAll, 'matrix does not assert 100% coverage while dataset-relevant rows are blocked');

process.stdout.write(`\n${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
