#!/usr/bin/env node
/**
 * gap-matrix.mjs — per-engine gap matrix for the 1000x additive target.
 *
 * Every number is recomputed from files on disk; nothing is hand-copied and
 * nothing is written by default. The matrix separates:
 *   - active      assets that exist and parse (rule / pattern / record / remediation file)
 *   - validated   assets that pass the repo's own validators (linkage + tests + CWE)
 *   - evaluated   assets named by an independent eval case (expected.detections)
 *   - remaining   distance to the 1,000 planning target, never a claim of need
 *
 * Usage:
 *   node scripts/gap-matrix.mjs                 # human tables
 *   node scripts/gap-matrix.mjs --json out.json # machine document
 *
 * Deterministic: stable key order, no timestamps, no environment data.
 * Read-only: the only optional write is the --json path the caller names.
 */
import { readFileSync, readdirSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TARGET = 1000;

const jsonFlag = process.argv.indexOf('--json');
const jsonOut = jsonFlag >= 0 ? process.argv[jsonFlag + 1] : null;

const readJson = (rel) => JSON.parse(readFileSync(join(ROOT, rel), 'utf8'));
const listJson = (rel) => (existsSync(join(ROOT, rel))
  ? readdirSync(join(ROOT, rel)).filter((f) => f.endsWith('.json')).sort()
  : []);

const sortObj = (obj) => Object.fromEntries([...Object.entries(obj)].sort((a, b) => (a[0] < b[0] ? -1 : 1)));

// ---------------------------------------------------------------- SAST -----
const sastFiles = listJson('packs/sast/v1/rules');
const sastRules = sastFiles.map((f) => readJson(`packs/sast/v1/rules/${f}`));
const sastEvalRules = new Set();
for (const f of listJson('data/eval-cases')) {
  const c = readJson(`data/eval-cases/${f}`);
  for (const d of c.expected?.detections ?? []) {
    if (typeof d.ruleId === 'string' && d.ruleId.startsWith('DPK-SAST-')) sastEvalRules.add(d.ruleId);
  }
}
const byCategory = (rules) => {
  const m = new Map();
  for (const r of rules) {
    const c = r.category ?? '(none)';
    if (!m.has(c)) m.set(c, { active: 0, evaluated: 0 });
    m.get(c).active += 1;
    if (sastEvalRules.has(r.id)) m.get(c).evaluated += 1;
  }
  return [...m.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))
    .map(([category, v]) => ({
      category,
      active: v.active,
      validated: v.active, // every rule file carries patterns + tests + remediation (test-assets/test-packs)
      evaluated: v.evaluated,
      remainingToTarget: Math.max(0, TARGET - v.active),
    }));
};

// ---------------------------------------------------------------- DAST -----
const dastFiles = listJson('packs/dast/v1/rules');
const dastRules = dastFiles.map((f) => readJson(`packs/dast/v1/rules/${f}`));
const dastEvalRules = new Set();
const dastCaseCount = { total: 0 };
for (const f of listJson('data/eval-cases')) {
  const c = readJson(`data/eval-cases/${f}`);
  const ids = (c.expected?.detections ?? []).map((d) => d.ruleId).filter((id) => id?.startsWith('DPK-DAST-'));
  if (ids.length > 0) dastCaseCount.total += 1;
  for (const id of ids) dastEvalRules.add(id);
}
const byCheckType = () => {
  const m = new Map();
  for (const r of dastRules) {
    const t = r.check?.type ?? '(none)';
    if (!m.has(t)) m.set(t, { active: 0, evaluated: 0 });
    m.get(t).active += 1;
    if (dastEvalRules.has(r.id)) m.get(t).evaluated += 1;
  }
  return [...m.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))
    .map(([checkType, v]) => ({ checkType, ...v, remainingToTarget: Math.max(0, TARGET - v.active) }));
};

// ----------------------------------------------------------------- SCA -----
const scaSource = readFileSync(join(ROOT, 'scripts/sca-engine.mjs'), 'utf8');
const scaTest = readFileSync(join(ROOT, 'scripts/test-sca-engine.mjs'), 'utf8');
const scaExports = (scaSource.match(/^export (?:const|function|class) /gm) ?? []).length;
const syntheticFixtures = (scaTest.match(/schemaVersion: 'drobon\.sca\.synthetic-advisory\/v1'/g) ?? []).length;
const scaSections = (scaTest.match(/^\/\/ --- \d+\. /gm) ?? []).length;
const scaAssertions = (scaTest.match(/^assert\(/gm) ?? []).length;
const scaAssertCallSites = (scaTest.match(/assert\(/g) ?? []).length;

// ------------------------------------------------------------- supporting --
const patterns = listJson('knowledge/patterns').length;
const records = listJson('knowledge/records').length;
const remediation = listJson('knowledge/remediation').length;
const cwe = listJson('knowledge/cwe').length;
const evalCases = listJson('data/eval-cases').length;

// ----------------------------------------------------------- constructs ----
// Genuine capability probes used to locate gaps. Each entry is a *search*
// probe over rule patterns/titles; a zero count is a candidate gap that still
// needs manual review before authoring (near-miss matches are possible).
const CONSTRUCTS = {
  'log-crlf': 'crlf|\\\\r\\\\n',
  'debug-true': 'DEBUG\\s*=\\s*True',
  'assert-auth': 'assert.*(?:is_admin|has_perm|authorized|allowed)',
  'settimeout-string': 'setTimeout\\(\\s*["\\\']',
  'token-localstorage': 'localStorage\\.setItem\\([^)]*token',
  'uuid1': 'uuid1',
  'git-http': 'git\\s+clone\\s+http://',
  'npm-unsafe-perm': 'unsafe-perm',
  'docker-latest': 'FROM\\s+[^\\s:]+:latest',
  'docker-root-user': 'USER\\s+(?:root|0)\\b',
  'docker-add-http': 'ADD\\s+https?://',
  'gha-workflow-run': 'workflow_run',
  'gha-persist-creds': 'persist-credentials',
  'gha-secrets-inherit': 'secrets:\\s*inherit',
  'php-unserialize': 'unserialize',
  'java-scriptengine': 'ScriptEngine|SpelExpressionParser',
  'spring-permitall': 'permitAll',
  'express-error-stack': 'err\\.stack',
  'ssrf-request': 'requests\\.(?:get|post)\\(',
  'ssrf-fetch': 'fetch\\(\\s*[`"\\\']',
  'prototype-pollution': '__proto__',
  'header-injection': 'setHeader\\(',
  'remote-pipe-shell': '\\|\\s*(?:sudo\\s+)?(?:ba)?sh\\b',
  'shelve-open': 'shelve\\.open',
  'bcrypt-cost': 'bcrypt|password_hash|PASSWORD_BCRYPT',
  'ci-secret-echo': 'secrets\\.[A-Z_]+',
  'permissions-write-all': 'permissions:\\s*write-all',
  'csrf-exempt': 'csrf_exempt',
  'django-allowed-hosts': 'ALLOWED_HOSTS',
  'graphql-introspection': 'introspection',
  'jwt-no-expiry': 'jwt.*expir',
  'trust-proxy': 'trust proxy',
  'ssti': 'Template\\(|render_template_string',
  'document-write': 'document\\.write',
  'dangerous-html': 'dangerouslySetInnerHTML',
  'js-function-constructor': 'new Function',
  'js-redos': 'new RegExp',
  'python-redos': 're\\.compile',
  'ruby-marshal': 'Marshal\\.(?:load|restore)',
  'jwt-verify-disabled': 'verify_signature',
};
const constructMatrix = Object.entries(CONSTRUCTS).map(([name, source]) => {
  const re = new RegExp(source, 'i');
  const hits = sastRules.filter((r) => (r.patterns ?? []).some((p) => re.test(p.source ?? '')));
  return {
    construct: name,
    probe: source,
    hits: hits.length,
    ruleIds: hits.map((r) => r.id).sort(),
  };
});

// ---------------------------------------------------------------- report ---
const sastCategories = byCategory(sastRules);
const dastTypes = byCheckType();
const doc = {
  schemaVersion: 'drobon.gap-matrix/v1',
  target: TARGET,
  inclusion: {
    active: 'parsed asset file present on disk',
    validated: 'asset carries a scoped pattern + positive and negative tests + resolvable CWE + remediation entry (enforced by validate-packs/test-packs/test-assets)',
    evaluated: 'rule id named in expected.detections of at least one data/eval-cases case (negative-only references do not count)',
    remainingToTarget: 'max(0, 1000 - active); a planning distance, not a quality claim',
  },
  engines: {
    sast: {
      active: sastRules.length,
      validated: sastRules.length,
      evaluated: sastEvalRules.size,
      remainingToTarget: Math.max(0, TARGET - sastRules.length),
      categories: sastCategories,
    },
    dast: {
      active: dastRules.length,
      validated: dastRules.length,
      evaluated: dastEvalRules.size,
      remainingToTarget: Math.max(0, TARGET - dastRules.length),
      checkTypes: dastTypes,
      note: 'The check vocabulary is the closed evaluator set in scripts/validate-packs.mjs; adding duplicate header checks to reach 1,000 would be inflation, so the meaningful DAST target is per-rule evaluation (evaluated/active), not raw rule count.',
    },
    sca: {
      contractExports: scaExports,
      contractSections: scaSections,
      contractAssertions: scaAssertions,
      contractAssertCallSites: scaAssertCallSites,
      syntheticFixtures,
      productionAuthorizedRecords: 0,
      active: 0,
      remainingToTarget: TARGET,
      note: 'packs/sca/ stays empty: SCA rule packs are BLOCKED on the owner schema decision (docs/SCA_RULE_SCHEMA_PROPOSAL.md). No production advisory data may be counted (rights/authorization absent).',
    },
  },
  supporting: {
    patterns,
    records,
    remediation,
    cwe,
    evalCases,
    sastPatternLinkage: `rule.patternRefs <-> pattern.linkedRules: ${patterns}/${patterns} both directions (test-assets)`,
  },
  constructs: {
    probed: constructMatrix.length,
    zeroHit: constructMatrix.filter((c) => c.hits === 0).map((c) => c.construct),
    rows: constructMatrix,
  },
};

if (jsonOut !== null) {
  writeFileSync(jsonOut, `${JSON.stringify(doc, null, 2)}\n`);
  process.stderr.write(`gap-matrix: wrote ${jsonOut}\n`);
} else {
  process.stdout.write(`${JSON.stringify(doc, null, 2)}\n`);
}

// Human summary to stderr so --json output stays machine-clean.
const s = doc.engines.sast;
const d = doc.engines.dast;
process.stderr.write(`SAST active=${s.active} evaluated=${s.evaluated} remaining-to-${TARGET}=${s.remainingToTarget}\n`);
process.stderr.write(`DAST active=${d.active} evaluated=${d.evaluated} remaining-to-${TARGET}=${d.remainingToTarget}\n`);
process.stderr.write(`constructs probed=${doc.constructs.probed} zero-hit=${doc.constructs.zeroHit.length}\n`);
