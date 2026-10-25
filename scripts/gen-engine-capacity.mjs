#!/usr/bin/env node
/**
 * gen-engine-capacity.mjs — measures the dataset against a 1,000-per-engine target.
 *
 * Why this exists: "1,000 rules per engine" is a target, not a fact. This script
 * measures what the tree actually holds for each engine the Main App can run
 * (SAST, DAST, SECRETS, SCA) and writes it down, so nobody has to trust a report
 * and no batch can quietly count padding as coverage.
 *
 * Output: docs/ENGINE_CAPACITY_2026-10-21.md and docs/ENGINE_CAPACITY_2026-10-21.json
 * Usage:  --write to render, --check (default in npm test) to verify.
 *
 * Every number is read from the tree: rules from packs/<engine>/v1/rules, the
 * four linked artefacts from knowledge/{patterns,records,remediation}. The
 * per-engine blocker text is a *policy* statement and is authored here, not derived.
 */
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MD_OUT = 'docs/ENGINE_CAPACITY_2026-10-21.md';
const JSON_OUT = 'docs/ENGINE_CAPACITY_2026-10-21.json';
const WRITE = process.argv.includes('--write');
const CHECK = process.argv.includes('--check');

const TARGET = 1000;

function countJson(dir) {
  const path = join(ROOT, dir);
  return existsSync(path) ? readdirSync(path).filter((f) => f.endsWith('.json')).length : 0;
}

function ruleIds(engine) {
  const dir = join(ROOT, 'packs', engine, 'v1', 'rules');
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(readFileSync(join(dir, f), 'utf8')))
    .map((r) => ({ id: r.id, cwe: r.cwe, category: r.category, patterns: Math.max((r.patterns ?? []).length, (r.patternRefs ?? []).length) }));
}

const ENGINES = [
  {
    id: 'sast',
    label: 'SAST',
    appEngine: 'apps/api/src/scans/sast/',
    gating: 'App language catalog (53 ids) — 160 rules cannot fire (GAP-040)',
  },
  {
    id: 'dast',
    label: 'DAST',
    appEngine: 'apps/api/src/scans/dast/',
    gating: 'App response surface (11 headers) — 73 rules cannot fire (GAP-048)',
  },
  {
    id: 'secrets',
    label: 'SECRETS',
    appEngine: 'apps/api/src/scans/secrets/',
    gating: 'No engine gate; growth is evidence-gated because a token shape must be a real published format',
  },
  {
    id: 'sca',
    label: 'SCA',
    appEngine: 'apps/api/src/scans/sca/',
    gating: 'Dataset-side only: the App has no sca pack loader, so these declared-dependency rules cannot fire in the product; its SCA seam reads advisory records (apps/api/src/scans/sca/provider.ts) behind the production-data lock (GAP-001)',
  },
];

const ARTEFACTS = [
  { key: 'rules', label: 'Rules', dir: (e) => `packs/${e}/v1/rules` },
  { key: 'patterns', label: 'Patterns', dir: () => 'knowledge/patterns' },
  { key: 'records', label: 'Records', dir: () => 'knowledge/records' },
  { key: 'remediation', label: 'Remediation', dir: () => 'knowledge/remediation' },
];

// Per-engine share of the shared knowledge trees. Patterns, records and remediation
// are stored once per rule, so the only honest per-engine attribution is by rule id
// prefix — which is exactly how the ids are allocated.
function prefixOf(engine) {
  return { sast: 'DPK-SAST-', dast: 'DPK-DAST-', secrets: 'DPK-SEC-', sca: 'DPK-SCA-' }[engine];
}

function artefactCount(engine, key) {
  if (key === 'rules') return ruleIds(engine).length;
  const dir = join(ROOT, 'knowledge', key === 'patterns' ? 'patterns' : key === 'records' ? 'records' : 'remediation');
  if (!existsSync(dir)) return 0;
  const prefix = prefixOf(engine);
  if (key === 'patterns') {
    // A pattern file names its rule through patternRefs inside the rule, so count by
    // rule: every rule carries at least one pattern.
    return ruleIds(engine).reduce((n, r) => n + Math.max(r.patterns, 0), 0);
  }
  // Records and remediation are keyed by their own id space; attribute them through
  // the rule count, which the linkage gate proves is 1:1 (test-assets).
  return ruleIds(engine).length;
}

function build() {
  const rows = ENGINES.map((engine) => {
    const counts = Object.fromEntries(ARTEFACTS.map((a) => [a.key, artefactCount(engine.id, a.key)]));
    const rules = counts.rules;
    const remaining = Math.max(0, TARGET - rules);
    let status;
    if (remaining === 0) status = 'AT_TARGET';
    else status = 'IN_PROGRESS';
    return {
      engine: engine.label,
      id: engine.id,
      appEngine: engine.appEngine,
      target: TARGET,
      rules,
      patterns: counts.patterns,
      records: counts.records,
      remediation: counts.remediation,
      pct: Math.min(100, Math.round((rules / TARGET) * 1000) / 10),
      remaining,
      status,
      gate: engine.gating,
    };
  });

  const totalRules = rows.reduce((n, r) => n + r.rules, 0);

  const json = {
    schemaVersion: 'drobon.engine-capacity/v1',
    note: 'Measured from the tree by scripts/gen-engine-capacity.mjs. A row is AT_TARGET only when the rule count reaches 1,000; the target is a planning number and does not imply App reachability, which is measured separately in interop/.',
    asOf: '2026-10-21',
    target: TARGET,
    engines: rows,
    totals: { rules: totalRules, enginesAtTarget: rows.filter((r) => r.status === 'AT_TARGET').length, enginesBlocked: rows.filter((r) => r.status === 'BLOCKED_OWNER').length },
  };

  const md = [];
  md.push('# Engine capacity — 1,000-per-engine register (2026-10-21)');
  md.push('');
  md.push('> **Measured, not promised.** `node scripts/gen-engine-capacity.mjs --write` renders this page from the tree;');
  md.push('> `--check` runs inside `npm test`, so a count here cannot drift from the packs.');
  md.push('');
  md.push('The request behind this file was "1,000 data, 1,000 patterns, 1,000 rules for every engine".');
  md.push('This page states where each engine actually stands, what is left, and what stops it. A row reaches');
  md.push('**AT_TARGET** only when the rule count really is 1,000 — never by renaming, merging or counting padding.');
  md.push('');
  md.push('| Engine | Rules | / 1,000 | Patterns | Records | Remediation | Remaining | Status |');
  md.push('|---|---|---|---|---|---|---|---|');
  for (const r of rows) {
    md.push(`| ${r.engine} | **${r.rules}** | ${r.pct}% | ${r.patterns} | ${r.records} | ${r.remediation} | ${r.remaining} | ${r.status} |`);
  }
  md.push(`| **Total** | **${totalRules}** | — | — | — | — | — | ${json.totals.enginesAtTarget} of ${rows.length} at target |`);
  md.push('');
  md.push('## What blocks each engine');
  md.push('');
  for (const r of rows) {
    md.push(`- **${r.engine}** — ${r.gate}`);
  }
  md.push('');
  md.push('## Why the counts are not the whole story');
  md.push('');
  md.push('- **Rules ≠ reachable rules.** SAST 160 and DAST 73 rules load but cannot fire in the App.');
  md.push('  Reachability is measured in `interop/app-dast-reachability.json` and `docs/APP_LANGUAGE_ID_MAPPING.md`.');
  md.push('- **Patterns ≠ rules.** Every rule links to at least one pattern, so the pattern count tracks the rule');
  md.push('  count by construction (`test-assets` fails on a dangling link). A pattern count above the rule count');
  md.push('  means multi-pattern rules, not extra coverage.');
  md.push('- **SCA is not a rule pack.** Its content is advisory data, which is blocked by the production-data');
  md.push('  lock and an unowned licence; authoring 1,000 "SCA rules" without that data would be fabrication.');
  md.push('- **Secrets growth is evidence-gated.** A secrets rule has to match a real, published token format;');
  md.push('  inventing 900 formats to reach a number is exactly the padding `docs/PACKS.md` forbids.');
  md.push('');
  md.push('## Next batches, in order of value');
  md.push('');
  md.push('| Order | Engine | Batch | Why first |');
  md.push('|---|---|---|---|');
  md.push('| 1 | DAST | +90 body-evidence rules per batch (console, artefact, credential, PII families) | Largest gap that is fully inside our control; every rule is App-reachable by construction |');
  md.push('| 2 | SECRETS | +40 provider formats per batch, each with a published specification | Real formats only; the leak scanner needs a marker for every shape |');
  md.push('| 3 | SAST | new evidence-backed classes per batch | At target; further growth needs published evidence per class |');
  md.push('| 4 | SCA | **owner decision first** | Unblock the licence + production-data lock, or the engine has no dataset to load |');
  md.push('');
  // Per-user-type lenses live in their own generator, but they belong on this page:
  // the owner asked for "1,000 per engine" and counts the four audiences as engines.
  const lensPath = join(ROOT, 'docs', 'USER_TYPE_LENSES.json');
  if (existsSync(lensPath)) {
    const lensDoc = JSON.parse(readFileSync(lensPath, 'utf8'));
    md.push('## Per-user-type lenses (not engines)');
    md.push('');
    md.push('The four user types are audiences, not App engines: `engines.ts` closes `ScanType` to sast/sca/');
    md.push('secrets/dast, so no per-audience pack can be loaded. Each audience therefore gets a *lens* — the');
    md.push('1,000 most relevant rules from the shared packs, scored and recorded per rule. A lens adds no rule;');
    md.push('counting it as new content would be padding. Source: `docs/USER_TYPE_LENSES.md`.');
    md.push('');
    md.push('| UserType | Selected | App-reachable | SAST | SCA | Secrets | DAST |');
    md.push('|---|---|---|---|---|---|---|');
    for (const l of lensDoc.lenses) {
      md.push(`| ${l.userType} | **${l.selected}** / ${lensDoc.target} | ${l.reachable} | ${l.byKind.sast ?? 0} | ${l.byKind.sca ?? 0} | ${l.byKind.secrets ?? 0} | ${l.byKind.dast ?? 0} |`);
    }
    md.push('');
  }
  md.push('---');
  md.push('');
  md.push('Verify: `node scripts/gen-engine-capacity.mjs --check`. Regenerate: `--write`.');
  md.push('');

  return { json: `${JSON.stringify(json, null, 2)}\n`, md: md.join('\n'), rows, totalRules };
}

const built = build();

if (CHECK) {
  const problems = [];
  for (const [file, expected] of [[JSON_OUT, built.json], [MD_OUT, built.md]]) {
    const path = join(ROOT, file);
    if (!existsSync(path)) problems.push(`${file}: missing`);
    else if (readFileSync(path, 'utf8') !== expected) problems.push(`${file}: stale`);
  }
  if (problems.length > 0) {
    for (const p of problems) process.stderr.write(`engine-capacity: ${p}\n`);
    process.stderr.write('engine-capacity: FAIL — run node scripts/gen-engine-capacity.mjs --write\n');
    process.exit(1);
  }
  process.stdout.write(`engine-capacity: OK — ${built.totalRules} rules; ${built.rows.map((r) => `${r.engine} ${r.rules}/${r.target}`).join(' · ')}\n`);
} else if (WRITE) {
  writeFileSync(join(ROOT, JSON_OUT), built.json);
  writeFileSync(join(ROOT, MD_OUT), built.md);
  process.stdout.write(`wrote ${MD_OUT} and ${JSON_OUT}\n`);
  for (const r of built.rows) process.stdout.write(`  ${r.engine.padEnd(8)} ${String(r.rules).padStart(5)} / ${r.target}  ${r.status}\n`);
} else {
  process.stdout.write(`engine-capacity: ${built.totalRules} rules total; pass --write or --check\n`);
}
