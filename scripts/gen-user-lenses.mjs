#!/usr/bin/env node
/**
 * gen-user-lenses.mjs — per-user-type 1,000-rule lenses over the shared packs.
 *
 * Why this exists: the owner asked for "1,000 per engine" and then clarified that
 * the four user types count as engines too. The Main App has no per-user-type
 * engine (engines.ts closes ScanType to sast/sca/secrets/dast), so the only
 * honest way to give DEVELOPER / STUDENT / SECURITY_PROFESSIONAL / PENTESTER a
 * 1,000-rule surface is a *lens*: a deterministic, documented selection of the
 * 1,000 rules from the existing packs that matter most to that audience.
 *
 * A lens is NOT new content. Copying rules into four per-user-type packs would
 * quadruple the counts without adding a single detection, which is exactly the
 * padding docs/PACKS.md forbids. The lens file records, for every selected rule,
 * the score and the reasons it was selected, so the choice is auditable and
 * reproducible.
 *
 * Selection model (deterministic, no clock, no network):
 *   score = kindWeight(userType, kind)
 *         + severityWeight(severity)
 *         + categoryAffinity(userType, category)
 *         + reachableBonus(userType, reachable)
 *   ties break on rule id, then the first 1,000 by descending score are kept.
 * The weights are authored policy, printed in docs/USER_TYPE_LENSES.md.
 *
 * Output: views/<slug>-v1.json, docs/USER_TYPE_LENSES.{md,json}
 * Usage:  --write to render, --check (runs in npm test) to verify.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const WRITE = process.argv.includes('--write');
const CHECK = process.argv.includes('--check');
const TARGET = 1000;
const AS_OF = '2026-10-21';

const KINDS = ['sast', 'sca', 'secrets', 'dast'];
const PREFIX = { sast: 'DPK-SAST-', dast: 'DPK-DAST-', secrets: 'DPK-SEC-', sca: 'DPK-SCA-' };
const SEVERITY_WEIGHT = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

// Authored policy: how much each scan kind matters to each audience, and which
// categories that audience works in day to day. Every number is printed on the
// generated page so a reader can argue with it.
const USER_TYPES = [
  {
    id: 'DEVELOPER',
    slug: 'developer',
    label: 'Developer',
    kindWeight: { sast: 3.0, sca: 2.0, secrets: 1.6, dast: 0.9 },
    affinity: {
      'injection': 1.2, 'deserialization': 1.2, 'path-traversal': 1.0, 'crypto': 0.8,
      'command-execution': 1.0, 'xss': 0.8, 'ssrf': 0.8, 'authentication': 0.6,
      'ci-security': 1.0, 'configuration': 0.6, 'race-condition': 0.6,
    },
    reachableBonus: 0.8,
    purpose: 'Rules a developer can act on in a pull request: source-level sinks, dependency and CI configuration, and the credential shapes that end up committed.',
  },
  {
    id: 'STUDENT',
    slug: 'student',
    label: 'Student',
    kindWeight: { sast: 2.4, secrets: 1.8, dast: 1.6, sca: 1.2 },
    affinity: {
      'injection': 1.2, 'xss': 1.2, 'path-traversal': 1.0, 'authentication': 1.0,
      'crypto': 1.0, 'deserialization': 0.8, 'information-disclosure': 0.8,
      'security-headers': 0.8, 'transport-security': 0.8, 'privacy-exposure': 0.6,
    },
    reachableBonus: 0.6,
    purpose: 'Rules whose finding is explainable in a lesson: a clear sink, a bounded scope and a remediation the learner can apply themselves.',
  },
  {
    id: 'SECURITY_PROFESSIONAL',
    slug: 'security-professional',
    label: 'Security professional',
    kindWeight: { sast: 1.8, dast: 2.2, secrets: 2.0, sca: 2.2 },
    affinity: {
      'information-disclosure': 1.0, 'security-headers': 1.0, 'csp-weakness': 1.0,
      'cors': 1.0, 'cookie-flags': 1.0, 'transport-security': 0.8, 'credential-exposure': 1.2,
      'debug-exposure': 1.0, 'exposed-interface': 0.8, 'injection': 0.8, 'crypto': 0.8,
    },
    reachableBonus: 0.8,
    purpose: 'Rules that produce an assessment finding: live response evidence, exposed interfaces and credentials, plus the source classes that explain them.',
  },
  {
    id: 'PENTESTER',
    slug: 'pentester',
    label: 'Pentester',
    kindWeight: { dast: 3.0, secrets: 2.2, sast: 1.4, sca: 0.8 },
    affinity: {
      'open-redirect': 1.2, 'authentication': 1.2, 'injection': 1.0, 'ssrf': 1.0,
      'exposed-interface': 1.2, 'information-disclosure': 1.0, 'debug-exposure': 1.0,
      'data-exposure': 1.0, 'weak-markup': 0.8, 'path-traversal': 0.8,
    },
    reachableBonus: 1.0,
    purpose: 'Passive rules an engagement can check without touching the target: response evidence, exposed surfaces and credential shapes that show up in a response.',
  },
];

function readRules(kind) {
  const dir = join(ROOT, 'packs', kind, 'v1', 'rules');
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(dir, f), 'utf8')))
    .map((r) => ({
      id: r.id,
      kind,
      severity: r.severity,
      category: r.category,
      cwe: r.cwe,
      languages: Array.isArray(r.languages) ? r.languages : null,
      header: (r.check?.header ?? '').toLowerCase(),
      checkType: r.check?.type ?? '',
      hasRemediation: Boolean(r.remediation),
    }));
}

const allRules = KINDS.flatMap(readRules);

// --- reachability, read from the artefacts that already measure it -------------
const reachability = (() => {
  const packs = readFileSync(join(ROOT, 'docs', 'PACKS.md'), 'utf8');
  const block = /^```app-language-catalog\n([\s\S]*?)\n```$/m.exec(packs);
  const catalog = block ? JSON.parse(block[1]) : {};
  const analyzed = new Set(Object.keys(catalog).filter((id) => ['PARTIAL', 'CONFIG_ANALYSIS', 'FULL'].includes(catalog[id])));

  const dast = JSON.parse(readFileSync(join(ROOT, 'interop', 'app-dast-reachability.json'), 'utf8'));
  const headers = new Set((dast.surface?.inspectedResponseHeaders ?? []).map((h) => h.toLowerCase()));

  return (rule) => {
    if (rule.kind === 'sast') {
      if (rule.languages === null) return true; // no `languages` field: any-file convention
      return rule.languages.some((id) => analyzed.has(id));
    }
    if (rule.kind === 'dast') {
      if (rule.header === '') return true; // body rules have no header gate
      return headers.has(rule.header);
    }
    if (rule.kind === 'secrets') return true; // the App secrets engine has no header/language gate
    return false; // sca has no rules yet
  };
})();

function scoreOf(rule, user) {
  const reasons = [];
  let score = user.kindWeight[rule.kind] ?? 0;
  reasons.push(`kind ${rule.kind} ${(user.kindWeight[rule.kind] ?? 0).toFixed(1)}`);
  const sev = SEVERITY_WEIGHT[rule.severity] ?? 0;
  if (sev > 0) {
    score += sev * 0.5;
    reasons.push(`severity ${rule.severity} ${(sev * 0.5).toFixed(1)}`);
  }
  const aff = user.affinity[rule.category] ?? 0;
  if (aff > 0) {
    score += aff;
    reasons.push(`category ${rule.category} ${aff.toFixed(1)}`);
  }
  const reachable = reachability(rule);
  if (reachable && user.reachableBonus > 0) {
    score += user.reachableBonus;
    reasons.push(`app-reachable ${user.reachableBonus.toFixed(1)}`);
  }
  return { score: Math.round(score * 100) / 100, reasons, reachable };
}

function buildLens(user) {
  const scored = allRules
    .map((rule) => ({ rule, ...scoreOf(rule, user) }))
    .sort((a, b) => (b.score - a.score) || (a.rule.id < b.rule.id ? -1 : a.rule.id > b.rule.id ? 1 : 0));
  const selected = scored.slice(0, TARGET);
  const byKind = {};
  for (const s of selected) byKind[s.rule.kind] = (byKind[s.rule.kind] ?? 0) + 1;
  const bySeverity = {};
  for (const s of selected) bySeverity[s.rule.severity] = (bySeverity[s.rule.severity] ?? 0) + 1;
  const reachableCount = selected.filter((s) => s.reachable).length;
  const lastScore = selected.length > 0 ? selected[selected.length - 1].score : 0;
  return {
    schemaVersion: 'drobon.view.user-lens/v1',
    asOf: AS_OF,
    userType: user.id,
    label: user.label,
    target: TARGET,
    note: 'A lens is a selection over the shared packs, not new content. The same rule can serve several user types; no rule is copied and no count here is a duplicate of another engine.',
    purpose: user.purpose,
    method: {
      scoreFormula: 'kindWeight + 0.5*severityWeight + categoryAffinity + reachableBonus',
      kindWeight: user.kindWeight,
      severityWeight: { CRITICAL: 2, HIGH: 1.5, MEDIUM: 1, LOW: 0.5 },
      categoryAffinity: user.affinity,
      reachableBonus: user.reachableBonus,
      tieBreak: 'descending score, then ascending rule id',
      cutoffScore: lastScore,
    },
    counts: {
      selected: selected.length,
      candidates: scored.length,
      reachable: reachableCount,
      unreachable: selected.length - reachableCount,
      byKind,
      bySeverity,
    },
    selection: selected.map((s) => ({ ruleId: s.rule.id, kind: s.rule.kind, score: s.score, reasons: s.reasons })),
  };
}

const lenses = USER_TYPES.map((user) => ({ user, lens: buildLens(user) }));

const json = {
  schemaVersion: 'drobon.view.user-lenses/v1',
  asOf: AS_OF,
  target: TARGET,
  note: 'Per-user-type lenses over the shared packs. The App has four scan engines (sast/sca/secrets/dast); a user type is an audience lens, never a fifth engine.',
  candidates: allRules.length,
  lenses: lenses.map(({ user, lens }) => ({
    userType: user.id,
    slug: user.slug,
    label: user.label,
    selected: lens.counts.selected,
    reachable: lens.counts.reachable,
    byKind: lens.counts.byKind,
    cutoffScore: lens.method.cutoffScore,
    file: `views/${user.slug}-v1.json`,
  })),
};

const md = [];
md.push('# Per-user-type lenses — 1,000 rules each (2026-10-21)');
md.push('');
md.push('> **Measured, not promised.** `node scripts/gen-user-lenses.mjs --write` renders this page and the four');
md.push('> lens files; `--check` runs inside `npm test`, so a selection cannot drift from the packs.');
md.push('');
md.push('## What a "user-type engine" can honestly be');
md.push('');
md.push('The Main App closes `ScanType` to `sast`, `sca`, `secrets` and `dast` (`apps/api/src/engines.ts` at');
md.push('`9360dd1`), so there is no per-user-type engine to load a pack. What the dataset can give each user');
md.push('type is a **lens**: a deterministic selection of the 1,000 rules from the shared packs that matter most');
md.push('for that audience, with the score and the reasons recorded for every one of them.');
md.push('');
md.push('A lens is **not new content**. Writing four 1,000-rule packs would quadruple the counts while adding');
md.push('zero detections — the padding `docs/PACKS.md` forbids. The same rule can legitimately serve several');
md.push('audiences, and this page says so instead of counting it four times as if it were new.');
md.push('');
md.push('## The four lenses');
md.push('');
md.push('| UserType | Selected | App-reachable | Cutoff score | SAST | SCA | Secrets | DAST | File |');
md.push('|---|---|---|---|---|---|---|---|---|');
for (const { user, lens } of lenses) {
  const k = lens.counts.byKind;
  md.push(`| ${lens.userType} | **${lens.counts.selected}** / ${TARGET} | ${lens.counts.reachable} | ${lens.method.cutoffScore.toFixed(2)} | ${k.sast ?? 0} | ${k.sca ?? 0} | ${k.secrets ?? 0} | ${k.dast ?? 0} | \`views/${user.slug}-v1.json\` |`);
}
md.push('');
md.push(`Candidates: **${allRules.length}** rules across the four packs. Every lens selects the top ${TARGET}, so a rule`);
md.push('outside a lens is not rejected as wrong — it is simply past the cutoff for that audience.');
md.push('');
md.push('## Scoring model (authored policy, printed so it can be argued with)');
md.push('');
md.push('`score = kindWeight + 0.5 × severityWeight + categoryAffinity + reachableBonus`; ties break on rule id.');
md.push('');
md.push('| UserType | SAST | SCA | Secrets | DAST | Reachable bonus |');
md.push('|---|---|---|---|---|---|');
for (const { user } of lenses) {
  const w = user.kindWeight;
  md.push(`| ${user.id} | ${w.sast.toFixed(1)} | ${w.sca.toFixed(1)} | ${w.secrets.toFixed(1)} | ${w.dast.toFixed(1)} | ${user.reachableBonus.toFixed(1)} |`);
}
md.push('');
md.push('Category affinities are listed per user type in `docs/USER_TYPE_LENSES.json` and in each lens file’s');
md.push('`method` block. “App-reachable” reuses the measured surfaces: the 53-id App language catalog for SAST,');
md.push('the 11 forwarded response headers for DAST, and the ungated secrets engine.');
md.push('');
md.push('## What this does not claim');
md.push('');
md.push('- No user type has a live App consumer for these lenses; the file is a dataset artefact until the App');
md.push('  gains an audience filter.');
md.push('- A selected rule is not a verified finding: reachability measures whether the rule *can* fire, not');
md.push('  whether it fires correctly. That is the eval corpus’s job (4,718 cases, TP 4,041, FN 0, FP 1).');
md.push('- SCA contributes zero rules to every lens because the SCA pack is still empty and blocked on the');
md.push('  owner decision recorded in `DROBON_REMAINING_WORK.csv` (GAP-001, GAP-002).');
md.push('');
md.push('---');
md.push('');
md.push('Regenerate: `node scripts/gen-user-lenses.mjs --write`. Verify: `--check`.');
md.push('');

const outputs = new Map();
outputs.set('docs/USER_TYPE_LENSES.md', md.join('\n'));
outputs.set('docs/USER_TYPE_LENSES.json', `${JSON.stringify(json, null, 2)}\n`);
for (const { user, lens } of lenses) {
  outputs.set(`views/${user.slug}-v1.json`, `${JSON.stringify(lens, null, 2)}\n`);
}

function verify() {
  const problems = [];
  for (const [file, expected] of outputs) {
    const path = join(ROOT, file);
    if (!existsSync(path)) problems.push(`${file}: missing`);
    else if (readFileSync(path, 'utf8') !== expected) problems.push(`${file}: stale`);
  }
  // Guard rails that do not depend on the rendered bytes: the lens must select
  // real rule ids, once each, and must not be a copy of another lens.
  const idsOnDisk = new Set(allRules.map((r) => r.id));
  const signatures = new Map();
  for (const { user, lens } of lenses) {
    if (lens.selection.length !== TARGET) problems.push(`${user.id}: selects ${lens.selection.length}, expected ${TARGET}`);
    const ids = lens.selection.map((s) => s.ruleId);
    if (new Set(ids).size !== ids.length) problems.push(`${user.id}: duplicate rule id in selection`);
    const unknown = ids.filter((id) => !idsOnDisk.has(id));
    if (unknown.length > 0) problems.push(`${user.id}: unknown rule ids ${unknown.slice(0, 3).join(', ')}`);
    const sig = ids.slice().sort().join(',');
    if (signatures.has(sig)) problems.push(`${user.id}: identical selection to ${signatures.get(sig)}`);
    signatures.set(sig, user.id);
  }
  return problems;
}

if (CHECK) {
  const problems = verify();
  if (problems.length > 0) {
    for (const p of problems) process.stderr.write(`user-lenses: ${p}\n`);
    process.stderr.write('user-lenses: FAIL — run node scripts/gen-user-lenses.mjs --write\n');
    process.exit(1);
  }
  process.stdout.write(`user-lenses: OK — ${lenses.map(({ lens }) => `${lens.userType} ${lens.counts.selected}/${TARGET} (${lens.counts.reachable} reachable)`).join(' · ')}\n`);
} else if (WRITE) {
  mkdirSync(join(ROOT, 'views'), { recursive: true });
  for (const [file, text] of outputs) writeFileSync(join(ROOT, file), text);
  process.stdout.write(`wrote ${outputs.size} files (docs/USER_TYPE_LENSES.{md,json} + views/*.json)\n`);
  for (const { lens } of lenses) {
    process.stdout.write(`  ${lens.userType.padEnd(22)} ${String(lens.counts.selected).padStart(5)} / ${TARGET}  reachable ${lens.counts.reachable}  cutoff ${lens.method.cutoffScore.toFixed(2)}\n`);
  }
} else {
  process.stdout.write(`user-lenses: ${allRules.length} candidates; pass --write or --check\n`);
}
