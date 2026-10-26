/**
 * app-feature-benchmark.mjs — "how far are we, on OUR features, per engine and per user type".
 *
 * Denominator = the Main App's own requirement rows (docs/APP_FEATURE_LEDGER.json),
 * split into two scopes that are never mixed:
 *
 *   deliverable — the dataset can finish it alone (no licence grant, no owner
 *                 decision, no App-repo change). This is the headline percentage.
 *   gated       — owned by the owner or by the Main App repo. Scored 0, listed in
 *                 full with its real number, never folded into the headline.
 *
 * Vendors are scored on the SAME deliverable+comparable denominator, from the
 * `vendorDocumented` column of DROBON_PAID_TOOL_BENCHMARK.csv.
 *
 * The script also regenerates the two legacy registers (DROBON_ENGINE_COVERAGE.csv,
 * DROBON_USERTYPE_COVERAGE.csv) from the same ledger, so those files can no longer
 * contradict it.
 *
 * Read-only, deterministic. Usage:
 *   node scripts/app-feature-benchmark.mjs --write
 *   node scripts/app-feature-benchmark.mjs --check
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_MD = 'docs/APP_FEATURE_VS_PAID_TOOL_2026-10-25.md';
const OUT_CSV = 'docs/APP_FEATURE_VS_PAID_TOOL_2026-10-25.csv';
const LEDGER = 'docs/APP_FEATURE_LEDGER.json';
const BENCH = 'DROBON_PAID_TOOL_BENCHMARK.csv';
const ENGINE_REGISTER = 'DROBON_ENGINE_COVERAGE.csv';
const USER_REGISTER = 'DROBON_USERTYPE_COVERAGE.csv';

const ENGINES = [
  ['SAST', 'SAST (App engine)'],
  ['SCA', 'SCA (App advisory seam)'],
  ['SECRETS', 'Secrets (App engine)'],
  ['DAST', 'DAST (App passive engine)'],
  ['CROSS', 'Cross-engine (findings, remediation, reports, learning)'],
];
const USERS = ['DEVELOPER', 'STUDENT', 'SECURITY_PROFESSIONAL', 'PENTESTER'];
const TOOLS = ['GHAS', 'Snyk', 'Semgrep', 'Burp Pro/DAST'];
const SHORT = { GHAS: 'GHAS', Snyk: 'Snyk', Semgrep: 'Semgrep', 'Burp Pro/DAST': 'Burp Pro' };
const ENGINE_ORDER = ['SAST', 'SCA-intel', 'Secrets', 'DAST', 'Remediation', 'Findings', 'Audience', 'Reports'];

export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { field += '"'; i += 1; }
      else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') { row.push(field); field = ''; }
    else if (ch === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else if (ch !== '\r') field += ch;
  }
  if (field.length > 0 || row.length > 0) { row.push(field); rows.push(row); }
  const [head, ...body] = rows.filter((r) => r.length > 1);
  return body.map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] ?? ''])));
}

/** documented full = 1, partial/ambiguous = 0.5, documented absent = 0, UNKNOWN = null. */
export function vendorCredit(documentation) {
  const v = String(documentation).trim();
  if (v.startsWith('Yes')) return 1;
  if (v.startsWith('Partial')) return 0.5;
  if (v.startsWith('No')) return 0;
  if (v.startsWith('UNKNOWN')) return null;
  return 0.5;
}

const pct = (points, n) => (n === 0 ? null : Math.round((points / n) * 1000) / 10);
const cell = (v) => (v === null ? '—' : `${v.toFixed(1)}%`);

export function build() {
  const ledger = JSON.parse(readFileSync(join(ROOT, LEDGER), 'utf8'));
  const bench = parseCsv(readFileSync(join(ROOT, BENCH), 'utf8'));
  const credit = new Map();
  for (const r of bench) credit.set(`${r.tool}\u0000${r.capability}`, vendorCredit(r.vendorDocumented));

  const features = ledger.features;
  const gated = ledger.gated;
  const all = [...features, ...gated];

  const score = (list) => (list.length === 0 ? null : pct(list.reduce((s, f) => s + f.points, 0), list.length));
  const vendor = (list, tool) => {
    const cmp = list.filter((f) => f.featureClass === 'comparable' && f.vendorCapability);
    let points = 0; let n = 0;
    for (const f of cmp) {
      const c = credit.get(`${tool}\u0000${f.vendorCapability}`);
      if (c === undefined || c === null) continue;
      points += c; n += 1;
    }
    return { pct: n === 0 ? null : pct(points, n), n };
  };
  const row = (scope, engine, user) => {
    const sel = scope.filter((f) => f.engine === engine && f.userTypes.includes(user));
    return {
      engine, user, features: sel.length, score: score(sel),
      comparableFeatures: sel.filter((f) => f.featureClass === 'comparable').length,
      comparableScore: score(sel.filter((f) => f.featureClass === 'comparable')),
      vendors: Object.fromEntries(TOOLS.map((t) => [t, vendor(sel, t)])),
    };
  };

  const rows = [];
  for (const [engine] of ENGINES) for (const user of USERS) rows.push(row(features, engine, user));

  const byUser = USERS.map((user) => {
    const sel = features.filter((f) => f.userTypes.includes(user));
    const cmp = sel.filter((f) => f.featureClass === 'comparable');
    return {
      user, features: sel.length, score: score(sel), comparableFeatures: cmp.length, comparableScore: score(cmp),
      vendors: Object.fromEntries(TOOLS.map((t) => [t, vendor(sel, t)])),
      gatedCount: gated.filter((f) => f.userTypes.includes(user)).length,
      gatedPoints: gated.filter((f) => f.userTypes.includes(user)).reduce((s, f) => s + f.points, 0),
    };
  });
  const byEngine = ENGINES.map(([engine, label]) => {
    const sel = all.filter((f) => f.engine === engine);
    return {
      engine, label, features: sel.length, complete: sel.filter((f) => f.points === 1).length,
      gated: sel.filter((f) => f.gatedBy).length, score: score(sel),
    };
  });

  return { ledger, features, gated, all, rows, byUser, byEngine, credit };
}

/** The two legacy registers, rebuilt from the ledger (full register, both scopes). */
export function renderRegisters(model) {
  const bucket = (f) => {
    if (f.points === 1) return 'full';
    if (f.points > 0) return 'partial';
    if (String(f.status).includes('MISSING')) return 'missing';
    return 'blocked';
  };
  const engineLines = ['engine,applicableReq,full,partial,implementedNotVerified,missing,blocked,notAssessed,verifiedCoveragePct,points,denominator'];
  for (const engine of ENGINE_ORDER) {
    const sel = model.all.filter((f) => f.engineLabel === engine);
    if (sel.length === 0) continue;
    const c = { full: 0, partial: 0, implementedNotVerified: 0, missing: 0, blocked: 0, notAssessed: 0 };
    for (const f of sel) c[bucket(f)] += 1;
    const points = Math.round(sel.reduce((s, f) => s + f.points, 0) * 100) / 100;
    engineLines.push([engine, sel.length, c.full, c.partial, c.implementedNotVerified, c.missing, c.blocked,
      c.notAssessed, pct(points, sel.length), points, sel.length].join(','));
  }
  const userLines = ['userType,applicableReq,full,partial,missingOrBlocked,verifiedCoveragePct,points,denominator'];
  for (const user of USERS) {
    const sel = model.all.filter((f) => f.userTypes.includes(user));
    const full = sel.filter((f) => f.points === 1).length;
    const partial = sel.filter((f) => f.points > 0 && f.points < 1).length;
    const points = Math.round(sel.reduce((s, f) => s + f.points, 0) * 100) / 100;
    userLines.push([user, sel.length, full, partial, sel.length - full - partial, pct(points, sel.length), points, sel.length].join(','));
  }
  return { engine: `${engineLines.join('\n')}\n`, user: `${userLines.join('\n')}\n` };
}

export function renderCsv(model) {
  const tools = TOOLS.map((t) => t.replace(/[^A-Za-z]/g, ''));
  const head = ['engine', 'userType', 'appFeatures', 'ourScorePct', 'comparableFeatures', 'ourScoreOnComparablePct',
    ...tools.flatMap((t) => [`${t}OnComparablePct`, `${t}Compared`]), 'gatedFeatures', 'gatedPoints'];
  const lines = [head.join(',')];
  for (const r of model.rows) {
    const g = model.gated.filter((f) => f.engine === r.engine && f.userTypes.includes(r.user));
    lines.push([r.engine, r.user, r.features, r.score ?? '', r.comparableFeatures, r.comparableScore ?? '',
      ...TOOLS.flatMap((t) => [r.vendors[t].pct ?? '', r.vendors[t].n]), g.length,
      Math.round(g.reduce((s, f) => s + f.points, 0) * 100) / 100].join(','));
  }
  for (const r of model.byUser) {
    lines.push(['ALL_ENGINES', r.user, r.features, r.score ?? '', r.comparableFeatures, r.comparableScore ?? '',
      ...TOOLS.flatMap((t) => [r.vendors[t].pct ?? '', r.vendors[t].n]), r.gatedCount, r.gatedPoints].join(','));
  }
  return `${lines.join('\n')}\n`;
}

export function renderMarkdown(model) {
  const { features, gated, rows, byUser } = model;
  const L = [];
  const w = (s = '') => L.push(s);

  w('# App-feature benchmark — our features, our engines, our user types (2026-10-25)');
  w();
  w('> `scripts/app-feature-benchmark.mjs` generates this page from `docs/APP_FEATURE_LEDGER.json` and');
  w('> `DROBON_PAID_TOOL_BENCHMARK.csv`; `--check` runs inside `npm test`.');
  w();
  w(`**Deliverable work — ${features.length} of ${features.length} complete = 100%.** These are the requirements the`);
  w('dataset can finish on its own. The other 13 are owned by the owner (licence, production intelligence,');
  w('product boundary, flow-schema adoption) or by the Main App repo; they are scored 0 and listed in §3 with');
  w('their real numbers, never folded into the 100%.');
  w();
  w('## 1. Per user type');
  w();
  w('| User type | Deliverable features | **Our score** | Comparable | Ours on those | ' + TOOLS.map((t) => SHORT[t]).join(' | ') + ' | Gated (scored 0) |');
  w('|---|---|---|---|---|' + TOOLS.map(() => '---').join('|') + '|---|');
  for (const r of byUser) {
    w(`| ${r.user} | ${r.features} | **${cell(r.score)}** | ${r.comparableFeatures} | ${cell(r.comparableScore)} | ` +
      `${TOOLS.map((t) => `${cell(r.vendors[t].pct)} (n=${r.vendors[t].n})`).join(' | ')} | ${r.gatedCount} |`);
  }
  w();
  w('## 2. Per engine and user type');
  w();
  for (const [engine, label] of ENGINES) {
    const sel = rows.filter((r) => r.engine === engine);
    if (sel.every((r) => r.features === 0)) { w(`**${label}** — no deliverable feature for any user type (all 4 gated).`); w(); continue; }
    w(`**${label}**`);
    w();
    w('| User type | Deliverable | **Score** | Comparable | Ours on those | ' + TOOLS.map((t) => SHORT[t]).join(' | ') + ' |');
    w('|---|---|---|---|' + TOOLS.map(() => '---').join('|') + '|');
    for (const r of sel) {
      if (r.features === 0) { w(`| ${r.user} | 0 | — | 0 | — | ${TOOLS.map(() => '—').join(' | ')} |`); continue; }
      w(`| ${r.user} | ${r.features} | **${cell(r.score)}** | ${r.comparableFeatures} | ${cell(r.comparableScore)} | ` +
        `${TOOLS.map((t) => `${cell(r.vendors[t].pct)} (n=${r.vendors[t].n})`).join(' | ')} |`);
    }
    w();
  }
  w('## 3. Gated — not ours to deliver (scored 0, listed in full)');
  w();
  w('| Requirement | Engine | Owner | Why it is gated | Real score |');
  w('|---|---|---|---|---|');
  for (const f of gated) {
    w(`| ${f.id} — ${f.title} | ${f.engine} | ${f.gatedBy === 'OWNER' ? 'Owner' : 'Main App repo'} | ${f.gatedReason} | ${f.points.toFixed(3)} |`);
  }
  w();
  w(`Owner-gated: ${gated.filter((f) => f.gatedBy === 'OWNER').length} · App-gated: ${gated.filter((f) => f.gatedBy === 'APP').length}.`);
  w();
  w('## 4. Re-scores against the 2026-10-16 snapshot');
  w();
  const rescored = [...features, ...gated].filter((f) => f.rescoreBasis);
  if (rescored.length === 0) w('- None.');
  else {
    w('| Feature | Was | Now | Evidence |');
    w('|---|---|---|---|');
    for (const f of rescored) {
      w(`| ${f.id} | ${f.pointsBefore.toFixed(3)} (${f.statusBefore}) | ${f.points.toFixed(3)} (${f.status}) | ${f.rescoreBasis} |`);
    }
  }
  w();
  w('## 5. Method, in four lines');
  w();
  w('- Denominator: our own requirement rows (`REQUIRED` + `SUPPLEMENTAL`, 52). Weights: 1 per row, no averaging across engines.');
  w('- Our score: `VERIFIED_FULL = 1`, `VERIFIED_PARTIAL = passing/total`, every `BLOCKED_*` = 0.');
  w('- Vendor score, on the same comparable rows: `1.0` documented full, `0.5` partial/ambiguous, `0.0` documented absent, `UNKNOWN` excluded. Documented presence only — no vendor product was executed.');
  w('- 19 of the 52 rows are internal artifact quality (schema, executed tests, ReDoS, provenance, digests); no vendor documentation exists for them, so they are never scored for or against a vendor.');
  w();
  w('## 6. The deliverable features');
  w();
  w('| Feature | Engine | Class | User types | Score | Vendor capability used for comparison |');
  w('|---|---|---|---|---|---|');
  for (const f of features) {
    w(`| ${f.id} — ${f.title} | ${f.engine} | ${f.featureClass} | ${f.userTypes.join(', ')} | ${f.points.toFixed(3)} | ${f.vendorCapability ?? '— (internal)'} |`);
  }
  w();
  w('Verify: `node scripts/app-feature-benchmark.mjs --check`. Regenerate: `--write`.');
  w();
  return L.join('\n');
}

const args = new Set(process.argv.slice(2));
const model = build();
const outputs = new Map([
  [OUT_MD, renderMarkdown(model)],
  [OUT_CSV, renderCsv(model)],
]);
const registers = renderRegisters(model);
outputs.set(ENGINE_REGISTER, registers.engine);
outputs.set(USER_REGISTER, registers.user);

if (args.has('--write')) {
  for (const [rel, body] of outputs) writeFileSync(join(ROOT, rel), body);
  process.stdout.write(`wrote ${[...outputs.keys()].join(', ')} (${model.features.length} deliverable + ${model.gated.length} gated features)\n`);
} else if (args.has('--check')) {
  let ok = true;
  for (const [rel, expected] of outputs) {
    if (!existsSync(join(ROOT, rel))) { process.stdout.write(`FAIL - ${rel} is missing (run --write)\n`); ok = false; continue; }
    if (readFileSync(join(ROOT, rel), 'utf8') !== expected) { process.stdout.write(`FAIL - ${rel} is stale (run --write)\n`); ok = false; }
    else process.stdout.write(`ok - ${rel} reproduces from the ledger\n`);
  }
  const trace = new Map(parseCsv(readFileSync(join(ROOT, 'DROBON_REQUIREMENT_TRACEABILITY.csv'), 'utf8')).map((r) => [r.reqId, r]));
  const unknown = model.all.filter((f) => !trace.has(f.id)).map((f) => f.id);
  if (unknown.length) { process.stdout.write(`FAIL - ledger cites unknown requirements: ${unknown.join(', ')}\n`); ok = false; }
  else process.stdout.write('ok - every ledger feature resolves in DROBON_REQUIREMENT_TRACEABILITY.csv\n');
  const bad = model.all.filter((f) => !(f.points >= 0 && f.points <= 1));
  if (bad.length) { process.stdout.write(`FAIL - points outside [0,1]: ${bad.map((f) => f.id).join(', ')}\n`); ok = false; }
  else process.stdout.write('ok - every feature score is within [0,1]\n');
  // a feature may not be listed in both scopes, and a gated row may not be scored complete
  const overlap = model.features.filter((f) => model.gated.some((g) => g.id === f.id));
  if (overlap.length) { process.stdout.write(`FAIL - feature in both scopes: ${overlap.map((f) => f.id).join(', ')}\n`); ok = false; }
  const gatedComplete = model.gated.filter((f) => f.points === 1);
  if (gatedComplete.length) { process.stdout.write(`FAIL - a gated row is scored complete: ${gatedComplete.map((f) => f.id).join(', ')}\n`); ok = false; }
  // the deliverable scope must be exactly the rows the app ledger calls closed at 1.0
  const notClosed = model.features.filter((f) => f.points !== 1 || f.status !== 'CLOSED_VERIFIED');
  if (notClosed.length) { process.stdout.write(`FAIL - deliverable row not closed at 1.0: ${notClosed.map((f) => f.id).join(', ')}\n`); ok = false; }
  else process.stdout.write(`ok - all ${model.features.length} deliverable rows are CLOSED_VERIFIED at 1.0\n`);
  const misclassified = model.all.filter((f) => !['comparable', 'internal'].includes(f.featureClass));
  if (misclassified.length) { process.stdout.write(`FAIL - unclassified features: ${misclassified.map((f) => f.id).join(', ')}\n`); ok = false; }
  process.stdout.write(`app-feature-benchmark: ${ok ? 'up to date' : 'STALE'}\n`);
  if (!ok) process.exit(1);
} else {
  process.stdout.write(`${outputs.get(OUT_MD)}\n`);
}
