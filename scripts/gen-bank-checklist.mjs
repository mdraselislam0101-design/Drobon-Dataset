#!/usr/bin/env node
/**
 * gen-bank-checklist.mjs — renders the bank audit checklist from the packs.
 *
 * Output (committed, deterministic, no timestamps):
 *   docs/BANK_RULE_CHECKLIST.md    — the 437 App-reachable rules grouped by tier,
 *                                    plus an appendix naming the 73 header-blocked ones
 *                                    and the header that would unlock each.
 *   docs/BANK_RULE_CHECKLIST.csv   — one row per rule, for spreadsheet triage.
 *
 * The checklist is derived, never hand-edited: `--check` fails when the committed
 * files no longer match the tree. Only reachability comes from
 * interop/app-dast-reachability.json; everything else is read from the rule files.
 */
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MD_OUT = 'docs/BANK_RULE_CHECKLIST.md';
const CSV_OUT = 'docs/BANK_RULE_CHECKLIST.csv';
const CHECK = process.argv.includes('--check');

const TIERS = [
  {
    id: 1,
    name: 'Tier 1 — customer money and identity',
    why: 'These are the observations a fraud team would act on first: financial identifiers, card credentials, one-time codes, session tokens and transport protection. A finding here is worth an incident ticket, not a backlog item.',
    categories: ['privacy-exposure', 'credential-exposure', 'cookie-flags', 'cookie-hygiene', 'cors', 'transport-security', 'mixed-content', 'cache-control'],
  },
  {
    id: 2,
    name: 'Tier 2 — browser trust and interface contracts',
    why: 'Header, CSP and markup weaknesses do not move money by themselves, but they are the difference between a stolen session and a blocked one, and between a clickjackable login and a safe one.',
    categories: ['security-headers', 'csp-weakness', 'response-headers', 'weak-markup', 'content-injection', 'open-redirect', 'http-methods'],
  },
  {
    id: 3,
    name: 'Tier 3 — disclosure, fingerprints and debug surfaces',
    why: 'Artefacts, consoles and stack traces rarely cause a loss on their own; they shorten the attacker’s reconnaissance and are the cheapest findings to close.',
    categories: ['information-disclosure', 'debug-exposure', 'data-exposure', 'exposed-interface'],
  },
];

const tierOf = new Map();
for (const tier of TIERS) for (const category of tier.categories) tierOf.set(category, tier.id);
const CATEGORY_COVERED = new Set(TIERS.flatMap((t) => t.categories));

function ruleFiles() {
  const dir = join(ROOT, 'packs', 'dast', 'v1', 'rules');
  return readdirSync(dir).filter((f) => /^DPK-DAST-.*\.json$/.test(f)).sort().map((f) => JSON.parse(readFileSync(join(dir, f), 'utf8')));
}

function observes(rule) {
  const t = rule.check?.type;
  const header = rule.check?.header;
  if (t === 'http-url') return 'the URL scheme of the target';
  if (t === 'missing-response-header') return `that the ${header} header is absent or empty`;
  if (t === 'response-header-missing-directive') return `the ${header} value for the ${rule.check?.directive} directive`;
  if (t === 'response-header-matches') return `the ${header} value against a pattern`;
  if (t === 'response-header-host-differs') return `the ${header} header host against the target host`;
  if (t === 'cookie-missing-flag') return `the Set-Cookie flags for ${rule.check?.flag}`;
  if (t === 'response-body-matches') return 'the response body (first 32,768 bytes)';
  return `the ${t} signal`;
}

/** First sentence of the action, capped — the CSV keeps the full remediation text. */
function shortAction(text) {
  const firstSentence = String(text).split(/(?<=[.;])\s/)[0];
  return firstSentence.length > 190 ? `${firstSentence.slice(0, 187).trimEnd()}…` : firstSentence;
}

function csvCell(value) {
  const text = String(value ?? '');
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function build() {
  const reach = JSON.parse(readFileSync(join(ROOT, 'interop', 'app-dast-reachability.json'), 'utf8'));
  const blocked = new Map(reach.unreachable.map((u) => [u.id, u]));
  const rules = ruleFiles().sort((a, b) => a.id.localeCompare(b.id));

  for (const rule of rules) {
    if (!CATEGORY_COVERED.has(rule.category)) {
      throw new Error(`${rule.id}: category "${rule.category}" has no bank tier — add it to TIERS instead of letting it disappear`);
    }
  }

  const rows = rules.map((rule) => {
    const block = blocked.get(rule.id);
    return {
      id: rule.id,
      tier: tierOf.get(rule.category),
      title: rule.title,
      category: rule.category,
      severity: rule.severity,
      cwe: rule.cwe,
      checkType: rule.check?.type ?? '',
      reachable: block === undefined ? 'yes' : 'no',
      unlock: block === undefined ? '' : block.header,
      observes: observes(rule),
      action: rule.remediation,
      actionShort: shortAction(rule.remediation),
    };
  });

  const reachableCount = rows.filter((r) => r.reachable === 'yes').length;

  // --- CSV -----------------------------------------------------------------
  const header = ['ruleId', 'tier', 'title', 'category', 'severity', 'cwe', 'checkType', 'appReachable', 'unlockingHeader', 'observes', 'action'];
  const csv = [header.join(',')]
    .concat(rows.map((r) => [r.id, r.tier, r.title, r.category, r.severity, r.cwe, r.checkType, r.reachable, r.unlock, r.observes, r.action].map(csvCell).join(',')))
    .join('\n') + '\n';

  // --- markdown ------------------------------------------------------------
  const md = [];
  md.push('# Bank rule checklist — 2026-10-21');
  md.push('');
  md.push('> **Generated, not hand-written.** `node scripts/gen-bank-checklist.mjs --write` renders this page and');
  md.push('> `docs/BANK_RULE_CHECKLIST.csv` from `packs/dast/v1/rules`; `--check` fails when either drifts.');
  md.push('> Reachability is read from `interop/app-dast-reachability.json` (App at `9360dd1`, 11 forwarded headers).');
  md.push('');
  md.push(`**${rows.length} rules · ${reachableCount} evaluable inside the Main App · ${rows.length - reachableCount} blocked by the response-header surface.**`);
  md.push('');
  md.push('This is an **audit checklist**, not a claim of protection: every row states what the rule observes in one');
  md.push('synthetic-tested response and what to change. See `docs/BANK_THREAT_COVERAGE_2026-10-21.md` for what no');
  md.push('passive rule can see (anything behind login, business logic, authorization, TLS, runtime defence).');
  md.push('');
  md.push('Column 5 is the first step of the rule\'s remediation; the full text, the declared limitation and the check');
  md.push('type are in `docs/BANK_RULE_CHECKLIST.csv`.');
  md.push('');
  md.push('How to use it: work Tier 1 first; for each row capture the observed URL, status and the evidence string the');
  md.push('finding carries, then close the action. A row is not "passed" because a scan found nothing — only because');
  md.push('someone verified the observation on the target.');
  md.push('');
  md.push('| Tier | Focus | Rules | App-reachable |');
  md.push('|---|---|---|---|');
  for (const tier of TIERS) {
    const inTier = rows.filter((r) => r.tier === tier.id);
    md.push(`| ${tier.id} | ${tier.name.replace(/^Tier \d — /, '')} | ${inTier.length} | ${inTier.filter((r) => r.reachable === 'yes').length} |`);
  }
  md.push('');
  for (const tier of TIERS) {
    const inTier = rows.filter((r) => r.tier === tier.id);
    md.push(`## ${tier.name}`);
    md.push('');
    md.push(`*${tier.why}*`);
    md.push('');
    md.push(`**${inTier.length} rules, ${inTier.filter((r) => r.reachable === 'yes').length} evaluable today.**`);
    md.push('');
    md.push('| Rule | Severity | CWE | What it observes | What to do (first step) | Reachable |');
    md.push('|---|---|---|---|---|---|');
    for (const r of inTier) {
      const mark = r.reachable === 'yes' ? 'yes' : `**no** — needs \`${r.unlock}\``;
      md.push(`| \`${r.id}\` ${r.title} | ${r.severity} | ${r.cwe} | ${r.observes} | ${r.actionShort} | ${mark} |`);
    }
    md.push('');
  }
  const blockedRows = rows.filter((r) => r.reachable === 'no');
  md.push('## Appendix — the 73 rules the App cannot evaluate today');
  md.push('');
  md.push('Each row names the response header that would unlock it (`GAP-048`). Until the App forwards that header,');
  md.push('these rules load but can never fire; they are listed so nobody mistakes "loaded" for "working".');
  md.push('');
  const byHeader = new Map();
  for (const r of blockedRows) {
    const list = byHeader.get(r.unlock) ?? [];
    list.push(r);
    byHeader.set(r.unlock, list);
  }
  md.push('| Header that unlocks it | Rules | Ids |');
  md.push('|---|---|---|');
  for (const [head, list] of [...byHeader.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    md.push(`| \`${head}\` | ${list.length} | ${list.map((r) => `\`${r.id}\``).join(', ')} |`);
  }
  md.push('');
  md.push(`Total: **${blockedRows.length} rules across ${byHeader.size} headers.**`);
  md.push('');
  md.push('---');
  md.push('');
  md.push('Regenerate: `node scripts/gen-bank-checklist.mjs --write`. Verify: `node scripts/gen-bank-checklist.mjs --check`.');
  md.push('');

  return { md: md.join('\n'), csv, rules: rows.length, reachableCount };
}

const built = build();

if (CHECK) {
  const problems = [];
  for (const [file, expected] of [[MD_OUT, built.md], [CSV_OUT, built.csv]]) {
    const path = join(ROOT, file);
    if (!existsSync(path)) problems.push(`${file}: missing`);
    else if (readFileSync(path, 'utf8') !== expected) problems.push(`${file}: stale`);
  }
  if (problems.length > 0) {
    for (const p of problems) process.stderr.write(`bank-checklist: ${p}\n`);
    process.stderr.write('bank-checklist: FAIL — run node scripts/gen-bank-checklist.mjs --write\n');
    process.exit(1);
  }
  process.stdout.write(`bank-checklist: OK — ${built.rules} rules (${built.reachableCount} reachable) reproduce\n`);
} else if (process.argv.includes('--write')) {
  writeFileSync(join(ROOT, MD_OUT), built.md);
  writeFileSync(join(ROOT, CSV_OUT), built.csv);
  process.stdout.write(`wrote ${MD_OUT} and ${CSV_OUT}\n`);
  process.stdout.write(`  ${built.rules} rules · ${built.reachableCount} App-reachable · ${built.rules - built.reachableCount} blocked\n`);
} else {
  process.stdout.write(`bank-checklist: ${built.rules} rules (${built.reachableCount} reachable); pass --write or --check\n`);
}
