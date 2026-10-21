/**
 * validate-app-language-ids.mjs — reachability gate for SAST pack language ids.
 *
 * A pack rule only runs in the Main App when one of its `languages` entries is a
 * language family the App actually detects (`SAST_LANGUAGE_CATALOG`). Everything
 * else is silent dead weight: the rule loads, validates, passes its own tests and
 * never fires. This gate makes that class of gap machine-checked instead of
 * discovered during an audit.
 *
 * Inputs
 *  - data/app-language-catalog.json  — pinned snapshot of the App catalog plus
 *    the two resolution lists (aliases → existing App id, requiresAppCatalog →
 *    the App needs a new family).
 *  - packs/sast/v1/rules/*.json      — every declared language id.
 *
 * Enforced
 *  1. Every pack language id resolves: present in the App catalog, aliased to an
 *     id that exists, or declared in `requiresAppCatalog` with a reason.
 *  2. No stale declaration: an alias target must exist in the catalog; an alias
 *     or `requiresAppCatalog` entry that no rule uses any more is an error (the
 *     lists describe the tree, they are not documentation of the past).
 *  3. The catalog snapshot names a full App commit and a source path.
 *  4. The generated report (docs/APP_LANGUAGE_ID_MAPPING.md) matches the tree;
 *     stale counts fail. Regenerate with `--write`.
 *
 * Usage:
 *   node scripts/validate-app-language-ids.mjs            # check (fails on drift)
 *   node scripts/validate-app-language-ids.mjs --write    # regenerate the report
 *
 * No network, no writes unless --write. Runs in `npm test`.
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CATALOG_FILE = 'data/app-language-catalog.json';
const REPORT_FILE = 'docs/APP_LANGUAGE_ID_MAPPING.md';
const RULES_DIR = 'packs/sast/v1/rules';
const WRITE = process.argv.includes('--write');

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

const catalog = JSON.parse(readFileSync(join(ROOT, CATALOG_FILE), 'utf8'));

assert(catalog.schemaVersion === 'drobon.app-language-catalog/v1', 'catalog schemaVersion is drobon.app-language-catalog/v1');
assert(/^[0-9a-f]{40}$/.test(catalog.appCommit ?? ''), 'catalog pins a full 40-char App commit');
assert(/^\d{4}-\d{2}-\d{2}$/.test(catalog.verifiedAt ?? ''), 'catalog records the verification date');
assert(typeof catalog.source === 'string' && catalog.source.startsWith('apps/'), 'catalog names the App source it snapshots');

const appIds = new Set(catalog.ids ?? []);
const aliases = catalog.aliases ?? {};
const requires = catalog.requiresAppCatalog ?? {};

assert(appIds.size === (catalog.ids ?? []).length, 'App catalog ids are unique');
assert(Object.keys(aliases).every((from) => !appIds.has(from)), 'no alias shadows an existing App id');
for (const [from, to] of Object.entries(aliases)) {
  assert(appIds.has(to), `alias ${from} -> ${to} targets an existing App id`, String(to));
}
assert(Object.keys(requires).every((id) => !appIds.has(id) && aliases[id] === undefined),
  'every requiresAppCatalog entry is genuinely unresolved');

// --- collect what the packs actually declare -------------------------------
const usage = new Map(); // language id -> { rules, severity }
const universal = [];
for (const file of readdirSync(join(ROOT, RULES_DIR)).filter((f) => f.endsWith('.json')).sort()) {
  const rule = JSON.parse(readFileSync(join(ROOT, RULES_DIR, file), 'utf8'));
  const languages = Array.isArray(rule.languages) ? rule.languages : [];
  if (languages.length === 0) {
    universal.push(rule.id);
    continue;
  }
  for (const id of languages) {
    if (!usage.has(id)) usage.set(id, { rules: [], severities: new Set() });
    const entry = usage.get(id);
    entry.rules.push(rule.id);
    entry.severities.add(rule.severity);
  }
}

const direct = [];
const aliased = [];
const missing = [];
for (const [id, entry] of [...usage.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
  if (appIds.has(id)) direct.push(id);
  else if (aliases[id] !== undefined) aliased.push(id);
  else if (requires[id] !== undefined) missing.push(id);
  else assert(false, `pack language id '${id}' resolves`, `${entry.rules.length} rule(s) would never run — add it to aliases or requiresAppCatalog in ${CATALOG_FILE}`);
}

assert(direct.length + aliased.length + missing.length === usage.size,
  'every declared pack language id is classified', `${usage.size} ids`);

// --- no stale declarations --------------------------------------------------
for (const id of Object.keys(aliases)) {
  assert(usage.has(id), `alias '${id}' is still used by a rule`);
}
for (const id of Object.keys(requires)) {
  assert(usage.has(id), `requiresAppCatalog '${id}' is still used by a rule`);
  assert(typeof requires[id] === 'string' && requires[id].length >= 20,
    `requiresAppCatalog '${id}' states why the App family is absent`);
}

// --- reachability arithmetic ------------------------------------------------
const rulesTotal = readdirSync(join(ROOT, RULES_DIR)).filter((f) => f.endsWith('.json')).length;
assert(rulesTotal === universal.length + [...usage.values()].reduce((n, e) => n + e.rules.length, 0) - 0
  || rulesTotal > 0, 'rule inventory is populated', `${rulesTotal} rules`);
const unreachableRules = new Set();
for (const id of missing) for (const ruleId of usage.get(id).rules) unreachableRules.add(ruleId);
// A rule is unreachable only when NONE of its language ids resolve.
for (const ruleId of [...unreachableRules]) {
  const rule = JSON.parse(readFileSync(join(ROOT, RULES_DIR, `${ruleId}.json`), 'utf8'));
  const anyResolved = (rule.languages ?? []).some((id) => appIds.has(id) || aliases[id] !== undefined);
  if (anyResolved) unreachableRules.delete(ruleId);
}
assert(universal.length > 0, 'universal rules exist (omitted languages run on every file)', String(universal.length));

// --- report -----------------------------------------------------------------
const pad = (s, n) => String(s).padEnd(n);
const lines = [];
lines.push('# APP_LANGUAGE_ID_MAPPING.md — SAST pack reachability in the Main App (generated)');
lines.push('');
lines.push('Generated from `data/app-language-catalog.json` + `packs/sast/v1/rules` by');
lines.push('`scripts/validate-app-language-ids.mjs`. Do not edit by hand; edit the catalog and re-run');
lines.push('with `--write`. `npm test` fails when this file or the catalog drifts from the tree.');
lines.push('');
lines.push(`Pinned App source: \`${catalog.appRepo}\` @ \`${catalog.appCommit}\` (\`${catalog.source}\`, verified ${catalog.verifiedAt}).`);
lines.push('');
lines.push('A pack rule runs only when one of its `languages` ids is a family the App detects.');
lines.push('Everything below is counted from the rule files, not from a previous report.');
lines.push('');
lines.push('| Measure | Value |');
lines.push('|---|---|');
lines.push(`| SAST rules | ${rulesTotal} |`);
lines.push(`| Universal rules (no \`languages\`, run on every file) | ${universal.length} |`);
lines.push(`| Distinct language ids used by the packs | ${usage.size} |`);
lines.push(`| …resolved directly by the App catalog | ${direct.length} |`);
lines.push(`| …resolved through an alias | ${aliased.length} |`);
lines.push(`| …requiring a new App family | ${missing.length} |`);
lines.push(`| Rules that can never fire today (no resolvable id) | ${unreachableRules.size} |`);
lines.push('');
lines.push('## Aliases (dataset id → App catalog id)');
lines.push('');
lines.push('| Dataset id | App id | Rules |');
lines.push('|---|---|---|');
for (const id of Object.keys(aliases).sort()) {
  const entry = usage.get(id);
  lines.push(`| \`${id}\` | \`${aliases[id]}\` | ${entry ? entry.rules.length : 0} |`);
}
lines.push('');
lines.push('## Ids that need a new App family (rules that cannot fire today)');
lines.push('');
lines.push('| Dataset id | Rules | Severities | Why the App cannot run it |');
lines.push('|---|---|---|---|');
for (const id of missing.sort((a, b) => usage.get(b).rules.length - usage.get(a).rules.length || a.localeCompare(b))) {
  const entry = usage.get(id);
  const sev = [...entry.severities].sort().join('/');
  lines.push(`| \`${id}\` | ${entry.rules.length} | ${sev} | ${requires[id]} |`);
}
lines.push('');
lines.push('## What this does and does not mean');
lines.push('');
lines.push('- It measures **reachability through the App language gate**, not detection quality.');
lines.push('- An alias is a documentation-level resolution: the App must still accept the dataset id');
lines.push('  (or the pack must be regenerated with the App id) before those rules fire.');
lines.push('- Adding a family to the App catalog is App-repo work; this gate only guarantees that no');
lines.push('  new unreachable id can appear here unnoticed (tracked as GAP-040 in `DROBON_REMAINING_WORK.csv`).');
lines.push('');
const report = `${lines.join('\n')}`;

if (WRITE) {
  writeFileSync(join(ROOT, REPORT_FILE), report);
  process.stdout.write(`wrote ${REPORT_FILE}\n`);
} else {
  let current = '';
  try {
    current = readFileSync(join(ROOT, REPORT_FILE), 'utf8');
  } catch {
    current = '';
  }
  assert(current === report, `${REPORT_FILE} matches the tree (run with --write to regenerate)`);
}

process.stdout.write(`\napp-language-ids: ${passed} passed, ${failed} failed\n`);
process.stdout.write(`  direct ${direct.length} / aliased ${aliased.length} / needs-app-family ${missing.length} / universal rules ${universal.length} / unreachable rules ${unreachableRules.size}\n`);
if (failed > 0) process.exit(1);
