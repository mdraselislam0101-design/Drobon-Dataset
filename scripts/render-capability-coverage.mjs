/**
 * render-capability-coverage.mjs — deterministic renderer for the human view
 * of docs/CAPABILITY_COVERAGE_MATRIX.json.
 *
 *   node scripts/render-capability-coverage.mjs --check   # fail if stale
 *   node scripts/render-capability-coverage.mjs --write   # regenerate
 *
 * The Markdown is a pure function of the JSON: no timestamps, no network.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = 'docs/CAPABILITY_COVERAGE_MATRIX.json';
const OUT = 'docs/CAPABILITY_COVERAGE_MATRIX.md';

const m = JSON.parse(readFileSync(join(ROOT, SRC), 'utf8'));

const esc = (s) => String(s).replace(/\|/g, '\\|');
const lines = [];
lines.push('# CAPABILITY_COVERAGE_MATRIX.md — Main App capability ↔ Dataset coverage (generated)');
lines.push('');
lines.push('Generated from `docs/CAPABILITY_COVERAGE_MATRIX.json` by `scripts/render-capability-coverage.mjs`.');
lines.push('Do not edit by hand; edit the JSON and re-render.');
lines.push('');
lines.push(`As of **${m.asOf}**. Main App reference: \`${m.app.repo}\` @ \`${m.app.commit}\` (read-only; ${m.app.verificationMethod}).`);
lines.push('');
lines.push('> ' + m.note);
lines.push('');
lines.push(`Rows: **${m.counts.capabilities}** · Dataset-relevant: **${m.counts.datasetRelevant}** · ` +
  `COVERED_VERIFIED **${m.counts.coveredVerified}** · APP_INTEGRATION_BLOCKED **${m.counts.appIntegrationBlocked}** · ` +
  `RIGHTS_BLOCKED **${m.counts.rightsBlocked}** · NOT_APPLICABLE **${m.counts.notApplicable}**`);
lines.push('');
lines.push('Status vocabulary (closed): `' + m.statusVocabulary.join('`, `') + '`.');
lines.push('');

lines.push('## 1. Capability inventory and coverage');
lines.push('');
lines.push('| ID | Capability | Dataset requirement | Coverage status | Integration | Remaining work |');
lines.push('|---|---|---|---|---|---|');
for (const c of m.capabilities) {
  lines.push(`| \`${c.id}\` | ${esc(c.name)} | ${c.datasetRequirement} | **${c.coverageStatus}** | ${c.appIntegration} | ${esc(c.remainingWork)} |`);
}
lines.push('');

lines.push('## 2. Dataset-relevant rows — assets, relationships, evidence, rights');
lines.push('');
for (const c of m.capabilities.filter((x) => x.datasetRequirement !== 'NONE')) {
  lines.push(`### ${c.id} — ${c.name}`);
  lines.push('');
  lines.push(`- Status: **${c.coverageStatus}** (basis: \`${c.verificationBasis}\`); requirement: ${c.datasetRequirement}; integration: ${c.appIntegration}.`);
  lines.push(`- Contract: ${c.dataContract}`);
  if (c.assetRefs.length) {
    lines.push('- Assets: ' + c.assetRefs.map((r) => `\`${r.path}\` — ${r.count} (${r.countingRule})`).join('; ') + '.');
  }
  if (c.relationships.length) lines.push('- Relationships: ' + c.relationships.join('; ') + '.');
  if (c.evaluationEvidence.length) lines.push('- Evaluation: ' + c.evaluationEvidence.join('; ') + '.');
  lines.push(`- Production eligibility: \`${c.productionEligibility}\`; rights: \`${c.rightsStatus}\`; owner decision: ${c.ownerDecision}.`);
  if (c.verification.length) lines.push('- Verification: ' + c.verification.map((v) => `\`${v}\``).join(', ') + '.');
  if (c.notApplicableReason) lines.push(`- N/A reason: ${c.notApplicableReason}`);
  lines.push('');
}

lines.push('## 3. UserType × capability view');
lines.push('');
lines.push('The four UserTypes are presentation/workflow layers over one shared engine set and one Dataset. No profile has, or may add, a duplicate rule pack.');
lines.push('');
lines.push('| UserType | Workflow evidence | Mapped capabilities | Profile-specific Dataset assets |');
lines.push('|---|---|---|---|');
for (const u of m.userTypeMatrix) {
  lines.push(`| ${u.userType} | ${esc(u.appWorkflow)} | ${u.capabilities.length} (${u.capabilities.map((x) => `\`${x}\``).join(', ')}) | ${u.userTypeSpecificDatasetAssets.length} |`);
}
lines.push('');
for (const u of m.userTypeMatrix) {
  lines.push(`- **${u.userType}**: ${u.notes}`);
}
lines.push('');

lines.push('## 4. Closed App-inventory mapping');
lines.push('');
lines.push('Every row of the Main App capability inventory maps to at least one capability; the mapping is closed in both directions (validator-enforced).');
lines.push('');
lines.push('| Inventory ref | App evidence | Capability rows |');
lines.push('|---|---|---|');
for (const e of m.appInventoryCoverage) {
  lines.push(`| ${e.id} | ${esc(e.sourceRef)} | ${e.rowIds.map((x) => `\`${x}\``).join(', ')} |`);
}
lines.push('');

lines.push('## 5. Decision rules');
lines.push('');
for (const r of m.decisionRules ?? []) lines.push(`- ${r}`);
lines.push('');
lines.push('## 6. Notes');
lines.push('');
for (const n of m.notes ?? []) lines.push(`- ${n}`);
lines.push('');

const out = lines.join('\n');
const abs = join(ROOT, OUT);
if (process.argv.includes('--write')) {
  writeFileSync(abs, out);
  process.stdout.write(`wrote ${OUT} (${m.counts.capabilities} rows)\n`);
} else {
  const current = readFileSync(abs, 'utf8');
  if (current !== out) {
    process.stdout.write(`STALE: ${OUT} does not match ${SRC}; run node scripts/render-capability-coverage.mjs --write\n`);
    process.exit(1);
  }
  process.stdout.write(`ok - ${OUT} is up to date\n`);
}
