/**
 * originality-report.mjs — Dataset-side originality and duplication audit.
 *
 * Scope: the authored intelligence tree (pack rules, patterns, records,
 * remediation). Read-only; no network; deterministic output.
 *
 * Checks:
 *  1. duplicate canonical ids within each asset class;
 *  2. exact-duplicate normalised content (same JSON with identity fields
 *     removed) — a hard defect, never a style opinion;
 *  3. near-duplicate wording: token-shingle Jaccard over selected text fields,
 *     reported in bands. These are REVIEW FLAGS for a human; they are not
 *     proof of copying and never fail the gate;
 *  4. repeated remediation text (exact whyItMatters duplicates);
 *  5. provenance/origin presence: no invented third-party attribution, and
 *     every generated asset declares `origin`;
 *  6. broken cross-references between rule/pattern/record/remediation.
 *
 * Usage:
 *   node scripts/originality-report.mjs            # human summary
 *   node scripts/originality-report.mjs --json     # machine summary
 *   node scripts/originality-report.mjs --check    # exit 1 on hard defects
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => JSON.parse(readFileSync(join(ROOT, rel), 'utf8'));
const list = (rel) => (existsSync(join(ROOT, rel)) ? readdirSync(join(ROOT, rel)).filter((f) => f.endsWith('.json')).sort() : []);

const rules = ['sast', 'secrets', 'dast'].flatMap((fam) =>
  list(`packs/${fam}/v1/rules`).map((f) => ({ fam, path: `packs/${fam}/v1/rules/${f}`, doc: read(`packs/${fam}/v1/rules/${f}`) })));
const patterns = list('knowledge/patterns').map((f) => ({ path: `knowledge/patterns/${f}`, doc: read(`knowledge/patterns/${f}`) }));
const records = list('knowledge/records').map((f) => ({ path: `knowledge/records/${f}`, doc: read(`knowledge/records/${f}`) }));
const remediation = list('knowledge/remediation').map((f) => ({ path: `knowledge/remediation/${f}`, doc: read(`knowledge/remediation/${f}`) }));

const hard = [];
const flags = [];

// 1. duplicate ids
function dupIds(label, items, key) {
  const seen = new Map();
  for (const it of items) {
    const id = it.doc[key];
    if (seen.has(id)) hard.push({ check: 'duplicate-id', class: label, id, paths: [seen.get(id), it.path] });
    else seen.set(id, it.path);
  }
  return seen;
}
const ruleIds = dupIds('rule', rules, 'id');
const patIds = dupIds('pattern', patterns, 'id');
const recIds = dupIds('record', records, 'id');
dupIds('remediation', remediation, 'ruleId');

// 2. exact duplicate normalised content
const strip = (obj, drop) => {
  const clone = JSON.parse(JSON.stringify(obj));
  for (const k of drop) delete clone[k];
  return clone;
};
function exactDup(label, items, dropKeys) {
  const seen = new Map();
  for (const it of items) {
    const body = JSON.stringify(strip(it.doc, dropKeys));
    if (seen.has(body)) hard.push({ check: 'exact-duplicate-content', class: label, paths: [seen.get(body), it.path] });
    else seen.set(body, it.path);
  }
}
exactDup('record', records, ['id', 'cell', 'relatedPatterns', 'relatedRules']);
// Identical supplementary text is a review flag, not a hard defect: sibling
// language cells can legitimately share one API-level fix.
const remBodies = new Map();
for (const it of remediation) {
  const { ruleId, ...body } = it.doc;
  const key = JSON.stringify(body);
  if (remBodies.has(key)) flags.push({ class: 'identical-remediation-text', paths: [remBodies.get(key), it.path] });
  else remBodies.set(key, it.path);
}

// 3. near-duplicate wording (review flags only)
const words = (s) => String(s ?? '').toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter((w) => w.length > 2);
function shingles(text, n = 4) {
  const w = words(text);
  const set = new Set();
  for (let i = 0; i + n <= w.length; i += 1) set.add(w.slice(i, i + n).join(' '));
  return set;
}
function jaccard(a, b) {
  if (a.size === 0 || b.size === 0) return 0;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter += 1;
  return inter / (a.size + b.size - inter);
}
function nearDup(label, items, textOf, bandFloor) {
  const prepared = items.map((it) => ({ path: it.path, id: it.doc.id ?? it.doc.ruleId, s: shingles(textOf(it.doc)) }));
  const buckets = new Map();
  for (const p of prepared) {
    const key = (p.s.size > 0 ? [...p.s].sort()[0] : '') + '|' + p.s.size;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(p);
  }
  let compared = 0;
  const pairs = [];
  for (let i = 0; i < prepared.length; i += 1) {
    for (let j = i + 1; j < prepared.length; j += 1) {
      const a = prepared[i];
      const b = prepared[j];
      if (Math.abs(a.s.size - b.s.size) > Math.max(a.s.size, b.s.size) * 0.8) continue;
      compared += 1;
      const jac = jaccard(a.s, b.s);
      if (jac >= bandFloor) pairs.push({ a: a.id, b: b.id, jaccard: Math.round(jac * 1000) / 1000 });
    }
  }
  pairs.sort((x, y) => y.jaccard - x.jaccard || (x.a < y.a ? -1 : 1));
  flags.push({ class: label, pairsCompared: compared, flagged: pairs.length, top: pairs.slice(0, 8) });
}
nearDup('record-description', records, (d) => `${d.title} ${d.description}`, 0.85);
nearDup('remediation-why', remediation, (d) => d.whyItMatters, 0.9);
nearDup('rule-description', rules.map((r) => ({ path: r.path, doc: r.doc })), (d) => `${d.title} ${d.description ?? ''}`, 0.9);

// 4. repeated remediation text (exact)
const why = new Map();
for (const it of remediation) {
  const text = String(it.doc.whyItMatters ?? '').trim();
  if (why.has(text)) flags.push({ class: 'repeated-remediation', text: text.slice(0, 80), paths: [why.get(text), it.path] });
  else why.set(text, it.path);
}

// 5. provenance / origin
for (const it of rules) if (it.doc.origin === undefined) flags.push({ class: 'missing-origin', path: it.path });
for (const it of [...patterns, ...records]) if (it.doc.origin !== 'original-authored') hard.push({ check: 'unexpected-origin', path: it.path, origin: it.doc.origin });
for (const it of [...rules, ...patterns, ...records, ...remediation]) {
  for (const k of ['source', 'sourceUrl', 'retrievedAt', 'license']) {
    if (Object.prototype.hasOwnProperty.call(it.doc, k)) flags.push({ class: 'third-party-provenance-field', path: it.path, field: k });
  }
}

// 6. broken cross-references
for (const it of rules) {
  for (const ref of it.doc.patternRefs ?? it.doc.patterns ?? []) if (!patIds.has(ref)) hard.push({ check: 'broken-rule-pattern-ref', path: it.path, ref });
}
for (const it of patterns) {
  for (const ref of it.doc.linkedRules ?? []) if (!ruleIds.has(ref)) hard.push({ check: 'broken-pattern-rule-ref', path: it.path, ref });
}
for (const it of records) {
  for (const ref of it.doc.relatedPatterns ?? []) if (!patIds.has(ref)) hard.push({ check: 'broken-record-pattern-ref', path: it.path, ref });
  for (const ref of it.doc.relatedRules ?? []) if (!ruleIds.has(ref)) hard.push({ check: 'broken-record-rule-ref', path: it.path, ref });
}
for (const it of remediation) if (!ruleIds.has(it.doc.ruleId)) hard.push({ check: 'broken-remediation-rule-ref', path: it.path, ref: it.doc.ruleId });

// 7. evaluation-case duplication: distinct cases must not restate the same fixture
//    with the same expectation (a duplicate case inflates the assessed population).
const evalCases = (existsSync(join(ROOT, 'data/eval-cases')) ? readdirSync(join(ROOT, 'data/eval-cases')) : [])
  .filter((f) => f.endsWith('.json')).sort()
  .map((f) => ({ path: `data/eval-cases/${f}`, doc: read(join('data', 'eval-cases', f)) }));
const casePrints = new Map();
for (const c of evalCases) {
  const doc = c.doc;
  const print = JSON.stringify({
    lines: doc.fixture?.lines ?? null,
    observation: doc.fixture?.observation ?? null,
    detections: doc.expected?.detections ?? [],
    forbidden: [...(doc.expected?.forbiddenDetections ?? [])].sort(),
  });
  if (casePrints.has(print)) hard.push({ check: 'duplicate-eval-case', paths: [casePrints.get(print), c.path] });
  else casePrints.set(print, c.path);
  if (doc.provenance?.origin !== 'original-authored') hard.push({ check: 'unexpected-case-origin', path: c.path, origin: doc.provenance?.origin });
}
const caseRuleIds = new Set(evalCases.flatMap((c) => [
  ...(c.doc.expected?.detections ?? []).map((d) => d.ruleId),
  ...(c.doc.expected?.forbiddenDetections ?? []),
]));
for (const id of caseRuleIds) if (!ruleIds.has(id)) hard.push({ check: 'case-references-unknown-rule', ref: id });

const coverage = {
  rules: rules.length,
  patterns: patterns.length,
  records: records.length,
  remediation: remediation.length,
  evalCases: evalCases.length,
  evalRulesExercised: caseRuleIds.size,
  patternsWithoutRecord: patterns.filter((p) => !records.some((r) => (r.doc.relatedPatterns ?? []).includes(p.doc.id))).length,
  rulesWithoutRecord: rules.filter((r) => !records.some((rec) => (rec.doc.relatedRules ?? []).includes(r.doc.id))).length,
  rulesWithoutPattern: rules.filter((r) => (r.doc.patternRefs ?? r.doc.patterns ?? []).length === 0).length,
};

const summary = {
  schemaVersion: 'drobon.originality.report/v1',
  population: 'authored pack rules, knowledge patterns, concept records and remediation entries',
  method: 'deterministic; token-shingle Jaccard (n=4) on wording fields; exact-match normalised content; id and cross-reference integrity',
  limitation: 'Similarity flags are review aids only. They are not evidence of copying and cannot establish infringement or its absence. Absence of flags does not prove independent authorship of ideas.',
  coverage,
  hardDefectCount: hard.length,
  hardDefects: hard.slice(0, 50),
  reviewFlagGroups: flags,
};

if (process.argv.includes('--json')) {
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
} else {
  process.stdout.write(`originality: ${rules.length} rules, ${patterns.length} patterns, ${records.length} records, ${remediation.length} remediation\n`);
  process.stdout.write(`hard defects: ${hard.length}\n`);
  for (const h of hard.slice(0, 10)) process.stdout.write(`  HARD ${h.check}: ${h.path ?? h.class} ${h.ref ?? ''}\n`);
  for (const f of flags) {
    if (typeof f.flagged === 'number') {
      process.stdout.write(`review ${f.class}: ${f.flagged} flagged of ${f.pairsCompared} compared\n`);
      for (const p of f.top.slice(0, 3)) process.stdout.write(`  ~${p.jaccard} ${p.a} <> ${p.b}\n`);
    } else if (Array.isArray(f.paths)) {
      process.stdout.write(`review ${f.class}: ${f.paths.join(' , ')}\n`);
    }
  }
  process.stdout.write(`patterns without record: ${coverage.patternsWithoutRecord}; rules without record: ${coverage.rulesWithoutRecord}; rules without pattern: ${coverage.rulesWithoutPattern}\n`);
  process.stdout.write(`eval cases: ${coverage.evalCases} exercising ${coverage.evalRulesExercised} distinct rules (synthetic, test-only)\n`);
}
if (process.argv.includes('--check') && hard.length > 0) process.exit(1);
