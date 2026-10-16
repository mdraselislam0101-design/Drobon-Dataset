/**
 * Executable quality tests for detection patterns + data records.
 *
 * Every pattern's examples RUN against its signal (regex compile + match,
 * or DAST check evaluation); rule<->pattern linkage must resolve exactly
 * in both directions; pattern signals must mirror a linked rule's signal.
 * Runs in `npm test`.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { evalDastCheck } from './validate-packs.mjs';
import { PATTERN_SCHEMA, RECORD_SCHEMA, validatePattern, validateRecord } from './validate-assets.mjs';

const ROOT = resolve(new URL('.', import.meta.url).pathname, '..');

let passed = 0;
let failed = 0;
function assert(condition, name, detail = '') {
  if (condition) {
    passed += 1;
    process.stdout.write(`ok - ${name}\n`);
  } else {
    failed += 1;
    process.stdout.write(`FAIL - ${name}${detail === '' ? '' : `\n    ${detail}`}\n`);
  }
}

function collectJsonFiles(root) {
  return readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.json'))
    .map((entry) => join(root, entry.name))
    .sort();
}

function loadJson(file) {
  return JSON.parse(readFileSync(file, 'utf8'));
}

const patternFiles = collectJsonFiles(join(ROOT, 'knowledge', 'patterns'));
const recordFiles = collectJsonFiles(join(ROOT, 'knowledge', 'records'));
const ruleFiles = ['sast', 'secrets', 'dast'].flatMap((kind) =>
  collectJsonFiles(join(ROOT, 'packs', kind, 'v1', 'rules')),
);
const patterns = new Map(patternFiles.map((file) => [loadJson(file).id, { file, record: loadJson(file) }]));
const records = new Map(recordFiles.map((file) => [loadJson(file).id, { file, record: loadJson(file) }]));
const rules = new Map(ruleFiles.map((file) => [loadJson(file).id, { file, record: loadJson(file) }]));

// --- 1. positive: patterns + records validate --------------------------------
for (const [id, { file, record }] of patterns) {
  const errors = validatePattern(record);
  assert(errors.length === 0, `positive: ${relative(ROOT, file)} validates`, errors.join('; '));
}
for (const [id, { file, record }] of records) {
  const errors = validateRecord(record);
  assert(errors.length === 0, `positive: ${relative(ROOT, file)} validates`, errors.join('; '));
}

// --- 2. layout: filename matches id, schemaVersion const ---------------------
for (const [id, { file, record }] of patterns) {
  const base = file.split('/').pop().replace(/\.json$/, '');
  assert(record.id === base, `layout: ${relative(ROOT, file)} filename matches pattern id`, `file ${base} vs id ${String(record.id)}`);
  assert(record.schemaVersion === PATTERN_SCHEMA, `layout: ${relative(ROOT, file)} schemaVersion is pattern/v1`, String(record.schemaVersion));
}
for (const [id, { file, record }] of records) {
  const base = file.split('/').pop().replace(/\.json$/, '');
  assert(record.id === base, `layout: ${relative(ROOT, file)} filename matches record id`, `file ${base} vs id ${String(record.id)}`);
  assert(record.schemaVersion === RECORD_SCHEMA, `layout: ${relative(ROOT, file)} schemaVersion is record/v1`, String(record.schemaVersion));
}

// --- 3. executable: pattern examples run against the signal ------------------
// A regex example is either an inline `line`, or a pointer `{ ruleRef, testIndex, match }`
// to a test line already stored in the owning rule file. The pointer form keeps
// credential-shaped text inside packs/ fixtures only (see test-consistency's gate).
// Failure messages report the index, never the line text.
function resolveRegexExample(entry) {
  if (entry.ruleRef === undefined) {
    return typeof entry.line === 'string' ? { line: entry.line } : { error: 'regex-kind example needs a line' };
  }
  if (typeof entry.ruleRef !== 'string' || !Number.isInteger(entry.testIndex)) {
    return { error: 'ruleRef example needs a string ruleRef and an integer testIndex' };
  }
  const file = ['sast', 'secrets', 'dast']
    .map((kind) => join(ROOT, 'packs', kind, 'v1', 'rules', `${entry.ruleRef}.json`))
    .find((candidate) => existsSync(candidate));
  if (file === undefined) {
    return { error: `ruleRef ${entry.ruleRef} has no rule file` };
  }
  const rule = JSON.parse(readFileSync(file, 'utf8'));
  const test = Array.isArray(rule.tests) ? rule.tests[entry.testIndex] : undefined;
  if (test === undefined || typeof test.line !== 'string') {
    return { error: `${entry.ruleRef} tests[${entry.testIndex}] has no line` };
  }
  if (test.match !== entry.match) {
    return { error: `${entry.ruleRef} tests[${entry.testIndex}] polarity differs from the example` };
  }
  return { line: test.line };
}
for (const [id, { record }] of patterns) {
  const examples = record.examples ?? [];
  const pos = examples.filter((t) => t.match === true).length;
  const neg = examples.filter((t) => t.match === false).length;
  assert(pos >= 1 && neg >= 1, `floors: ${id} ships >=1 positive and >=1 negative example`, `pos=${pos} neg=${neg}`);
  const mismatches = [];
  if (record.signal?.kind === 'regex') {
    let regex = null;
    try {
      // eslint-disable-next-line require-unicode-regexp
      regex = new RegExp(record.signal.source, record.signal.flags ?? '');
    } catch {
      mismatches.push('signal does not compile');
    }
    if (regex !== null) {
      examples.forEach((entry, index) => {
        const resolved = resolveRegexExample(entry);
        if (resolved.error !== undefined) {
          mismatches.push(`examples[${index}]: ${resolved.error}`);
          return;
        }
        const actual = regex.test(resolved.line);
        if (actual !== entry.match) {
          mismatches.push(`examples[${index}]: got ${String(actual)}, want ${String(entry.match)}`);
        }
      });
    }
  } else if (record.signal?.kind === 'check') {
    examples.forEach((entry, index) => {
      if (typeof entry.observation !== 'object' || entry.observation === null) {
        mismatches.push(`examples[${index}]: check-kind example needs an observation`);
        return;
      }
      let actual = null;
      try {
        actual = evalDastCheck(record.signal.check, entry.observation);
      } catch (err) {
        mismatches.push(`examples[${index}]: check threw: ${err.message}`);
        return;
      }
      if (actual !== entry.match) {
        mismatches.push(`examples[${index}]: got ${String(actual)}, want ${String(entry.match)}`);
      }
    });
  } else {
    mismatches.push('unknown signal kind');
  }
  assert(mismatches.length === 0, `executable: ${id} examples behave as declared`, mismatches.join('; '));
}

// --- 4. uniqueness: signals, descriptions, ids --------------------------------
const seenSignals = new Map();
const signalCollisions = [];
for (const [id, { record }] of patterns) {
  const key =
    record.signal?.kind === 'regex'
      ? `re:${[...(record.targets ?? [])].sort().join(',')}::${record.signal.source}::${record.signal.flags ?? ''}`
      : `check:${JSON.stringify(record.signal?.check)}`;
  if (seenSignals.has(key)) {
    signalCollisions.push(`${id} ~= ${seenSignals.get(key)}`);
  } else {
    seenSignals.set(key, id);
  }
}
assert(signalCollisions.length === 0, `unique: no duplicate pattern signals (${seenSignals.size} unique)`, signalCollisions.join('; '));
const seenDescriptions = new Map();
const descriptionCollisions = [];
for (const [id, { record }] of records) {
  if (seenDescriptions.has(record.description)) {
    descriptionCollisions.push(`${id} ~= ${seenDescriptions.get(record.description)}`);
  } else {
    seenDescriptions.set(record.description, id);
  }
}
assert(descriptionCollisions.length === 0, `unique: no duplicate record descriptions (${seenDescriptions.size} unique)`, descriptionCollisions.join('; '));
assert(patterns.size === patternFiles.length, `unique: pattern ids are distinct (${patterns.size}/${patternFiles.length})`);
assert(records.size === recordFiles.length, `unique: record ids are distinct (${records.size}/${recordFiles.length})`);

// --- 5. linkage: bidirectional rule<->pattern, mirror-equality, records ------
const danglingRuleRefs = [];
for (const [id, { record }] of rules) {
  for (const ref of record.patternRefs ?? []) {
    if (!patterns.has(ref)) {
      danglingRuleRefs.push(`${id} -> ${ref}`);
    }
  }
}
assert(danglingRuleRefs.length === 0, 'linkage: every rule patternRefs resolves to a pattern', danglingRuleRefs.join('; '));
const danglingPatternRefs = [];
const asymmetric = [];
for (const [id, { record }] of patterns) {
  for (const ruleId of record.linkedRules ?? []) {
    const target = rules.get(ruleId);
    if (target === undefined) {
      danglingPatternRefs.push(`${id} -> ${ruleId}`);
    } else if (!(target.record.patternRefs ?? []).includes(id)) {
      asymmetric.push(`${id} lists ${ruleId} but not back`);
    }
  }
}
for (const [id, { record }] of rules) {
  for (const ref of record.patternRefs ?? []) {
    const target = patterns.get(ref);
    if (target !== undefined && !(target.record.linkedRules ?? []).includes(id)) {
      asymmetric.push(`${id} lists ${ref} but not back`);
    }
  }
}
assert(danglingPatternRefs.length === 0, 'linkage: every pattern linkedRules resolves to a rule', danglingPatternRefs.join('; '));
assert(asymmetric.length === 0, 'linkage: rule<->pattern references are exactly bidirectional', asymmetric.join('; '));
function ruleSignals(rule) {
  const found = [];
  for (const pattern of rule.patterns ?? []) {
    found.push(`re:${pattern.source}::${pattern.flags ?? ''}`);
  }
  if (rule.check !== undefined) {
    found.push(`check:${JSON.stringify(rule.check)}`);
  }
  return found;
}
const mirrorBreaks = [];
for (const [id, { record }] of patterns) {
  const want =
    record.signal?.kind === 'regex'
      ? `re:${record.signal.source}::${record.signal.flags ?? ''}`
      : `check:${JSON.stringify(record.signal?.check)}`;
  const mirrored = (record.linkedRules ?? []).some((ruleId) => ruleSignals(rules.get(ruleId)?.record ?? {}).includes(want));
  if (!mirrored) {
    mirrorBreaks.push(`${id}: no linked rule carries this signal`);
  }
}
assert(mirrorBreaks.length === 0, 'linkage: every pattern signal mirrors a linked rule signal', mirrorBreaks.join('; '));
const danglingRecordRefs = [];
for (const [id, { record }] of records) {
  for (const ref of record.relatedPatterns ?? []) {
    if (!patterns.has(ref)) {
      danglingRecordRefs.push(`${id} -> ${ref}`);
    }
  }
  for (const ref of record.relatedRules ?? []) {
    if (!rules.has(ref)) {
      danglingRecordRefs.push(`${id} -> ${ref}`);
    }
  }
}
assert(danglingRecordRefs.length === 0, 'linkage: every record reference resolves', danglingRecordRefs.join('; '));
const uncoveredRules = [...rules.keys()].filter((id) => (rules.get(id).record.patternRefs ?? []).length === 0);
const uncoveredPatterns = [...patterns.keys()].filter((id) => (patterns.get(id).record.linkedRules ?? []).length === 0);
assert(
  uncoveredRules.length === 0 && uncoveredPatterns.length === 0,
  `linkage: 100% rule<->pattern coverage (${rules.size} rules, ${patterns.size} patterns)`,
  `rules without patterns: ${uncoveredRules.join(', ')}; patterns without rules: ${uncoveredPatterns.join(', ')}`,
);

process.stdout.write(`asset-tests: ${failed === 0 ? 'PASS' : 'FAIL'} (${passed}/${passed + failed} passed)\n`);
process.exitCode = failed === 0 ? 0 : 1;
