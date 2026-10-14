#!/usr/bin/env node
/**
 * Audience test runner (zero dependencies), executed after test-packs.mjs
 * via `npm test`:
 *  1. every file under knowledge/ learning/ assessments/ engagements/
 *     MUST validate (positive — includes lesson practice execution);
 *  2. layout policy (kind dirs, schemaVersion, filename == id);
 *  3. every fixture under test/invalid-audiences/ MUST be rejected.
 *
 * Usage: node scripts/test-audiences.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateAudiencePath } from './validate-audiences.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let passed = 0;
let failed = 0;

function assert(condition, label, detail = '') {
  if (condition) {
    passed += 1;
    process.stdout.write(`ok - ${label}\n`);
  } else {
    failed += 1;
    process.stdout.write(`FAIL - ${label}\n`);
    if (detail) {
      process.stdout.write(`    ${detail}\n`);
    }
  }
}

function collectJsonFiles(root) {
  const found = [];
  const walk = (dir) => {
    const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && entry.name.endsWith('.json')) {
        found.push(full);
      }
    }
  };
  walk(root);
  return found;
}

const AUDIENCE_DIRS = {
  'knowledge/remediation': { schema: 'drobon.knowledge.remediation/v1', idField: 'ruleId', min: 4 },
  'learning/lessons': { schema: 'drobon.learning.lesson/v1', idField: 'id', min: 3 },
  'assessments/templates': { schema: 'drobon.assessment.template/v1', idField: 'id', min: 3 },
  engagements: { schema: 'drobon.engagement.template/v1', idField: 'id', min: 2 },
};

// --- 1. positive ------------------------------------------------------------
for (const [dir, spec] of Object.entries(AUDIENCE_DIRS)) {
  const files = collectJsonFiles(join(ROOT, dir));
  assert(files.length >= spec.min, `audiences: ${dir} ships starter content (found ${files.length})`);
  for (const file of files) {
    const errors = validateAudiencePath(file, ROOT);
    assert(errors.length === 0, `positive: ${relative(ROOT, file)} validates`, errors.join('; '));
  }
  // --- 2. layout -----------------------------------------------------------
  for (const file of files) {
    const rel = relative(ROOT, file);
    const record = JSON.parse(readFileSync(file, 'utf8'));
    const fileName = rel.split('/').pop().replace(/\.json$/, '');
    assert(
      record.schemaVersion === spec.schema,
      `layout: ${rel} schemaVersion matches its dir`,
      String(record.schemaVersion),
    );
    assert(
      typeof record[spec.idField] === 'string' && record[spec.idField] === fileName,
      `layout: ${rel} filename matches ${spec.idField}`,
      `file ${fileName} vs ${String(record[spec.idField])}`,
    );
  }
}

// --- 3. negative ---------------------------------------------------------------
const NEGATIVE = {
  'remediation-bad-ruleid.json': 'ruleId',
  'remediation-bad-standardid.json': 'standardId: must match',
  'lesson-bad-quiz.json': 'answerIndex',
  'lesson-starter-miss.json': 'no line triggers',
  'template-with-declarations.json': 'unknown property',
  'engagement-banned-phrase.json': 'banned phrase',
};
for (const [name, needle] of Object.entries(NEGATIVE)) {
  const file = join(ROOT, 'test', 'invalid-audiences', name);
  let errors = [];
  try {
    statSync(file);
    errors = validateAudiencePath(file, ROOT);
  } catch {
    errors = [];
  }
  const rejected = errors.length > 0 && errors.some((error) => error.includes(needle));
  assert(rejected, `negative: test/invalid-audiences/${name} rejected (${needle})`, errors.join('; '));
}

// --- summary -----------------------------------------------------------------
const total = passed + failed;
process.stdout.write(`audience-tests: ${failed === 0 ? 'PASS' : 'FAIL'} (${passed}/${total} passed)\n`);
process.exitCode = failed === 0 ? 0 : 1;
