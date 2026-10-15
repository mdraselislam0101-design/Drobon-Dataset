/**
 * Schema validator for detection patterns + data records (3000-asset pump).
 *
 *   knowledge/patterns/DPK-PAT-*.json  (drobon.knowledge.pattern/v1)
 *   knowledge/records/DPK-REC-*.json   (drobon.knowledge.record/v1)
 *
 * Schema-only: example execution, signal uniqueness, and rule↔pattern
 * linkage are enforced by scripts/test-assets.mjs, which runs in `npm test`.
 * Reuses the pack lint (lintRedos) so pattern signals obey the same ReDoS
 * rules as pack rules. Read-only: never writes.
 *
 * Usage: node scripts/validate-assets.mjs   (root = cwd)
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { checkClosed } from './validate.mjs';
import { lintRedos } from './validate-packs.mjs';

export const PATTERN_SCHEMA = 'drobon.knowledge.pattern/v1';
export const RECORD_SCHEMA = 'drobon.knowledge.record/v1';
export const PATTERN_ID = /^DPK-PAT-[0-9]{4,}$/;
export const RECORD_ID = /^DPK-REC-[0-9]{4,}$/;
const RULE_ID = /^DPK-(SAST|SEC|DAST)-[0-9]{3,}$/;
const TARGET_PATTERN = /^[a-z][a-z0-9]{0,31}$/;
const MAX_TEXT = 2000;
const MAX_SIGNAL = 500;

function hasControlChars(value) {
  // eslint-disable-next-line no-control-regex
  return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}

function checkBoundedText(errors, path, value, max) {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) {
    errors.push(`${path}: must be a 1..${max} character string`);
    return;
  }
  if (hasControlChars(value)) {
    errors.push(`${path}: must not contain control characters`);
  }
}

function checkIdArray(errors, path, value, pattern, label) {
  if (!Array.isArray(value) || value.length < 1) {
    errors.push(`${path}: must be a non-empty array of ${label}`);
    return;
  }
  const seen = new Set();
  value.forEach((entry, index) => {
    if (typeof entry !== 'string' || !pattern.test(entry)) {
      errors.push(`${path}[${index}]: must match ${pattern}`);
    } else if (seen.has(entry)) {
      errors.push(`${path}[${index}]: duplicate ${label} "${entry}"`);
    } else {
      seen.add(entry);
    }
  });
}

function checkRegexSignal(errors, path, signal) {
  checkClosed(errors, path, signal, ['kind', 'source', 'flags'], ['kind', 'source']);
  checkBoundedText(errors, `${path}.source`, signal['source'], MAX_SIGNAL);
  if (signal['flags'] !== undefined && signal['flags'] !== 'i') {
    errors.push(`${path}.flags: only "i" is allowed (no g/y/m/s)`);
  }
  if (typeof signal['source'] === 'string') {
    try {
      // eslint-disable-next-line require-unicode-regexp
      new RegExp(signal['source'], signal['flags'] ?? '');
    } catch {
      errors.push(`${path}.source: invalid regex (${signal['source'].slice(0, 60)})`);
      return;
    }
    const lint = lintRedos(signal['source']);
    if (lint !== null) {
      errors.push(`${path}.source: ReDoS lint failed (${lint})`);
    }
  }
}

function checkCheckSignal(errors, path, signal) {
  // Shape-only: the linked RULE carries the same check object and is fully
  // validated by validate-packs.mjs; test-assets.mjs additionally asserts
  // mirror-equality between pattern signal and rule signal.
  checkClosed(errors, path, signal, ['kind', 'check'], ['kind', 'check']);
  const check = signal['check'];
  if (typeof check !== 'object' || check === null || Array.isArray(check)) {
    errors.push(`${path}.check: must be an object`);
    return;
  }
  if (typeof check['type'] !== 'string' || check['type'].length === 0) {
    errors.push(`${path}.check.type: must be a non-empty string`);
  }
}

/** Validate one parsed pattern file. Returns an array of error strings. */
export function validatePattern(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return ['record: must be an object'];
  }
  const errors = [];
  checkClosed(
    errors,
    'record',
    value,
    [
      'schemaVersion',
      'id',
      'title',
      'targets',
      'signal',
      'scope',
      'limitations',
      'examples',
      'fpNotes',
      'linkedRules',
      'origin',
      'cell',
      'validationStatus',
    ],
    [
      'schemaVersion',
      'id',
      'title',
      'targets',
      'signal',
      'scope',
      'limitations',
      'examples',
      'fpNotes',
      'linkedRules',
      'origin',
      'cell',
      'validationStatus',
    ],
  );
  if (value['schemaVersion'] !== PATTERN_SCHEMA) {
    errors.push(`schemaVersion: must be ${PATTERN_SCHEMA}`);
  }
  if (typeof value['id'] !== 'string' || !PATTERN_ID.test(value['id'])) {
    errors.push(`id: must match ${PATTERN_ID}`);
  }
  checkBoundedText(errors, 'title', value['title'], 200);
  if (!Array.isArray(value['targets']) || value['targets'].length < 1 || value['targets'].length > 8) {
    errors.push('targets: must have 1..8 entries');
  } else {
    value['targets'].forEach((entry, index) => {
      if (typeof entry !== 'string' || !TARGET_PATTERN.test(entry)) {
        errors.push(`targets[${index}]: must match ^[a-z][a-z0-9]{0,31}$`);
      }
    });
  }
  const signal = value['signal'];
  if (typeof signal !== 'object' || signal === null || Array.isArray(signal)) {
    errors.push('signal: must be an object');
  } else if (signal['kind'] === 'regex') {
    checkRegexSignal(errors, 'signal', signal);
  } else if (signal['kind'] === 'check') {
    checkCheckSignal(errors, 'signal', signal);
  } else {
    errors.push('signal.kind: must be "regex" or "check"');
  }
  checkBoundedText(errors, 'scope', value['scope'], MAX_TEXT);
  checkBoundedText(errors, 'limitations', value['limitations'], MAX_TEXT);
  if (!Array.isArray(value['examples']) || value['examples'].length < 2) {
    errors.push('examples: must have at least 2 entries (>=1 positive and >=1 negative)');
  } else {
    value['examples'].forEach((entry, index) => {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
        errors.push(`examples[${index}]: must be an object`);
      } else if (typeof entry['match'] !== 'boolean') {
        errors.push(`examples[${index}].match: must be a boolean`);
      }
    });
  }
  checkBoundedText(errors, 'fpNotes', value['fpNotes'], MAX_TEXT);
  checkIdArray(errors, 'linkedRules', value['linkedRules'], RULE_ID, 'rule id');
  if (value['origin'] !== 'original-authored') {
    errors.push('origin: must be "original-authored"');
  }
  checkBoundedText(errors, 'cell', value['cell'], 120);
  if (value['validationStatus'] !== 'VALIDATED') {
    errors.push('validationStatus: must be "VALIDATED" (generator writes passing cells only)');
  }
  return errors;
}

/** Validate one parsed data-record file. Returns an array of error strings. */
export function validateRecord(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return ['record: must be an object'];
  }
  const errors = [];
  checkClosed(
    errors,
    'record',
    value,
    [
      'schemaVersion',
      'id',
      'category',
      'subcategory',
      'title',
      'description',
      'applicability',
      'risk',
      'relatedPatterns',
      'relatedRules',
      'origin',
      'cell',
      'validationStatus',
    ],
    [
      'schemaVersion',
      'id',
      'category',
      'subcategory',
      'title',
      'description',
      'applicability',
      'risk',
      'relatedPatterns',
      'relatedRules',
      'origin',
      'cell',
      'validationStatus',
    ],
  );
  if (value['schemaVersion'] !== RECORD_SCHEMA) {
    errors.push(`schemaVersion: must be ${RECORD_SCHEMA}`);
  }
  if (typeof value['id'] !== 'string' || !RECORD_ID.test(value['id'])) {
    errors.push(`id: must match ${RECORD_ID}`);
  }
  checkBoundedText(errors, 'category', value['category'], 64);
  checkBoundedText(errors, 'subcategory', value['subcategory'], 64);
  checkBoundedText(errors, 'title', value['title'], 200);
  checkBoundedText(errors, 'description', value['description'], 4000);
  checkBoundedText(errors, 'applicability', value['applicability'], MAX_TEXT);
  checkBoundedText(errors, 'risk', value['risk'], MAX_TEXT);
  checkIdArray(errors, 'relatedPatterns', value['relatedPatterns'], PATTERN_ID, 'pattern id');
  checkIdArray(errors, 'relatedRules', value['relatedRules'], RULE_ID, 'rule id');
  if (value['origin'] !== 'original-authored') {
    errors.push('origin: must be "original-authored"');
  }
  checkBoundedText(errors, 'cell', value['cell'], 120);
  if (value['validationStatus'] !== 'VALIDATED') {
    errors.push('validationStatus: must be "VALIDATED" (generator writes passing cells only)');
  }
  return errors;
}

function collectJsonFiles(root) {
  return readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.json'))
    .map((entry) => join(root, entry.name))
    .sort();
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (invokedAsScript) {
  const root = process.cwd();
  const failures = [];
  let fileCount = 0;
  for (const [dir, validator] of [
    ['knowledge/patterns', validatePattern],
    ['knowledge/records', validateRecord],
  ]) {
    let files;
    try {
      files = collectJsonFiles(join(root, dir));
    } catch (err) {
      failures.push(`${dir}: cannot read: ${err.message}`);
      continue;
    }
    fileCount += files.length;
    for (const file of files) {
      let parsed;
      try {
        parsed = JSON.parse(readFileSync(file, 'utf8'));
      } catch (err) {
        failures.push(`${relative(root, file)}: cannot parse: ${err.message}`);
        continue;
      }
      for (const error of validator(parsed)) {
        failures.push(`${relative(root, file)}: ${error}`);
      }
    }
  }
  if (failures.length > 0) {
    for (const failure of failures.slice(0, 40)) {
      process.stderr.write(`${failure}\n`);
    }
    process.stderr.write(`validate-assets: FAIL (${failures.length} errors)\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`validate-assets: PASS (${fileCount} files, 0 errors)\n`);
  }
}
