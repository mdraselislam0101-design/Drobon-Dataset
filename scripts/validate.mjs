#!/usr/bin/env node
/**
 * Zero-dependency validator for `drobon.vuln-intel/v1` advisory records.
 *
 * This is the EXECUTABLE SPEC: docs/FORMAT.md describes it and
 * schema/advisory.schema.json mirrors it for editors/tooling. If they
 * ever disagree, this file wins and the others must be fixed.
 *
 * Every bound mirrors the Drobon app's ScaAdvisory contract exactly, so
 * a record that passes here can never produce an advisory the app's
 * closed `isScaAdvisory` guard would reject.
 *
 * Usage:
 *   node scripts/validate.mjs [path...]   # files or directories (default: vuln-intel)
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateRange } from './range.mjs';

export const SCHEMA_VERSION = 'drobon.vuln-intel/v1';

// Mirrors SCA_ECOSYSTEMS (Drobon app, packages/shared/src/sca.ts).
const ECOSYSTEMS = ['npm', 'pypi'];
// Mirrors FINDING_SEVERITIES (Drobon app, packages/shared/src/scans.ts).
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

// Mirrors SCA_ADVISORY_ID_MAX_LENGTH.
const MAX_ID = 100;
// Mirrors SCA_ADVISORY_TEXT_MAX_LENGTH / SCA_ADVISORY_URL_MAX_LENGTH.
const MAX_TEXT = 400;
// Mirrors SCA_NAME_MAX_LENGTH.
const MAX_NAME = 214;
// Mirrors SCA_VERSION_MAX_LENGTH.
const MAX_VERSION = 200;
// Dataset-local bounds (provenance is not part of ScaAdvisory).
const MAX_SOURCE = 64;
const MAX_LICENSE = 100;
const MAX_AFFECTED = 50;

const FIXTURE_ID_PATTERN = /^DROBON-SAMPLE-[0-9]{3,}$/;
const FIXTURE_ID_PREFIX = 'DROBON-SAMPLE-';

const TOP_REQUIRED = [
  'schemaVersion',
  'fixture',
  'id',
  'ecosystem',
  'package',
  'summary',
  'severity',
  'affected',
  'provenance',
];
const TOP_ALLOWED = [...TOP_REQUIRED, 'url'];
const AFFECTED_ALLOWED = ['range', 'fixed'];
const PROVENANCE_ALLOWED = ['source', 'sourceUrl', 'retrievedAt', 'license'];

function hasControlChars(value) {
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function checkBoundedText(errors, path, value, max) {
  if (typeof value !== 'string') {
    errors.push(`${path}: must be a string`);
    return;
  }
  if (value.length < 1 || value.length > max) {
    errors.push(`${path}: must be 1..${max} characters (got ${value.length})`);
    return;
  }
  if (hasControlChars(value)) {
    errors.push(`${path}: must not contain control characters`);
  }
}

function checkUrl(errors, path, value, max) {
  checkBoundedText(errors, path, value, max);
  if (typeof value === 'string' && value.length > 0 && !value.startsWith('https://')) {
    errors.push(`${path}: must start with https://`);
  }
}

function checkClosed(errors, path, record, allowed, required) {
  for (const key of Object.keys(record)) {
    if (!allowed.includes(key)) {
      errors.push(`${path}: unknown property "${key}"`);
    }
  }
  for (const key of required) {
    if (record[key] === undefined) {
      errors.push(`${path}: missing required property "${key}"`);
    }
  }
}

function isValidDateTime(value) {
  if (typeof value !== 'string' || value.length === 0) {
    return false;
  }
  return Number.isFinite(Date.parse(value));
}

/**
 * Validate one parsed record. Returns an array of human-readable
 * error strings (empty = valid). Pure function of the value.
 */
export function validateRecord(value) {
  const errors = [];
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return ['record: must be an object'];
  }
  const record = value;
  checkClosed(errors, 'record', record, TOP_ALLOWED, TOP_REQUIRED);

  if (record['schemaVersion'] !== undefined && record['schemaVersion'] !== SCHEMA_VERSION) {
    errors.push(`schemaVersion: must be exactly "${SCHEMA_VERSION}"`);
  }
  if (record['fixture'] !== undefined && typeof record['fixture'] !== 'boolean') {
    errors.push('fixture: must be a boolean');
  }
  const isFixture = record['fixture'] === true;

  if (record['id'] !== undefined) {
    checkBoundedText(errors, 'id', record['id'], MAX_ID);
    if (typeof record['id'] === 'string') {
      if (isFixture && !FIXTURE_ID_PATTERN.test(record['id'])) {
        errors.push('id: fixture records must use ids matching DROBON-SAMPLE-###');
      }
      if (!isFixture && record['id'].startsWith(FIXTURE_ID_PREFIX)) {
        errors.push('id: real records must not use the DROBON-SAMPLE- prefix');
      }
    }
  }
  if (record['ecosystem'] !== undefined && !ECOSYSTEMS.includes(record['ecosystem'])) {
    errors.push(`ecosystem: must be one of ${ECOSYSTEMS.join(', ')}`);
  }
  if (record['package'] !== undefined) {
    checkBoundedText(errors, 'package', record['package'], MAX_NAME);
  }
  if (record['summary'] !== undefined) {
    checkBoundedText(errors, 'summary', record['summary'], MAX_TEXT);
  }
  if (record['severity'] !== undefined && !SEVERITIES.includes(record['severity'])) {
    errors.push(`severity: must be one of ${SEVERITIES.join(', ')}`);
  }
  if (record['url'] !== undefined) {
    checkUrl(errors, 'url', record['url'], MAX_TEXT);
  }

  if (record['affected'] !== undefined) {
    if (!Array.isArray(record['affected'])) {
      errors.push('affected: must be an array');
    } else {
      if (record['affected'].length < 1 || record['affected'].length > MAX_AFFECTED) {
        errors.push(
          `affected: must have 1..${MAX_AFFECTED} entries (got ${record['affected'].length})`,
        );
      }
      record['affected'].forEach((entry, index) => {
        const path = `affected[${index}]`;
        if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
          errors.push(`${path}: must be an object`);
          return;
        }
        checkClosed(errors, path, entry, AFFECTED_ALLOWED, ['range']);
        if (entry['range'] !== undefined) {
          checkBoundedText(errors, `${path}.range`, entry['range'], MAX_VERSION);
        }
        if (entry['fixed'] !== undefined) {
          checkBoundedText(errors, `${path}.fixed`, entry['fixed'], MAX_VERSION);
        }
        if (
          entry['range'] !== undefined &&
          typeof entry['range'] === 'string' &&
          ECOSYSTEMS.includes(record['ecosystem'])
        ) {
          const rangeError = validateRange(record['ecosystem'], entry['range']);
          if (rangeError !== null) {
            errors.push(`${path}.range: ${rangeError}`);
          }
        }
      });
    }
  }

  if (record['provenance'] !== undefined) {
    const provenance = record['provenance'];
    if (typeof provenance !== 'object' || provenance === null || Array.isArray(provenance)) {
      errors.push('provenance: must be an object');
    } else {
      checkClosed(errors, 'provenance', provenance, PROVENANCE_ALLOWED, ['source']);
      if (provenance['source'] !== undefined) {
        checkBoundedText(errors, 'provenance.source', provenance['source'], MAX_SOURCE);
        if (typeof provenance['source'] === 'string') {
          if (isFixture && provenance['source'] !== 'fixture') {
            errors.push('provenance.source: fixture records must use source "fixture"');
          }
          if (!isFixture && provenance['source'] === 'fixture') {
            errors.push('provenance.source: real records must not use source "fixture"');
          }
        }
      }
      if (!isFixture) {
        if (provenance['sourceUrl'] === undefined) {
          errors.push('provenance: real records require "sourceUrl"');
        }
        if (provenance['retrievedAt'] === undefined) {
          errors.push('provenance: real records require "retrievedAt"');
        }
      }
      if (provenance['sourceUrl'] !== undefined) {
        checkUrl(errors, 'provenance.sourceUrl', provenance['sourceUrl'], MAX_TEXT);
      }
      if (provenance['retrievedAt'] !== undefined && !isValidDateTime(provenance['retrievedAt'])) {
        errors.push('provenance.retrievedAt: must be a valid RFC 3339 date-time');
      }
      if (provenance['license'] !== undefined) {
        checkBoundedText(errors, 'provenance.license', provenance['license'], MAX_LICENSE);
      }
    }
  }

  return errors;
}

/** Validate one file on disk. Returns error strings prefixed with the path. */
export function validateFile(filePath) {
  let raw;
  try {
    raw = readFileSync(filePath, 'utf8');
  } catch (err) {
    return [`${filePath}: cannot read file: ${err.message}`];
  }
  let value;
  try {
    value = JSON.parse(raw);
  } catch (err) {
    return [`${filePath}: invalid JSON: ${err.message}`];
  }
  return validateRecord(value).map((error) => `${filePath}: ${error}`);
}

function collectJsonFiles(target) {
  const stat = statSync(target);
  if (stat.isFile()) {
    return target.endsWith('.json') ? [target] : [];
  }
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
  walk(target);
  return found;
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (invokedAsScript) {
  const targets = process.argv.slice(2);
  const roots = (targets.length > 0 ? targets : ['vuln-intel']).map((target) =>
    resolve(process.cwd(), target),
  );
  const failures = [];
  let fileCount = 0;
  for (const root of roots) {
    let files;
    try {
      files = collectJsonFiles(root);
    } catch (err) {
      failures.push(`${root}: cannot read: ${err.message}`);
      continue;
    }
    fileCount += files.length;
    for (const file of files) {
      failures.push(...validateFile(file));
    }
  }
  if (fileCount === 0 && failures.length === 0) {
    failures.push('no JSON files found (refusing to pass on empty input)');
  }
  for (const failure of failures) {
    process.stdout.write(`${failure}\n`);
  }
  if (failures.length > 0) {
    process.stdout.write(`validate: FAIL (${fileCount} files, ${failures.length} errors)\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`validate: PASS (${fileCount} files, 0 errors)\n`);
  }
}
