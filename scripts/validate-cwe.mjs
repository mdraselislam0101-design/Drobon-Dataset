#!/usr/bin/env node
/**
 * Zero-dependency validator for drobon.knowledge.cwe/v1 entries.
 *
 * CWE reference entries in Drobon's own words (names + short summaries
 * written originally; the canonical definition lives at cwe.mitre.org
 * and every entry links exactly there). The executable check: the url
 * MUST be the canonical MITRE page for the entry's own id.
 *
 * Usage: node scripts/validate-cwe.mjs [path...]  (default: knowledge/cwe)
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const CWE_SCHEMA = 'drobon.knowledge.cwe/v1';
// Mirrors FINDING_CWE_PATTERN (Drobon app, packages/shared/src/scans.ts):
// no leading zeros, so dataset ids always match app finding references.
const CWE_ID_PATTERN = /^CWE-([1-9][0-9]{0,5})$/;
const MAX_NAME = 120;
const MAX_SUMMARY = 500;

const ALLOWED = ['schemaVersion', 'id', 'name', 'summary', 'url'];

function hasControlChars(value) {
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function checkText(errors, path, value, max) {
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

export function validateCwe(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return ['record: must be an object'];
  }
  const errors = [];
  for (const key of Object.keys(value)) {
    if (!ALLOWED.includes(key)) {
      errors.push(`record: unknown property "${key}"`);
    }
  }
  for (const key of ALLOWED) {
    if (value[key] === undefined) {
      errors.push(`record: missing required property "${key}"`);
    }
  }
  if (value['schemaVersion'] !== undefined && value['schemaVersion'] !== CWE_SCHEMA) {
    errors.push(`schemaVersion: must be exactly "${CWE_SCHEMA}"`);
  }
  let number = null;
  if (value['id'] !== undefined) {
    const match = typeof value['id'] === 'string' ? CWE_ID_PATTERN.exec(value['id']) : null;
    if (match === null) {
      errors.push('id: must match ^CWE-[1-9][0-9]{0,5}$ (no leading zeros)');
    } else {
      number = match[1];
    }
  }
  if (value['name'] !== undefined) {
    checkText(errors, 'name', value['name'], MAX_NAME);
  }
  if (value['summary'] !== undefined) {
    checkText(errors, 'summary', value['summary'], MAX_SUMMARY);
  }
  if (value['url'] !== undefined) {
    const expected = number === null ? null : `https://cwe.mitre.org/data/definitions/${number}.html`;
    if (value['url'] !== expected) {
      errors.push(`url: must be the canonical MITRE page for this id (${expected ?? 'unknown'})`);
    }
  }
  return errors;
}

export function validateCwePath(filePath) {
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
  return validateCwe(value).map((error) => `${filePath}: ${error}`);
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
  const roots = (targets.length > 0 ? targets : ['knowledge/cwe']).map((target) =>
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
      failures.push(...validateCwePath(file));
    }
  }
  if (fileCount === 0 && failures.length === 0) {
    failures.push('no JSON files found (refusing to pass on empty input)');
  }
  for (const failure of failures) {
    process.stdout.write(`${failure}\n`);
  }
  if (failures.length > 0) {
    process.stdout.write(`validate-cwe: FAIL (${fileCount} files, ${failures.length} errors)\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`validate-cwe: PASS (${fileCount} files, 0 errors)\n`);
  }
}
