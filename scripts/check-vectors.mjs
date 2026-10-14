#!/usr/bin/env node
/**
 * Provider interop checker (zero dependencies).
 *
 * Pins the matching contract between this dataset and a future Drobon
 * SCA provider: for each vector in interop/provider-vectors.json, the
 * coordinate (ecosystem + name + version) MUST match exactly the
 * listed advisory ids — no more, no less.
 *
 * Matching semantics (mirrors docs/FORMAT.md + PROVIDER_MAPPING.md):
 * - real records only (fixtures never match);
 * - ecosystem + package equality, then ANY affected range satisfying
 *   the coordinate version (scripts/range.mjs);
 * - version-less coordinates NEVER match (conservative policy);
 * - matched ids deduplicated (multi-file advisories collapse to one id).
 *
 * A range this checker cannot evaluate exactly FAILS the vector with
 * an explicit message — never a silent match or silent miss.
 *
 * Usage: node scripts/check-vectors.mjs   (also runs inside npm test)
 */
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { satisfiesRange } from './range.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

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

function loadRealRecords(root) {
  const records = [];
  for (const file of collectJsonFiles(join(root, 'vuln-intel'))) {
    const record = JSON.parse(readFileSync(file, 'utf8'));
    if (record.fixture === false) {
      records.push(record);
    }
  }
  return records;
}

function matchVector(records, vector) {
  const { coordinate, expect } = vector;
  const matched = new Set();
  for (const record of records) {
    if (record.ecosystem !== coordinate.ecosystem || record.package !== coordinate.name) {
      continue;
    }
    if (typeof coordinate.version !== 'string') {
      continue; // version-less: conservative no-match
    }
    for (const entry of record.affected) {
      if (satisfiesRange(record.ecosystem, coordinate.version, entry.range)) {
        matched.add(record.id);
        break;
      }
    }
  }
  const actual = [...matched].sort();
  const expected = [...expect].sort();
  if (actual.length !== expected.length || actual.some((id, i) => id !== expected[i])) {
    return `expected [${expected.join(', ')}] but matched [${actual.join(', ')}]`;
  }
  return null;
}

export function checkVectors(root = join(HERE, '..')) {
  const vectorsDoc = JSON.parse(
    readFileSync(join(root, 'interop', 'provider-vectors.json'), 'utf8'),
  );
  if (vectorsDoc.schemaVersion !== 'drobon.vuln-intel/vectors/v1') {
    return {
      passed: 0,
      failed: 1,
      failures: ['vectors file has wrong schemaVersion'],
    };
  }
  const records = loadRealRecords(root);
  const failures = [];
  let passed = 0;
  for (const vector of vectorsDoc.vectors) {
    try {
      const mismatch = matchVector(records, vector);
      if (mismatch === null) {
        passed += 1;
      } else {
        failures.push(`${vector.id}: ${mismatch} (${vector.note ?? ''})`);
      }
    } catch (err) {
      failures.push(`${vector.id}: cannot evaluate (${err.message})`);
    }
  }
  return { passed, failed: failures.length, failures };
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (invokedAsScript) {
  const { passed, failed, failures } = checkVectors();
  for (const failure of failures) {
    process.stdout.write(`FAIL - ${failure}\n`);
  }
  process.stdout.write(
    `vectors: ${failed === 0 ? 'PASS' : 'FAIL'} (${passed}/${passed + failed} vectors)\n`,
  );
  process.exitCode = failed === 0 ? 0 : 1;
}
