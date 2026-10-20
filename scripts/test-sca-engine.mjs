#!/usr/bin/env node
/**
 * test-sca-engine.mjs — fail-closed contract tests for the original synthetic
 * SCA matching logic (scripts/sca-engine.mjs).
 *
 * Scope: original logic + synthetic fixtures only. No real advisory data, no
 * network, no feed ingestion, no third-party ids. Every negative path proves a
 * refusal rather than a silent fallback.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SCA_DATASET_STATUS,
  ScaContractError,
  createSyntheticProvider,
  normalizeCoordinate,
  severityRank,
  validateSyntheticRecord,
} from './sca-engine.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let passed = 0;
let failed = 0;
function assert(condition, name, detail = '') {
  if (condition) {
    passed += 1;
    process.stdout.write(`ok - ${name}\n`);
  } else {
    failed += 1;
    process.stdout.write(`FAIL - ${name}\n`);
    if (detail) process.stdout.write(`    ${detail}\n`);
  }
}
function codeOf(fn) {
  try {
    fn();
    return 'NO_THROW';
  } catch (error) {
    return error instanceof ScaContractError ? error.code : `UNEXPECTED:${error.message}`;
  }
}

const RECORDS = [
  {
    schemaVersion: 'drobon.sca.synthetic-advisory/v1',
    fixture: true,
    id: 'DROBON-SAMPLE-001',
    ecosystem: 'npm',
    package: 'acme-parser',
    severity: 'HIGH',
    affected: [{ range: '< 4.2.1', fixed: '4.2.1' }],
    provenance: { source: 'fixture' },
  },
  {
    schemaVersion: 'drobon.sca.synthetic-advisory/v1',
    fixture: true,
    id: 'DROBON-SAMPLE-002',
    ecosystem: 'npm',
    package: 'acme-parser',
    severity: 'LOW',
    affected: [{ range: '>= 4.0.0, < 4.1.0', fixed: '4.1.0' }],
    provenance: { source: 'fixture' },
  },
  {
    schemaVersion: 'drobon.sca.synthetic-advisory/v1',
    fixture: true,
    id: 'DROBON-SAMPLE-003',
    ecosystem: 'pypi',
    package: 'acme-client',
    severity: 'MEDIUM',
    affected: [
      { range: '>= 2.30.0, < 2.31.0', fixed: '2.31.0' },
      { range: '>= 3.0.0, < 3.0.2', fixed: '3.0.2' },
    ],
    provenance: { source: 'fixture' },
  },
];

// --- 1. record validation ---------------------------------------------------
assert(validateSyntheticRecord(RECORDS[0]).length === 0, 'records: a well-formed synthetic record validates');

const realRecord = { ...RECORDS[0], fixture: false, id: 'GHSA-aaaa-bbbb-cccc' };
const realReasons = validateSyntheticRecord(realRecord).join('; ');
assert(
  realReasons.includes('REAL_RECORD_REFUSED') && realReasons.includes('DROBON-SAMPLE'),
  'records: a real-style record is refused (fixture flag + synthetic id)',
  realReasons,
);
assert(codeOf(() => createSyntheticProvider([realRecord])) === 'INVALID_RECORD', 'records: provider construction refuses real records');
assert(validateSyntheticRecord({ ...RECORDS[0], schemaVersion: 'drobon.vuln-intel/v1' }).length > 0, 'records: a foreign schema is rejected');
assert(validateSyntheticRecord({ ...RECORDS[0], provenance: { source: 'GHSA' } }).length > 0, 'records: provenance.source must be fixture');
assert(validateSyntheticRecord({ ...RECORDS[0], affected: [{ range: '*' }] }).length > 0, 'records: bare wildcard range is rejected (explicit bounds required)');
assert(validateSyntheticRecord({ ...RECORDS[0], severity: 'SEVERE' }).length > 0, 'records: invented severity labels are rejected');

// --- 2. coordinate normalisation -------------------------------------------
const coordinate = normalizeCoordinate({ ecosystem: 'npm', name: 'acme-parser', version: '4.2.0' });
assert(Object.isFrozen(coordinate), 'coordinate: normalised object is frozen');
assert(codeOf(() => normalizeCoordinate({ ecosystem: 'maven', name: 'acme', version: '1.0.0' })) === 'INVALID_COORDINATE', 'coordinate: unknown ecosystem refused');
assert(codeOf(() => normalizeCoordinate({ ecosystem: 'npm', name: 'Acme Parser', version: '1.0.0' })) === 'INVALID_COORDINATE', 'coordinate: malformed package name refused');
assert(codeOf(() => normalizeCoordinate({ ecosystem: 'npm', name: 'acme', version: '^1.0.0' })) === 'INVALID_COORDINATE', 'coordinate: range syntax in a version field refused');
assert(codeOf(() => normalizeCoordinate(null)) === 'INVALID_COORDINATE', 'coordinate: non-object refused');

// --- 3. matching + boundaries ----------------------------------------------
const provider = createSyntheticProvider(RECORDS);
assert(provider.providerId === 'drobon-sca-synthetic/v1', 'provider: id pinned');
assert(provider.datasetStatus === SCA_DATASET_STATUS.ASSESSED, 'provider: non-empty fixture set reports ASSESSED');

const affected = provider.assess({ ecosystem: 'npm', name: 'acme-parser', version: '4.0.5' });
assert(affected.datasetStatus === SCA_DATASET_STATUS.ASSESSED, 'assess: vulnerable version is ASSESSED');
assert(affected.advisories.length === 2, 'assess: both synthetic ranges match', JSON.stringify(affected.advisories));
assert(affected.advisories[0].id === 'DROBON-SAMPLE-001', 'assess: severity order puts HIGH before LOW');
assert(affected.advisories[1].id === 'DROBON-SAMPLE-002', 'assess: LOW follows HIGH deterministically');

const fixedBoundary = provider.assess({ ecosystem: 'npm', name: 'acme-parser', version: '4.2.1' });
assert(fixedBoundary.advisories.length === 0, 'assess: the fixed version is not affected (upper boundary)');
const branchTwo = provider.assess({ ecosystem: 'npm', name: 'acme-parser', version: '4.2.0' });
assert(branchTwo.advisories.length === 1 && branchTwo.advisories[0].fixed === '4.2.1', 'assess: a version above the second branch matches only the wide range');

const otherPackage = provider.assess({ ecosystem: 'npm', name: 'acme-other', version: '4.2.0' });
assert(otherPackage.datasetStatus === SCA_DATASET_STATUS.ASSESSED && otherPackage.advisories.length === 0, 'assess: an unknown package is ASSESSED with no advisories');
const otherEcosystem = provider.assess({ ecosystem: 'pypi', name: 'acme-parser', version: '4.2.0' });
assert(otherEcosystem.advisories.length === 0, 'assess: ecosystem is part of the key');

// pypi + duplicate range branches must yield one advisory per record
const pypi = provider.assess({ ecosystem: 'pypi', name: 'acme-client', version: '2.30.5' });
assert(pypi.datasetStatus === SCA_DATASET_STATUS.ASSESSED && pypi.advisories.length === 1, 'assess: pypi range matches exactly one advisory');
assert(pypi.advisories[0].severity === 'MEDIUM', 'assess: declared severity is passed through unchanged (no scoring)');
const pypiFixed = provider.assess({ ecosystem: 'pypi', name: 'acme-client', version: '2.31.0' });
assert(pypiFixed.advisories.length === 0, 'assess: pypi fixed version is not affected');

// --- 4. fail-closed paths ---------------------------------------------------
const emptyProvider = createSyntheticProvider([]);
const empty = emptyProvider.assess({ ecosystem: 'npm', name: 'acme-parser', version: '4.2.0' });
assert(emptyProvider.datasetStatus === SCA_DATASET_STATUS.NO_DATA_LOADED, 'fail-closed: empty record set reports NO_DATA_LOADED');
assert(empty.datasetStatus === SCA_DATASET_STATUS.NO_DATA_LOADED && empty.advisories.length === 0, 'fail-closed: no-data answer carries no advisories');

const partialVersion = provider.assess({ ecosystem: 'npm', name: 'acme-parser', version: '4.2' });
assert(
  partialVersion.datasetStatus === SCA_DATASET_STATUS.NOT_ASSESSED,
  'fail-closed: a version the range evaluator cannot parse is NOT_ASSESSED, never a match',
  partialVersion.datasetStatus,
);
assert(partialVersion.advisories.length === 0, 'fail-closed: NOT_ASSESSED never carries advisories');
assert(
  codeOf(() => provider.assess({ ecosystem: 'npm', name: 'acme-parser', version: '4.2.0-rc.1' })) === 'NO_THROW',
  'fail-closed: prerelease versions are evaluated or refused, never crash the provider',
);

// --- 5. determinism, immutability, ordering --------------------------------
const first = JSON.stringify(provider.assess({ ecosystem: 'npm', name: 'acme-parser', version: '4.0.5' }));
const second = JSON.stringify(provider.assess({ ecosystem: 'npm', name: 'acme-parser', version: '4.0.5' }));
assert(first === second, 'determinism: identical input yields byte-identical output');
assert(Object.isFrozen(provider), 'immutability: provider is frozen');
assert(Object.isFrozen(provider.assess({ ecosystem: 'npm', name: 'acme-parser', version: '4.0.5' })), 'immutability: answers are frozen');
assert(severityRank('CRITICAL') === 3 && severityRank('LOW') === 0, 'ordering: severity ranks are total for known labels');
assert(severityRank('UNKNOWN') === -1, 'ordering: unknown labels sort below known labels');

// --- 6. no network / no live feed ------------------------------------------
const engineSource = readFileSync(join(ROOT, 'scripts', 'sca-engine.mjs'), 'utf8');
const forbiddenImports = ['node:http', 'node:https', 'node:net', 'node:dns', 'node:tls', 'undici', 'axios', 'node-fetch'];
assert(
  forbiddenImports.every((needle) => !engineSource.includes(needle)),
  'no-network: the engine imports no HTTP, DNS or socket module',
  forbiddenImports.filter((needle) => engineSource.includes(needle)).join(', '),
);
assert(!/\bfetch\s*\(/.test(engineSource), 'no-network: the engine calls no fetch()');
assert(engineSource.includes('range.mjs'), 'integration: the engine reuses the validated local range evaluator');

process.stdout.write(`\nsca-engine tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) {
  process.exitCode = 1;
}
