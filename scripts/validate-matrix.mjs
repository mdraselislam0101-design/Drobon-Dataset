#!/usr/bin/env node
/**
 * Zero-dependency validator for `drobon.requirements.matrix/v1`.
 *
 * The requirements matrix is traceability, not data — but it must never
 * drift from the tree it describes. Besides the closed shape, this
 * validator RECOMPUTES every inventory count from the working tree and
 * fails on any mismatch, checks that referenced scripts/dirs exist, and
 * enforces the license-file tripwire (see
 * docs/LICENSE_DECISION_RECORD.md): a top-level LICENSE/COPYING file
 * may only land together with an updated decision record + matrix.
 *
 * Usage: node scripts/validate-matrix.mjs [matrixPath]  (default:
 * docs/REQUIREMENTS_MATRIX.json; the tree root is always the cwd)
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { checkBoundedText, hasControlChars, readJsonFile } from './validate.mjs';

export const MATRIX_SCHEMA = 'drobon.requirements.matrix/v1';

const TOP_ALLOWED = ['schemaVersion', 'app', 'inventory', 'appReferencedCwe', 'ingestionLog', 'requirements'];
const APP_CWE_PATTERN = /^CWE-[1-9][0-9]{0,5}$/;
const APP_ALLOWED = ['repo', 'branch', 'commit', 'verified'];
const INVENTORY_KEYS = [
  'vulnIntelReal',
  'vulnIntelFixtures',
  'vulnIntelNpmReal',
  'vulnIntelPypiReal',
  'packsSast',
  'packsSecrets',
  'packsDast',
  'remediation',
  'cwe',
  'patterns',
  'records',
  'lessons',
  'assessmentTemplates',
  'engagements',
  'vectors',
];
const REQ_ALLOWED = [
  'id',
  'capability',
  'engine',
  'intelType',
  'asset',
  'provenance',
  'licenseStatus',
  'schemaValidation',
  'qualityTests',
  'coverageStatus',
  'evidence',
  'notes',
];
const ENGINES = [
  'SCA',
  'SAST',
  'SECRETS',
  'DAST',
  'CWE',
  'REMEDIATION',
  'STUDENT',
  'SECURITY_PROFESSIONAL',
  'PENTESTER',
  'ASSISTANT',
  'REPORTS',
  'CROSS_ENGINE',
  'META',
];
const COVERAGE_STATUSES = [
  'VERIFIED',
  'PARTIAL',
  'PLANNED',
  'NOT_IMPLEMENTED',
  'NOT_ASSESSED',
  'NOT_REQUIRED',
  'BLOCKED_BY_DATA_LOCK',
  'BLOCKED_LICENSE_REVIEW',
];
const LICENSE_STATUSES = [
  'VERIFIED',
  'POINTER_ONLY',
  'ORIGINAL_UNLICENSED',
  'NOT_APPLICABLE',
  'BLOCKED_LICENSE_REVIEW',
];
const REQ_ID_PATTERN = /^REQ-[A-Z]{2,6}-[0-9]{2}$/;
const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const DATE_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;
const LICENSE_FILE_PATTERN = /^(LICENSE|LICENCE|COPYING)/i;

function checkClosed(errors, path, record, allowed) {
  for (const key of Object.keys(record)) {
    if (!allowed.includes(key)) {
      errors.push(`${path}: unknown property "${key}"`);
    }
  }
  for (const key of allowed) {
    if (record[key] === undefined) {
      errors.push(`${path}: missing required property "${key}"`);
    }
  }
}

function countJsonFilesFlat(dir) {
  try {
    return readdirSync(dir, { withFileTypes: true }).filter(
      (entry) => entry.isFile() && entry.name.endsWith('.json'),
    ).length;
  } catch {
    return 0;
  }
}

function collectJsonFilesRecursive(root) {
  const found = [];
  const walk = (dir) => {
    const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && entry.name.endsWith('.json') && entry.name !== 'sources.json') {
        // sources.json is registry metadata, not a record (validated by validate-sources.mjs).
        found.push(full);
      }
    }
  };
  walk(root);
  return found;
}

/**
 * Recompute the inventory section from the working tree. Returns
 * { counts, errors }: counts always has every INVENTORY_KEYS entry.
 */
export function recomputeInventory(root) {
  const errors = [];
  const counts = Object.fromEntries(INVENTORY_KEYS.map((key) => [key, 0]));
  let advisoryFiles = [];
  try {
    advisoryFiles = collectJsonFilesRecursive(join(root, 'vuln-intel'));
  } catch (err) {
    errors.push(`inventory: cannot read vuln-intel/: ${err.message}`);
  }
  for (const file of advisoryFiles) {
    const rel = relative(root, file);
    const ecosystem = rel.startsWith('vuln-intel/npm/')
      ? 'npm'
      : rel.startsWith('vuln-intel/pypi/')
        ? 'pypi'
        : null;
    if (ecosystem === null) {
      errors.push(`inventory: advisory file outside npm/ and pypi/: ${rel}`);
      continue;
    }
    let record;
    try {
      record = JSON.parse(readFileSync(file, 'utf8'));
    } catch (err) {
      errors.push(`inventory: cannot parse ${rel}: ${err.message}`);
      continue;
    }
    if (typeof record['fixture'] !== 'boolean') {
      errors.push(`inventory: ${rel} has no boolean fixture flag`);
      continue;
    }
    if (record['fixture'] === true) {
      counts.vulnIntelFixtures += 1;
    } else {
      counts.vulnIntelReal += 1;
      counts[ecosystem === 'npm' ? 'vulnIntelNpmReal' : 'vulnIntelPypiReal'] += 1;
    }
  }
  counts.packsSast = countJsonFilesFlat(join(root, 'packs', 'sast', 'v1', 'rules'));
  counts.packsSecrets = countJsonFilesFlat(join(root, 'packs', 'secrets', 'v1', 'rules'));
  counts.packsDast = countJsonFilesFlat(join(root, 'packs', 'dast', 'v1', 'rules'));
  counts.remediation = countJsonFilesFlat(join(root, 'knowledge', 'remediation'));
  counts.cwe = countJsonFilesFlat(join(root, 'knowledge', 'cwe'));
  counts.patterns = countJsonFilesFlat(join(root, 'knowledge', 'patterns'));
  counts.records = countJsonFilesFlat(join(root, 'knowledge', 'records'));
  counts.lessons = countJsonFilesFlat(join(root, 'learning', 'lessons'));
  counts.assessmentTemplates = countJsonFilesFlat(join(root, 'assessments', 'templates'));
  counts.engagements = countJsonFilesFlat(join(root, 'engagements'));
  try {
    const vectors = JSON.parse(readFileSync(join(root, 'interop', 'provider-vectors.json'), 'utf8'));
    if (!Array.isArray(vectors['vectors'])) {
      errors.push('inventory: interop/provider-vectors.json has no vectors array');
    } else {
      counts.vectors = vectors['vectors'].length;
    }
  } catch (err) {
    errors.push(`inventory: cannot read interop/provider-vectors.json: ${err.message}`);
  }
  return { counts, errors };
}

function checkScriptRef(errors, path, value, coverageStatus, root) {
  if (typeof value !== 'string' || value.length === 0) {
    errors.push(`${path}: must be a string`);
    return;
  }
  if (value === 'N/A') {
    if (coverageStatus === 'VERIFIED' || coverageStatus === 'PARTIAL') {
      errors.push(`${path}: ${coverageStatus} rows must name their validator/test script, not N/A`);
    }
    return;
  }
  if (!value.endsWith('.mjs')) {
    errors.push(`${path}: must be N/A or a scripts/*.mjs path (got "${value}")`);
    return;
  }
  try {
    const stat = statSync(join(root, value));
    if (!stat.isFile()) {
      errors.push(`${path}: script not found: ${value}`);
    }
  } catch {
    errors.push(`${path}: script not found: ${value}`);
  }
}

function checkAssetRef(errors, path, value, root) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 120) {
    errors.push(`${path}: must be a 1..120 character string`);
    return;
  }
  if (hasControlChars(value)) {
    errors.push(`${path}: must not contain control characters`);
    return;
  }
  if (value.startsWith('(')) {
    return; // Explicit "(none — ...)" / "(shared ...)" marker: no path to check.
  }
  if (value.endsWith('/')) {
    try {
      const stat = statSync(join(root, value));
      if (!stat.isDirectory()) {
        errors.push(`${path}: directory not found: ${value}`);
      }
    } catch {
      errors.push(`${path}: directory not found: ${value}`);
    }
    return;
  }
  if (value.endsWith('.mjs') || value.endsWith('.json') || value.endsWith('.md')) {
    try {
      const stat = statSync(join(root, value));
      if (!stat.isFile()) {
        errors.push(`${path}: file not found: ${value}`);
      }
    } catch {
      errors.push(`${path}: file not found: ${value}`);
    }
    return;
  }
  errors.push(`${path}: must be a repo path (dir/ ending with /, or .mjs/.json/.md file) or a (...) marker`);
}

/** Validate one parsed matrix against the tree at root. Pure except for fs reads. */
export function validateMatrix(value, root) {
  const errors = [];
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return ['matrix: must be an object'];
  }
  checkClosed(errors, 'matrix', value, TOP_ALLOWED);
  if (value['schemaVersion'] !== undefined && value['schemaVersion'] !== MATRIX_SCHEMA) {
    errors.push(`schemaVersion: must be exactly "${MATRIX_SCHEMA}"`);
  }
  if (value['app'] !== undefined) {
    const app = value['app'];
    if (typeof app !== 'object' || app === null || Array.isArray(app)) {
      errors.push('app: must be an object');
    } else {
      checkClosed(errors, 'app', app, APP_ALLOWED);
      if (app['repo'] !== undefined) checkBoundedText(errors, 'app.repo', app['repo'], 120);
      if (app['branch'] !== undefined) checkBoundedText(errors, 'app.branch', app['branch'], 120);
      if (app['commit'] !== undefined) {
        if (typeof app['commit'] !== 'string' || !COMMIT_PATTERN.test(app['commit'])) {
          errors.push('app.commit: must be a 40-char lowercase hex commit hash');
        }
      }
      if (app['verified'] !== undefined) {
        if (typeof app['verified'] !== 'string' || !DATE_PATTERN.test(app['verified'])) {
          errors.push('app.verified: must be a YYYY-MM-DD date');
        }
      }
    }
  }
  if (value['inventory'] !== undefined) {
    const inventory = value['inventory'];
    if (typeof inventory !== 'object' || inventory === null || Array.isArray(inventory)) {
      errors.push('inventory: must be an object');
    } else {
      checkClosed(errors, 'inventory', inventory, INVENTORY_KEYS);
      for (const key of INVENTORY_KEYS) {
        const claimed = inventory[key];
        if (claimed !== undefined && (!Number.isInteger(claimed) || claimed < 0)) {
          errors.push(`inventory.${key}: must be an integer >= 0`);
        }
      }
      const recomputed = recomputeInventory(root);
      errors.push(...recomputed.errors);
      if (recomputed.errors.length === 0) {
        for (const key of INVENTORY_KEYS) {
          if (
            Number.isInteger(inventory[key]) &&
            inventory[key] !== recomputed.counts[key]
          ) {
            errors.push(
              `inventory.${key}: matrix claims ${inventory[key]}, tree recompute found ${recomputed.counts[key]}`,
            );
          }
        }
      }
    }
  }
  if (value['appReferencedCwe'] !== undefined) {
    const pin = value['appReferencedCwe'];
    if (!Array.isArray(pin)) {
      errors.push('appReferencedCwe: must be an array');
    } else {
      pin.forEach((id, index) => {
        if (typeof id !== 'string' || !APP_CWE_PATTERN.test(id)) {
          errors.push(`appReferencedCwe[${index}]: must match ^CWE-[1-9][0-9]{0,5}$`);
          return;
        }
        try {
          const stat = statSync(join(root, 'knowledge', 'cwe', `${id}.json`));
          if (!stat.isFile()) {
            errors.push(`appReferencedCwe[${index}]: unresolved — no knowledge/cwe/${id}.json`);
          }
        } catch {
          errors.push(`appReferencedCwe[${index}]: unresolved — no knowledge/cwe/${id}.json`);
        }
      });
    }
  }
  if (value['ingestionLog'] !== undefined) {
    const log = value['ingestionLog'];
    if (!Array.isArray(log)) {
      errors.push('ingestionLog: must be an array');
    } else {
      if (log.length > 200) {
        errors.push(`ingestionLog: must have 0..200 rows (got ${log.length})`);
      }
      const LOG_ALLOWED = ['date', 'source', 'count', 'reviewer', 'licenseBasis'];
      log.forEach((row, index) => {
        const path = `ingestionLog[${index}]`;
        if (typeof row !== 'object' || row === null || Array.isArray(row)) {
          errors.push(`${path}: must be an object`);
          return;
        }
        checkClosed(errors, path, row, LOG_ALLOWED);
        if (row['date'] !== undefined && (typeof row['date'] !== 'string' || !DATE_PATTERN.test(row['date']))) {
          errors.push(`${path}.date: must be a YYYY-MM-DD date`);
        }
        if (row['source'] !== undefined) checkBoundedText(errors, `${path}.source`, row['source'], 64);
        if (row['count'] !== undefined && (!Number.isInteger(row['count']) || row['count'] < 1)) {
          errors.push(`${path}.count: must be an integer >= 1`);
        }
        if (row['reviewer'] !== undefined) checkBoundedText(errors, `${path}.reviewer`, row['reviewer'], 120);
        if (row['licenseBasis'] !== undefined) {
          checkBoundedText(errors, `${path}.licenseBasis`, row['licenseBasis'], 300);
        }
      });
    }
  }
  if (value['requirements'] !== undefined) {
    const requirements = value['requirements'];
    if (!Array.isArray(requirements)) {
      errors.push('requirements: must be an array');
    } else {
      if (requirements.length < 1 || requirements.length > 200) {
        errors.push(`requirements: must have 1..200 rows (got ${requirements.length})`);
      }
      const seenIds = new Set();
      requirements.forEach((row, index) => {
        const path = `requirements[${index}]`;
        if (typeof row !== 'object' || row === null || Array.isArray(row)) {
          errors.push(`${path}: must be an object`);
          return;
        }
        checkClosed(errors, path, row, REQ_ALLOWED);
        if (row['id'] !== undefined) {
          if (typeof row['id'] !== 'string' || !REQ_ID_PATTERN.test(row['id'])) {
            errors.push(`${path}.id: must match ^REQ-[A-Z]{2,6}-[0-9]{2}$`);
          } else if (seenIds.has(row['id'])) {
            errors.push(`${path}.id: duplicate requirement id "${row['id']}"`);
          } else {
            seenIds.add(row['id']);
          }
        }
        if (row['capability'] !== undefined) checkBoundedText(errors, `${path}.capability`, row['capability'], 200);
        if (row['engine'] !== undefined && !ENGINES.includes(row['engine'])) {
          errors.push(`${path}.engine: must be one of ${ENGINES.join(', ')}`);
        }
        if (row['intelType'] !== undefined) checkBoundedText(errors, `${path}.intelType`, row['intelType'], 60);
        if (row['asset'] !== undefined) checkAssetRef(errors, `${path}.asset`, row['asset'], root);
        if (row['provenance'] !== undefined) checkBoundedText(errors, `${path}.provenance`, row['provenance'], 300);
        if (row['licenseStatus'] !== undefined && !LICENSE_STATUSES.includes(row['licenseStatus'])) {
          errors.push(`${path}.licenseStatus: must be one of ${LICENSE_STATUSES.join(', ')}`);
        }
        if (row['schemaValidation'] !== undefined) {
          checkScriptRef(errors, `${path}.schemaValidation`, row['schemaValidation'], row['coverageStatus'], root);
        }
        if (row['qualityTests'] !== undefined) {
          checkScriptRef(errors, `${path}.qualityTests`, row['qualityTests'], row['coverageStatus'], root);
        }
        if (row['coverageStatus'] !== undefined && !COVERAGE_STATUSES.includes(row['coverageStatus'])) {
          errors.push(`${path}.coverageStatus: must be one of ${COVERAGE_STATUSES.join(', ')}`);
        }
        if (row['evidence'] !== undefined) {
          if (!Array.isArray(row['evidence'])) {
            errors.push(`${path}.evidence: must be an array`);
          } else {
            if (row['evidence'].length < 1 || row['evidence'].length > 20) {
              errors.push(`${path}.evidence: must have 1..20 entries (got ${row['evidence'].length})`);
            }
            row['evidence'].forEach((item, itemIndex) => {
              checkBoundedText(errors, `${path}.evidence[${itemIndex}]`, item, 300);
            });
          }
        }
        if (row['notes'] !== undefined) checkBoundedText(errors, `${path}.notes`, row['notes'], 1000);
      });
    }
  }
  // License-file tripwire: a grant may only land with an updated record + matrix.
  try {
    const rootEntries = readdirSync(root, { withFileTypes: true });
    for (const entry of rootEntries) {
      if (entry.isFile() && LICENSE_FILE_PATTERN.test(entry.name)) {
        errors.push(
          `license tripwire: ${entry.name} is present — update docs/LICENSE_DECISION_RECORD.md (grant recorded), ` +
            'docs/REQUIREMENTS_MATRIX.json (licenseStatus), and this tripwire in the same commit',
        );
      }
    }
  } catch (err) {
    errors.push(`license tripwire: cannot read root: ${err.message}`);
  }
  return errors;
}

export function validateMatrixPath(filePath, root) {
  const loaded = readJsonFile(filePath);
  if (loaded.errors !== undefined) return loaded.errors;
  return validateMatrix(loaded.value, root).map((error) => `${filePath}: ${error}`);
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (invokedAsScript) {
  const targets = process.argv.slice(2);
  const matrixPath = resolve(
    process.cwd(),
    targets.length > 0 ? targets[0] : 'docs/REQUIREMENTS_MATRIX.json',
  );
  const failures = validateMatrixPath(matrixPath, process.cwd());
  for (const failure of failures) {
    process.stdout.write(`${failure}\n`);
  }
  if (failures.length > 0) {
    process.stdout.write(`validate-matrix: FAIL (${failures.length} errors)\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write('validate-matrix: PASS (matrix valid, inventory recomputed, no license file)\n');
  }
}
