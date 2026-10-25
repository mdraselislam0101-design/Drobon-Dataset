/**
 * Zero-dependency validator for the 100K corpus planning artifacts.
 *
 * Validates docs/CORPUS_TARGETS.json (category inventory + counts) and
 * docs/SOURCE_ROADMAP.json (source-by-source roadmap), recomputing every
 * COUNTED validatedCount from the repository files. Planning-stage honesty
 * rules are enforced, not documented:
 * - validated counts must equal recomputed counts (no stale/inflated claims);
 * - verifiedProduction counts must be 0 while no LICENSE grant exists;
 * - the roadmap may not quote volumes (volumeEstimate must stay null) and
 *   may not claim redistribution VERIFIED (nothing is verified under the lock).
 *
 * Usage:
 *   node scripts/validate-corpus.mjs [targetsPath] [roadmapPath] [decisionsPath]
 *   (defaults: docs/CORPUS_TARGETS.json docs/SOURCE_ROADMAP.json docs/OWNER_DECISIONS.json)
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { countAdvisoryItems } from './dedup-report.mjs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { hasControlChars } from './validate.mjs';

export const TARGETS_SCHEMA_VERSION = 'drobon.corpus.targets/v1';
export const ROADMAP_SCHEMA_VERSION = 'drobon.corpus.roadmap/v1';
export const DECISIONS_SCHEMA_VERSION = 'drobon.corpus.decisions/v1';
export const CORPUS_TARGET_MIN = 100000;
export const COUNTING_POLICY_PATH = 'docs/COUNTING_POLICY.md';

const CATEGORY_ID_PATTERN = /^[a-z0-9-]+$/;
const CATEGORY_STATUSES = ['COUNTED', 'EXCLUDED'];
const LICENSE_STATUSES = ['BLOCKED_LICENSE_REVIEW', 'ORIGINAL_UNLICENSED', 'NOT_APPLICABLE'];
const SOURCE_STATUSES = ['IN_USE_AS_SEED', 'IN_USE', 'PLANNED', 'REFERENCED', 'UNASSESSED'];
const SOURCE_LICENSE_STATUSES = ['VERIFIED_ALLOWED', 'RESTRICTED', 'BLOCKED_UNVERIFIED', 'ORIGINAL_UNLICENSED', 'NOT_APPLICABLE'];
const LICENSE_FILE_PATTERN = /^(LICENSE|LICENCE|COPYING)/i;
const DECISION_STATUSES = ['OWNER_DECISION_REQUIRED', 'APPROVED', 'REJECTED'];
const DECISION_SUBJECT_PATTERN = /^[A-Z][A-Z0-9_]*$/;
const DECISION_DATE_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;

function checkText(errors, path, value, max) {
  if (typeof value !== 'string') {
    errors.push(`${path}: must be a string`);
    return;
  }
  if (value.length < 1 || value.length > max) {
    errors.push(`${path}: must be 1..${max} characters`);
    return;
  }
  if (hasControlChars(value)) {
    errors.push(`${path}: must not contain control characters`);
  }
}

function checkClosed(errors, path, value, allowed) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      errors.push(`${path}: unknown property "${key}"`);
    }
  }
}

function checkHttpsUrl(errors, path, value, max) {
  checkText(errors, path, value, max);
  if (typeof value === 'string' && value.length > 0 && !value.startsWith('https://')) {
    errors.push(`${path}: must start with https://`);
  }
}

function readJson(file) {
  return JSON.parse(readFileSync(file, 'utf8'));
}

function countFlatJsonFiles(dir) {
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.json'))
    .length;
}

function hasLicenseFile(root) {
  try {
    return readdirSync(root, { withFileTypes: true }).some(
      (entry) => entry.isFile() && LICENSE_FILE_PATTERN.test(entry.name),
    );
  } catch {
    return false;
  }
}

function recomputeCategory(root, id) {
  switch (id) {
    case 'advisory-record':
      // Items, not files: same-tuple shards collapse to one (COUNTING_POLICY.md section 1).
      return countAdvisoryItems(root);
    case 'sast-rule':
      return countFlatJsonFiles(join(root, 'packs', 'sast', 'v1', 'rules'));
    case 'secrets-rule':
      return countFlatJsonFiles(join(root, 'packs', 'secrets', 'v1', 'rules'));
    case 'dast-check':
      return countFlatJsonFiles(join(root, 'packs', 'dast', 'v1', 'rules'));
    case 'sca-rule':
      return countFlatJsonFiles(join(root, 'packs', 'sca', 'v1', 'rules'));
    case 'cwe-entry':
      return countFlatJsonFiles(join(root, 'knowledge', 'cwe'));
    case 'remediation-entry':
      return countFlatJsonFiles(join(root, 'knowledge', 'remediation'));
    case 'lesson':
      return countFlatJsonFiles(join(root, 'learning', 'lessons'));
    case 'assessment-template':
      return countFlatJsonFiles(join(root, 'assessments', 'templates'));
    case 'engagement-aid':
      return countFlatJsonFiles(join(root, 'engagements'));
    case 'provider-vector': {
      const doc = readJson(join(root, 'interop', 'provider-vectors.json'));
      if (!Array.isArray(doc.vectors)) throw new Error('interop/provider-vectors.json: vectors must be an array');
      return doc.vectors.length;
    }
    default:
      throw new Error(`unknown COUNTED category "${id}" (extend recomputeCategory before adding categories)`);
  }
}

const TARGETS_TOP_ALLOWED = ['schemaVersion', 'targetMinUniqueItems', 'countingPolicy', 'verifiedProductionDefinition', 'categories', 'totals'];
const CATEGORY_ALLOWED = ['id', 'status', 'identityKey', 'asset', 'validatedCount', 'verifiedProductionCount', 'licenseStatus', 'appConsumer', 'notes', 'evidence'];

function validateTargetsDoc(doc, root, errors) {
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    errors.push('targets: must be an object');
    return;
  }
  checkClosed(errors, 'targets', doc, TARGETS_TOP_ALLOWED);
  if (doc['schemaVersion'] !== TARGETS_SCHEMA_VERSION) {
    errors.push(`targets.schemaVersion: must be "${TARGETS_SCHEMA_VERSION}"`);
  }
  if (!Number.isInteger(doc['targetMinUniqueItems']) || doc['targetMinUniqueItems'] < CORPUS_TARGET_MIN) {
    errors.push(`targets.targetMinUniqueItems: must be an integer >= ${CORPUS_TARGET_MIN}`);
  }
  if (doc['countingPolicy'] !== COUNTING_POLICY_PATH) {
    errors.push(`targets.countingPolicy: must be "${COUNTING_POLICY_PATH}"`);
  } else if (!existsSync(join(root, COUNTING_POLICY_PATH))) {
    errors.push(`targets.countingPolicy: ${COUNTING_POLICY_PATH} does not exist`);
  }
  if (doc['verifiedProductionDefinition'] !== undefined) {
    checkText(errors, 'targets.verifiedProductionDefinition', doc['verifiedProductionDefinition'], 600);
  }
  const categories = Array.isArray(doc['categories']) ? doc['categories'] : [];
  if (!Array.isArray(doc['categories']) || categories.length < 1) {
    errors.push('targets.categories: must be a non-empty array');
  }
  const seen = new Set();
  let validatedSum = 0;
  let verifiedSum = 0;
  const licensed = hasLicenseFile(root);
  categories.forEach((category, index) => {
    const path = `categories[${index}]`;
    if (typeof category !== 'object' || category === null || Array.isArray(category)) {
      errors.push(`${path}: must be an object`);
      return;
    }
    checkClosed(errors, path, category, CATEGORY_ALLOWED);
    if (typeof category['id'] !== 'string' || !CATEGORY_ID_PATTERN.test(category['id'])) {
      errors.push(`${path}.id: must match ^[a-z0-9-]+$`);
    } else if (seen.has(category['id'])) {
      errors.push(`${path}.id: duplicate category "${category['id']}"`);
    } else {
      seen.add(category['id']);
    }
    if (!CATEGORY_STATUSES.includes(category['status'])) {
      errors.push(`${path}.status: must be one of ${CATEGORY_STATUSES.join(', ')}`);
    }
    const keys = Array.isArray(category['identityKey']) ? category['identityKey'] : null;
    if (keys === null) {
      errors.push(`${path}.identityKey: must be an array`);
    } else if (category['status'] === 'COUNTED') {
      if (keys.length < 1 || keys.length > 6 || !keys.every((key) => typeof key === 'string' && key.length >= 1 && key.length <= 40)) {
        errors.push(`${path}.identityKey: COUNTED categories need 1..6 key names`);
      }
    } else if (keys.length !== 0) {
      errors.push(`${path}.identityKey: EXCLUDED categories must use []`);
    }
    checkText(errors, `${path}.asset`, category['asset'], 120);
    if (!Number.isInteger(category['validatedCount']) || category['validatedCount'] < 0) {
      errors.push(`${path}.validatedCount: must be an integer >= 0`);
    }
    if (!Number.isInteger(category['verifiedProductionCount']) || category['verifiedProductionCount'] < 0) {
      errors.push(`${path}.verifiedProductionCount: must be an integer >= 0`);
    } else if (
      Number.isInteger(category['validatedCount']) &&
      category['verifiedProductionCount'] > category['validatedCount']
    ) {
      errors.push(`${path}.verifiedProductionCount: must not exceed validatedCount`);
    } else if (!licensed && category['verifiedProductionCount'] > 0) {
      errors.push(`${path}.verifiedProductionCount: must be 0 while no LICENSE grant exists (verified production requires license verification)`);
    }
    if (!LICENSE_STATUSES.includes(category['licenseStatus'])) {
      errors.push(`${path}.licenseStatus: must be one of ${LICENSE_STATUSES.join(', ')}`);
    }
    checkText(errors, `${path}.appConsumer`, category['appConsumer'], 200);
    checkText(errors, `${path}.notes`, category['notes'], 600);
    if (category['status'] === 'EXCLUDED') {
      if (!Array.isArray(category['evidence']) || category['evidence'].length < 1 || category['evidence'].length > 4) {
        errors.push(`${path}.evidence: EXCLUDED categories need 1..4 evidence strings`);
      } else {
        category['evidence'].forEach((line, lineIndex) => checkText(errors, `${path}.evidence[${lineIndex}]`, line, 300));
      }
    } else if (category['evidence'] !== undefined) {
      errors.push(`${path}.evidence: only EXCLUDED categories carry evidence`);
    }
    if (category['status'] === 'COUNTED' && Number.isInteger(category['validatedCount'])) {
      try {
        const recomputed = recomputeCategory(root, category['id']);
        if (category['validatedCount'] !== recomputed) {
          errors.push(`${path}.validatedCount: claims ${category['validatedCount']} but recompute finds ${recomputed}`);
        }
      } catch (err) {
        errors.push(`${path}.validatedCount: recompute failed (${err.message})`);
      }
    } else if (category['status'] === 'EXCLUDED' && category['validatedCount'] !== 0) {
      errors.push(`${path}.validatedCount: EXCLUDED categories must claim 0`);
    }
    if (Number.isInteger(category['validatedCount'])) validatedSum += category['validatedCount'];
    if (Number.isInteger(category['verifiedProductionCount'])) verifiedSum += category['verifiedProductionCount'];
  });
  const totals = doc['totals'];
  if (typeof totals !== 'object' || totals === null || Array.isArray(totals)) {
    errors.push('targets.totals: must be an object');
    return;
  }
  checkClosed(errors, 'targets.totals', totals, ['validated', 'verifiedProduction']);
  if (totals['validated'] !== validatedSum) {
    errors.push(`targets.totals.validated: claims ${String(totals['validated'])} but categories sum to ${validatedSum}`);
  }
  if (totals['verifiedProduction'] !== verifiedSum) {
    errors.push(`targets.totals.verifiedProduction: claims ${String(totals['verifiedProduction'])} but categories sum to ${verifiedSum}`);
  }
}

const ROADMAP_TOP_ALLOWED = ['schemaVersion', 'note', 'sources'];
const SOURCE_ALLOWED = ['name', 'url', 'categories', 'volumeEstimate', 'estimateBasis', 'license', 'attribution', 'retrieval', 'dedupKeys', 'validation', 'provenance', 'appConsumer', 'status', 'statusEvidence', 'gaps'];

function validateRoadmapDoc(doc, root, errors) {
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    errors.push('roadmap: must be an object');
    return;
  }
  checkClosed(errors, 'roadmap', doc, ROADMAP_TOP_ALLOWED);
  if (doc['schemaVersion'] !== ROADMAP_SCHEMA_VERSION) {
    errors.push(`roadmap.schemaVersion: must be "${ROADMAP_SCHEMA_VERSION}"`);
  }
  if (doc['note'] !== undefined) checkText(errors, 'roadmap.note', doc['note'], 600);
  const sources = Array.isArray(doc['sources']) ? doc['sources'] : [];
  if (!Array.isArray(doc['sources']) || sources.length < 1) {
    errors.push('roadmap.sources: must be a non-empty array');
  }
  const seen = new Set();
  sources.forEach((source, index) => {
    const path = `sources[${index}]`;
    if (typeof source !== 'object' || source === null || Array.isArray(source)) {
      errors.push(`${path}: must be an object`);
      return;
    }
    checkClosed(errors, path, source, SOURCE_ALLOWED);
    checkText(errors, `${path}.name`, source['name'], 120);
    if (typeof source['name'] === 'string') {
      if (seen.has(source['name'])) errors.push(`${path}.name: duplicate source "${source['name']}"`);
      seen.add(source['name']);
    }
    checkHttpsUrl(errors, `${path}.url`, source['url'], 200);
    if (!Array.isArray(source['categories']) || source['categories'].length < 1 || source['categories'].length > 8) {
      errors.push(`${path}.categories: must be an array of 1..8 category ids`);
    } else {
      source['categories'].forEach((id, idIndex) => {
        if (typeof id !== 'string' || !CATEGORY_ID_PATTERN.test(id)) {
          errors.push(`${path}.categories[${idIndex}]: must match ^[a-z0-9-]+$`);
        }
      });
    }
    if (source['volumeEstimate'] !== null) {
      errors.push(`${path}.volumeEstimate: must stay null at the planning stage (measure at staging before quoting any volume)`);
    }
    checkText(errors, `${path}.estimateBasis`, source['estimateBasis'], 500);
    const license = source['license'];
    if (typeof license !== 'object' || license === null || Array.isArray(license)) {
      errors.push(`${path}.license: must be an object`);
    } else {
      checkClosed(errors, `${path}.license`, license, ['status', 'evidence']);
      if (!SOURCE_LICENSE_STATUSES.includes(license['status'])) {
        errors.push(`${path}.license.status: "${String(license['status'])}" is rejected at the planning stage (redistribution unverified under the data lock)`);
      }
      checkText(errors, `${path}.license.evidence`, license['evidence'], 500);
    }
    checkText(errors, `${path}.attribution`, source['attribution'], 500);
    const retrieval = source['retrieval'];
    if (typeof retrieval !== 'object' || retrieval === null || Array.isArray(retrieval)) {
      errors.push(`${path}.retrieval: must be an object`);
    } else {
      checkClosed(errors, `${path}.retrieval`, retrieval, ['method', 'cadence']);
      checkText(errors, `${path}.retrieval.method`, retrieval['method'], 300);
      checkText(errors, `${path}.retrieval.cadence`, retrieval['cadence'], 300);
    }
    if (!Array.isArray(source['dedupKeys']) || source['dedupKeys'].length < 1 || source['dedupKeys'].length > 6) {
      errors.push(`${path}.dedupKeys: must be an array of 1..6 key names`);
    }
    checkText(errors, `${path}.validation`, source['validation'], 500);
    checkText(errors, `${path}.provenance`, source['provenance'], 500);
    checkText(errors, `${path}.appConsumer`, source['appConsumer'], 200);
    if (!SOURCE_STATUSES.includes(source['status'])) {
      errors.push(`${path}.status: must be one of ${SOURCE_STATUSES.join(', ')}`);
    }
    checkText(errors, `${path}.statusEvidence`, source['statusEvidence'], 500);
    if (!Array.isArray(source['gaps']) || source['gaps'].length > 8) {
      errors.push(`${path}.gaps: must be an array of 0..8 strings`);
    } else {
      source['gaps'].forEach((gap, gapIndex) => checkText(errors, `${path}.gaps[${gapIndex}]`, gap, 300));
    }
  });
}

function validatePair(targetsDoc, roadmapDoc, errors) {
  if (targetsDoc === null || roadmapDoc === null) return;
  const known = new Set(
    (Array.isArray(targetsDoc['categories']) ? targetsDoc['categories'] : [])
      .filter((category) => typeof category?.id === 'string')
      .map((category) => category.id),
  );
  const counted = new Set(
    (Array.isArray(targetsDoc['categories']) ? targetsDoc['categories'] : [])
      .filter((category) => category?.status === 'COUNTED' && typeof category?.id === 'string')
      .map((category) => category.id),
  );
  const covered = new Set();
  (Array.isArray(roadmapDoc['sources']) ? roadmapDoc['sources'] : []).forEach((source, index) => {
    (Array.isArray(source?.categories) ? source.categories : []).forEach((id) => {
      if (typeof id === 'string' && !known.has(id)) {
        errors.push(`sources[${index}].categories: unknown corpus category "${id}"`);
      }
      if (typeof id === 'string' && counted.has(id) && source?.status !== 'UNASSESSED') {
        covered.add(id);
      }
    });
  });
  for (const id of counted) {
    if (!covered.has(id)) {
      errors.push(`pair: COUNTED category "${id}" has no non-UNASSESSED roadmap source`);
    }
  }
}

function validateDecisionsDoc(doc, errors) {
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    errors.push('decisions: must be an object');
    return;
  }
  checkClosed(errors, 'decisions', doc, ['schemaVersion', 'note', 'decisions']);
  if (doc['schemaVersion'] !== DECISIONS_SCHEMA_VERSION) {
    errors.push('decisions.schemaVersion: must be "' + DECISIONS_SCHEMA_VERSION + '"');
  }
  if (doc['note'] !== undefined) {
    checkText(errors, 'decisions.note', doc['note'], 600);
  }
  if (!Array.isArray(doc['decisions']) || doc['decisions'].length < 1) {
    errors.push('decisions.decisions: must be a non-empty array');
    return;
  }
  const subjects = new Set();
  doc['decisions'].forEach((entry, index) => {
    const path = 'decisions[' + index + ']';
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      errors.push(path + ': must be an object');
      return;
    }
    checkClosed(errors, path, entry, ['subject', 'roadmapSource', 'licenseOrTerms', 'evidenceUrl', 'evidenceDate', 'attribution', 'redistribution', 'commercialUse', 'requiredDecision', 'status', 'decidedAt', 'decider', 'reviewer', 'eligibleScope']);
    if (typeof entry['subject'] !== 'string' || !DECISION_SUBJECT_PATTERN.test(entry['subject']) || entry['subject'].length > 40) {
      errors.push(path + '.subject: must match [A-Z][A-Z0-9_]* (1..40 chars)');
    } else if (subjects.has(entry['subject'])) {
      errors.push(path + '.subject: duplicate subject "' + entry['subject'] + '"');
    } else {
      subjects.add(entry['subject']);
    }
    checkText(errors, path + '.roadmapSource', entry['roadmapSource'], 120);
    for (const field of ['licenseOrTerms', 'attribution', 'redistribution', 'commercialUse', 'requiredDecision', 'reviewer', 'eligibleScope']) {
      checkText(errors, path + '.' + field, entry[field], 500);
    }
    checkHttpsUrl(errors, path + '.evidenceUrl', entry['evidenceUrl'], 300);
    if (typeof entry['evidenceDate'] !== 'string' || !DECISION_DATE_PATTERN.test(entry['evidenceDate'])) {
      errors.push(path + '.evidenceDate: must be YYYY-MM-DD');
    }
    if (!DECISION_STATUSES.includes(entry['status'])) {
      errors.push(path + '.status: must be one of ' + DECISION_STATUSES.join(', '));
    }
    if (entry['status'] === 'OWNER_DECISION_REQUIRED') {
      if (entry['decidedAt'] !== null) {
        errors.push(path + '.decidedAt: undecided entries must use null (no fabricated dates)');
      }
      if (entry['decider'] !== null) {
        errors.push(path + '.decider: undecided entries must use null (no fabricated approval)');
      }
    } else if (DECISION_STATUSES.includes(entry['status'])) {
      if (typeof entry['decidedAt'] !== 'string' || !DECISION_DATE_PATTERN.test(entry['decidedAt'])) {
        errors.push(path + '.decidedAt: decided entries need a YYYY-MM-DD decision date');
      }
      checkText(errors, path + '.decider', entry['decider'], 120);
    }
  });
}

function validateDecisionsVsRoadmap(decisionsDoc, roadmapDoc, errors) {
  if (decisionsDoc === null || roadmapDoc === null) return;
  const names = new Set(
    (Array.isArray(roadmapDoc['sources']) ? roadmapDoc['sources'] : [])
      .filter((source) => typeof source?.name === 'string')
      .map((source) => source.name),
  );
  const referenced = new Set();
  (Array.isArray(decisionsDoc['decisions']) ? decisionsDoc['decisions'] : []).forEach((entry, index) => {
    if (typeof entry?.roadmapSource !== 'string') return;
    referenced.add(entry.roadmapSource);
    if (!names.has(entry.roadmapSource)) {
      errors.push('decisions[' + index + '].roadmapSource: unknown roadmap source "' + entry.roadmapSource + '"');
    }
  });
  for (const name of names) {
    if (!referenced.has(name)) {
      errors.push('set: roadmap source "' + name + '" has no owner-decision entry');
    }
  }
}

export function validateDecisionsPath(decisionsPath) {
  let doc = null;
  try {
    doc = readJson(decisionsPath);
  } catch (err) {
    return [decisionsPath + ': cannot parse (' + err.message + ')'];
  }
  const errors = [];
  validateDecisionsDoc(doc, errors);
  return errors.map((message) => decisionsPath + ': ' + message);
}

export function validateCorpusTargetsPath(targetsPath, root = process.cwd()) {
  const errors = [];
  let doc = null;
  try {
    doc = readJson(targetsPath);
  } catch (err) {
    return [`${targetsPath}: cannot parse (${err.message})`];
  }
  const local = [];
  validateTargetsDoc(doc, root, local);
  return local.map((message) => `${targetsPath}: ${message}`);
}

export function validateRoadmapPath(roadmapPath) {
  const errors = [];
  let doc = null;
  try {
    doc = readJson(roadmapPath);
  } catch (err) {
    return [`${roadmapPath}: cannot parse (${err.message})`];
  }
  validateRoadmapDoc(doc, process.cwd(), errors);
  return errors.map((message) => `${roadmapPath}: ${message}`);
}

export function validateCorpusSet(targetsPath, roadmapPath, decisionsPath, root = process.cwd()) {
  const errors = [
    ...validateCorpusTargetsPath(targetsPath, root),
    ...validateRoadmapPath(roadmapPath),
    ...validateDecisionsPath(decisionsPath),
  ];
  let targetsDoc = null;
  let roadmapDoc = null;
  let decisionsDoc = null;
  const slots = [[targetsPath, 'targets'], [roadmapPath, 'roadmap'], [decisionsPath, 'decisions']];
  for (const [file, slot] of slots) {
    try {
      const doc = readJson(file);
      if (slot === 'targets') targetsDoc = doc;
      else if (slot === 'roadmap') roadmapDoc = doc;
      else decisionsDoc = doc;
    } catch {
      // Parse failures are already reported by the per-file validators above.
    }
  }
  const setErrors = [];
  validatePair(targetsDoc, roadmapDoc, setErrors);
  validateDecisionsVsRoadmap(decisionsDoc, roadmapDoc, setErrors);
  return [...errors, ...setErrors.map((message) => 'pair: ' + message)];
}

export function validateCorpusPair(targetsPath, roadmapPath, root = process.cwd()) {
  const errors = [...validateCorpusTargetsPath(targetsPath, root), ...validateRoadmapPath(roadmapPath)];
  let targetsDoc = null;
  let roadmapDoc = null;
  try {
    targetsDoc = readJson(targetsPath);
  } catch {
    targetsDoc = null;
  }
  try {
    roadmapDoc = readJson(roadmapPath);
  } catch {
    roadmapDoc = null;
  }
  const pairErrors = [];
  validatePair(targetsDoc, roadmapDoc, pairErrors);
  return [...errors, ...pairErrors.map((message) => `pair: ${message}`)];
}

function main(argv) {
  const root = process.cwd();
  const targetsPath = resolve(root, argv[2] ?? 'docs/CORPUS_TARGETS.json');
  const roadmapPath = resolve(root, argv[3] ?? 'docs/SOURCE_ROADMAP.json');
  const decisionsPath = resolve(root, argv[4] ?? 'docs/OWNER_DECISIONS.json');
  const failures = validateCorpusSet(targetsPath, roadmapPath, decisionsPath, root);
  if (failures.length > 0) {
    for (const failure of failures) process.stdout.write(`${failure}\n`);
    process.stdout.write(`validate-corpus: FAIL (3 files, ${failures.length} errors)\n`);
    return 1;
  }
  process.stdout.write('validate-corpus: PASS (3 files, 0 errors)\n');
  return 0;
}

const invokedAsScript = (() => {
  try {
    return pathToFileURL(resolve(process.argv[1] ?? '')).href === import.meta.url;
  } catch {
    return false;
  }
})();

if (invokedAsScript) {
  process.exit(main(process.argv));
}
