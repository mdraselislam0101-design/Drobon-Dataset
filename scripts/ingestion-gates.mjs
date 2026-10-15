/**
 * Fail-closed enforcement for the four INGESTION_PLAN authorization gates.
 *
 * Importers call requireGates() at startup: any BLOCKED gate, any malformed
 * gate file, or any missing evidence blocks production ingestion with a loud
 * error. This module self-validates the gate file (closed shape, ordered ids,
 * SATISFIED requires decidedAt + evidence) so a corrupt file can never read
 * as approval.
 *
 * Usage (humans): node scripts/ingestion-gates.mjs   (exit 0 open / 1 blocked)
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const GATES_SCHEMA_VERSION = 'drobon.ingestion.gates/v1';
export const GATE_IDS = ['GATE-1', 'GATE-2', 'GATE-3', 'GATE-4'];
export const GATE_STATUSES = ['BLOCKED', 'SATISFIED'];
export const DEFAULT_GATES_PATH = 'docs/INGESTION_GATES.json';

const TOP_ALLOWED = ['schemaVersion', 'note', 'gates'];
const GATE_ALLOWED = ['id', 'title', 'evidenceRequired', 'validator', 'passCriteria', 'owner', 'status', 'statusEvidence', 'decidedAt'];
const DATE_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;

function isNonEmptyText(value, max) {
  return typeof value === 'string' && value.length >= 1 && value.length <= max;
}

/** Structural validation of a parsed gate file. Returns string[] errors. */
export function validateGatesDoc(doc) {
  const errors = [];
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    return ['gates: must be an object'];
  }
  for (const key of Object.keys(doc)) {
    if (!TOP_ALLOWED.includes(key)) errors.push(`gates: unknown property "${key}"`);
  }
  if (doc['schemaVersion'] !== GATES_SCHEMA_VERSION) {
    errors.push(`gates.schemaVersion: must be "${GATES_SCHEMA_VERSION}"`);
  }
  if (doc['note'] !== undefined && !isNonEmptyText(doc['note'], 600)) {
    errors.push('gates.note: must be 1..600 characters');
  }
  const gates = Array.isArray(doc['gates']) ? doc['gates'] : null;
  if (gates === null) {
    errors.push('gates.gates: must be an array');
    return errors;
  }
  if (gates.length !== GATE_IDS.length) {
    errors.push(`gates.gates: must have exactly ${GATE_IDS.length} gates (got ${gates.length})`);
  }
  gates.forEach((gate, index) => {
    const path = `gates[${index}]`;
    if (typeof gate !== 'object' || gate === null || Array.isArray(gate)) {
      errors.push(`${path}: must be an object`);
      return;
    }
    for (const key of Object.keys(gate)) {
      if (!GATE_ALLOWED.includes(key)) errors.push(`${path}: unknown property "${key}"`);
    }
    if (gate['id'] !== GATE_IDS[index]) {
      errors.push(`${path}.id: must be "${GATE_IDS[index] ?? '(none)'}" in order`);
    }
    for (const field of ['title', 'evidenceRequired', 'validator', 'passCriteria', 'owner']) {
      if (!isNonEmptyText(gate[field], 500)) errors.push(`${path}.${field}: must be 1..500 characters`);
    }
    if (!GATE_STATUSES.includes(gate['status'])) {
      errors.push(`${path}.status: must be one of ${GATE_STATUSES.join(', ')}`);
    }
    if (!isNonEmptyText(gate['statusEvidence'], 500)) {
      errors.push(`${path}.statusEvidence: must be 1..500 characters`);
    }
    if (gate['status'] === 'SATISFIED') {
      if (typeof gate['decidedAt'] !== 'string' || !DATE_PATTERN.test(gate['decidedAt'])) {
        errors.push(`${path}.decidedAt: SATISFIED gates need a YYYY-MM-DD decision date`);
      }
    } else if (gate['decidedAt'] !== null) {
      errors.push(`${path}.decidedAt: non-SATISFIED gates must use null (no fabricated dates)`);
    }
  });
  return errors;
}

/** Load + validate a gate file from disk. Returns { doc, errors }. */
export function loadGates(gatesPath = resolve(process.cwd(), DEFAULT_GATES_PATH)) {
  let doc = null;
  try {
    doc = JSON.parse(readFileSync(gatesPath, 'utf8'));
  } catch (err) {
    return { doc: null, errors: [`${gatesPath}: cannot parse (${err.message})`] };
  }
  return { doc, errors: validateGatesDoc(doc) };
}

/** Pure evaluation over an already-parsed doc. Returns { ok, missing[] }. */
export function gatesSatisfied(doc) {
  const structural = validateGatesDoc(doc);
  if (structural.length > 0) {
    return { ok: false, missing: [], invalid: structural };
  }
  const missing = doc.gates.filter((gate) => gate.status !== 'SATISFIED').map((gate) => gate.id);
  return { ok: missing.length === 0, missing, invalid: [] };
}

/**
 * Fail-closed enforcement. Accepts a path (default: the repo gate file) or an
 * already-parsed doc (tests). Returns true when all four gates are SATISFIED;
 * otherwise throws naming every missing gate (or the structural defect).
 */
export function requireGates(gatesPathOrDoc = resolve(process.cwd(), DEFAULT_GATES_PATH)) {
  let doc = null;
  let source = '';
  if (typeof gatesPathOrDoc === 'string') {
    source = gatesPathOrDoc;
    const loaded = loadGates(gatesPathOrDoc);
    if (loaded.errors.length > 0) {
      throw new Error(`production ingestion BLOCKED: gate file invalid: ${loaded.errors.join('; ')}`);
    }
    doc = loaded.doc;
  } else {
    source = '(provided doc)';
    doc = gatesPathOrDoc;
  }
  const result = gatesSatisfied(doc);
  if (result.invalid.length > 0) {
    throw new Error(`production ingestion BLOCKED: gate file invalid: ${result.invalid.join('; ')}`);
  }
  if (!result.ok) {
    throw new Error(
      `production ingestion BLOCKED by ${result.missing.length}/4 gates (${result.missing.join(', ')} unsatisfied) [${source}]`,
    );
  }
  return true;
}

const invokedAsScript = (() => {
  try {
    return pathToFileURL(resolve(process.argv[1] ?? '')).href === import.meta.url;
  } catch {
    return false;
  }
})();

if (invokedAsScript) {
  try {
    requireGates();
    process.stdout.write('ingestion-gates: OPEN (4/4 gates satisfied)\n');
  } catch (err) {
    process.stdout.write(`ingestion-gates: ${err.message}\n`);
    process.exitCode = 1;
  }
}
