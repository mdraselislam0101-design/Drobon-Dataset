#!/usr/bin/env node
/**
 * generate-sca-assets.mjs — compiler for `drobon.pack.sca/v1` cells.
 *
 * Reads hand-designed cells (data/asset-cells/sca-*.json), composes one rule,
 * one pattern, one record and one remediation entry per cell, and writes ONLY
 * cells that pass every gate. Failing cells are quarantined (listed, never
 * written). Deterministic: unchanged input produces byte-identical output.
 *
 * Id allocation is stable through data/sca-manifest.json: a cell
 * keeps its rule/pattern/record ids across runs, new cells take the next free
 * numbers, and numbers are never reused for a different cell.
 *
 * Usage: node scripts/generate-sca-assets.mjs   (root = cwd; writes files)
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { validatePattern, validateRecord } from './validate-assets.mjs';
import { validatePackFile } from './validate-packs.mjs';
import { ScaRuleError, evaluateScaCheck, scaSignature } from './sca-rule-engine.mjs';

const ROOT = process.cwd();
const CELLS_DIR = join(ROOT, 'data', 'asset-cells');
const SCA_MANIFEST_FILE = join(ROOT, 'data', 'sca-manifest.json');

const STRICT = [
  new RegExp('-----BEGIN (' + 'RSA |EC |OPENSSH )?PRIVATE KEY-----'),
  new RegExp('AK' + 'IA[0-9A-Z]{16}'),
  new RegExp('ghp' + '_[A-Za-z0-9]{36}'),
  new RegExp('xox' + '[bap]-[A-Za-z0-9-]+'),
  // eslint-disable-next-line no-useless-escape
  new RegExp("(api[_-]?key|secret|passwd|password|token)\\s*[:=]\\s*['\"][A-Za-z0-9_\\-+/=]{12,}['\"]", 'i'),
];

function leakCheck(relativePath, content) {
  for (const line of content.split('\n')) {
    if (STRICT.some((re) => re.test(line))) {
      return `strict leak shape in ${relativePath}: ${line.slice(0, 60)}`;
    }
  }
  return null;
}

const cap = (text) => text.charAt(0).toUpperCase() + text.slice(1);

function compose(cell, ids) {
  const what = cell.what;
  const description = `${cell.artifact} declares ${what}. ${cell.impact}`;
  const rule = {
    schemaVersion: 'drobon.pack.sca/v1',
    id: ids.ruleId,
    title: cell.title,
    description,
    severity: cell.severity,
    cwe: cell.cwe,
    category: cell.category,
    ecosystems: [cell.ecosystem],
    artifact: cell.artifact,
    parser: cell.parser,
    check: cell.check,
    tests: cell.tests,
    patternRefs: [ids.patId],
    remediation: cell.remediation,
    limitation: cell.limitation,
  };
  const pattern = {
    schemaVersion: 'drobon.knowledge.pattern/v1',
    id: ids.patId,
    title: `Signal: ${cell.title}`.slice(0, 200),
    targets: [cell.ecosystem],
    signal: { kind: 'check', check: cell.check },
    scope: `A ${cell.artifact} file that declares ${what}.`.slice(0, 2000),
    limitations: cell.limitation,
    examples: cell.tests.map((test) => ({ file: test.file, document: test.document, match: test.match })),
    fpNotes: cell.fp,
    linkedRules: [ids.ruleId],
    origin: 'original-authored',
    cell: `sca:${cell.class}`.slice(0, 120),
    validationStatus: 'VALIDATED',
  };
  const record = {
    schemaVersion: 'drobon.knowledge.record/v1',
    id: ids.recId,
    category: cell.category,
    subcategory: cell.subcategory ?? 'dependency-declaration',
    title: `Concept: ${cell.title}`.slice(0, 200),
    description: `${cell.artifact} declares ${what}, which leaves a dependency the reviewer cannot reason about: ${cell.impact}`.slice(0, 4000),
    applicability: `Projects that resolve dependencies through ${cell.artifact} (${cell.ecosystem}).`.slice(0, 2000),
    risk: cell.impact.slice(0, 2000),
    relatedPatterns: [ids.patId],
    relatedRules: [ids.ruleId],
    origin: 'original-authored',
    cell: `sca:${cell.class}`.slice(0, 120),
    validationStatus: 'VALIDATED',
  };
  const remediation = {
    schemaVersion: 'drobon.knowledge.remediation/v1',
    ruleId: ids.ruleId,
    whyItMatters: cell.impact.slice(0, 1000),
    actions: [cell.remediation],
    verification: `Re-run the dependency scan and confirm ${cell.artifact} no longer carries ${what}.`,
    standardId: cell.cwe,
  };
  return {
    [`packs/sca/v1/rules/${ids.ruleId}.json`]: rule,
    [`knowledge/patterns/${ids.patId}.json`]: pattern,
    [`knowledge/records/${ids.recId}.json`]: record,
    [`knowledge/remediation/${ids.ruleId}.json`]: remediation,
  };
}

function maxNumberIn(dir, prefix) {
  if (!existsSync(dir)) return 0;
  let max = 0;
  for (const file of readdirSync(dir)) {
    if (!file.startsWith(prefix) || !file.endsWith('.json')) continue;
    const n = Number.parseInt(file.slice(prefix.length), 10);
    if (Number.isFinite(n) && n > max) max = n;
  }
  return max;
}

function loadCells() {
  const files = readdirSync(CELLS_DIR)
    .filter((file) => /^sca-.*\.json$/.test(file))
    .sort();
  const cells = [];
  for (const file of files) {
    const parsed = JSON.parse(readFileSync(join(CELLS_DIR, file), 'utf8'));
    if (!Array.isArray(parsed)) throw new Error(`${file}: a cell file must be an array`);
    for (const cell of parsed) cells.push({ ...cell, sourceFile: file });
  }
  return cells;
}

function main() {
  const scaManifest = existsSync(SCA_MANIFEST_FILE)
    ? JSON.parse(readFileSync(SCA_MANIFEST_FILE, 'utf8'))
    : { cells: {}, files: [] };
  const cells = loadCells();
  const quarantined = [];
  let nextRule = maxNumberIn(join(ROOT, 'packs', 'sca', 'v1', 'rules'), 'DPK-SCA-');
  let nextPat = maxNumberIn(join(ROOT, 'knowledge', 'patterns'), 'DPK-PAT-');
  let nextRec = maxNumberIn(join(ROOT, 'knowledge', 'records'), 'DPK-REC-');
  for (const [cellId, ids] of Object.entries(scaManifest.cells)) {
    const ruleN = Number.parseInt(ids.ruleId.slice('DPK-SCA-'.length), 10);
    const patN = Number.parseInt(ids.patId.slice('DPK-PAT-'.length), 10);
    const recN = Number.parseInt(ids.recId.slice('DPK-REC-'.length), 10);
    if (ruleN > nextRule) nextRule = ruleN;
    if (patN > nextPat) nextPat = patN;
    if (recN > nextRec) nextRec = recN;
    if (!cells.some((cell) => cell.class === cellId)) quarantined.push({ cell: cellId, reason: 'cell removed from data; ids stay reserved' });
  }

  const wanted = new Map();
  const seenSignatures = new Map();
  const seenCells = new Set();
  for (const cell of cells) {
    const cellId = cell.class;
    const fail = (reason) => quarantined.push({ cell: cellId, reason });
    if (typeof cellId !== 'string' || !/^[a-z0-9][a-z0-9-]{2,79}$/.test(cellId)) {
      fail('class must match ^[a-z0-9][a-z0-9-]{2,79}$');
      continue;
    }
    if (seenCells.has(cellId)) {
      fail(`duplicate cell id (also in ${cell.sourceFile})`);
      continue;
    }
    seenCells.add(cellId);
    if (!Array.isArray(cell.tests) || cell.tests.filter((t) => t.match === true).length < 2 || cell.tests.filter((t) => t.match === false).length < 2) {
      fail('needs >=2 positives and >=2 negatives');
      continue;
    }
    try {
      for (const test of cell.tests) {
        const hit = evaluateScaCheck(cell.check, { file: test.file, document: test.document });
        if (hit !== test.match) {
          fail(`test execution: ${test.file} got ${hit}, want ${test.match}`);
          break;
        }
      }
    } catch (error) {
      fail(`check: ${error instanceof ScaRuleError ? error.message : String(error)}`);
      continue;
    }
    if (quarantined.some((entry) => entry.cell === cellId)) continue;
    const signature = scaSignature({ ecosystems: [cell.ecosystem], check: cell.check });
    if (seenSignatures.has(signature)) {
      fail(`duplicate predicate of ${seenSignatures.get(signature)}`);
      continue;
    }
    seenSignatures.set(signature, cellId);

    let ids = scaManifest.cells[cellId];
    if (ids === undefined) {
      nextRule += 1;
      nextPat += 1;
      nextRec += 1;
      ids = {
        ruleId: `DPK-SCA-${String(nextRule).padStart(4, '0')}`,
        patId: `DPK-PAT-${String(nextPat).padStart(4, '0')}`,
        recId: `DPK-REC-${String(nextRec).padStart(4, '0')}`,
      };
      scaManifest.cells[cellId] = ids;
    }
    const files = compose(cell, ids);
    let rejected = false;
    for (const [rel, obj] of Object.entries(files)) {
      const content = `${JSON.stringify(obj, null, 2)}\n`;
      const leak = leakCheck(rel, content);
      if (leak !== null) {
        fail(leak);
        rejected = true;
        break;
      }
      let errors = [];
      if (rel.startsWith('packs/')) errors = validatePackFile(obj);
      else if (rel.includes('/patterns/')) errors = validatePattern(obj);
      else if (rel.includes('/records/')) errors = validateRecord(obj);
      if (errors.length > 0) {
        fail(`schema ${rel}: ${errors[0]}`);
        rejected = true;
        break;
      }
    }
    if (rejected) {
      delete scaManifest.cells[cellId];
      continue;
    }
    for (const [rel, obj] of Object.entries(files)) wanted.set(rel, obj);
  }

  // Managed-output sweep: a file this generator previously wrote and no longer
  // composes belongs to a removed cell and is deleted. Files it never wrote are
  // never touched here.
  const liveIds = Object.values(scaManifest.cells);
  for (const rel of scaManifest.files ?? []) {
    if (wanted.has(rel)) continue;
    if (liveIds.some((ids) => rel.includes(ids.ruleId) || rel.includes(ids.patId) || rel.includes(ids.recId))) continue;
    const full = join(ROOT, rel);
    if (existsSync(full)) rmSync(full);
  }

  for (const [rel, obj] of wanted) {
    const full = join(ROOT, rel);
    mkdirSync(join(full, '..'), { recursive: true });
    const content = `${JSON.stringify(obj, null, 2)}\n`;
    if (!existsSync(full) || readFileSync(full, 'utf8') !== content) writeFileSync(full, content);
  }
  scaManifest.files = [...wanted.keys()].sort();
  writeFileSync(SCA_MANIFEST_FILE, `${JSON.stringify(scaManifest, null, 2)}\n`);

  for (const entry of quarantined) process.stdout.write(`quarantine: ${entry.cell}: ${entry.reason}\n`);
  process.stdout.write(`sca cells: ${cells.length}; written: ${wanted.size / 4}; quarantined: ${quarantined.length}\n`);
  if (quarantined.length > 0 && wanted.size === 0) process.exitCode = 1;
}

main();
