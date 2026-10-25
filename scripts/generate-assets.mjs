/**
 * Deterministic asset compiler for the 3000-asset pump (3000-asset pump).
 *
 * Reads hand-designed cell data (data/asset-cells/*.json), compiles each
 * (class, language) cell into rule + pattern + record + remediation files,
 * and writes ONLY cells passing every gate (see ASSET_METHODOLOGY.md).
 * Failing cells are quarantined (listed, never written).
 *
 * Skip-list policy (semantic dedup vs legacy rules, reviewed per class):
 *  - no php `system(`/`md5(` cells (covered by DPK-SAST-006 / narrowed -004);
 *  - no httpx verify=False, django DEBUG, flask debug, spring debug cells
 *    (covered by DPK-SAST-015 / DPK-SAST-019);
 *  - no java/spring duplicate spellings (one cell per distinct signal);
 *  - REVISED 2026-10-25 by owner direction (docs/SECRETS_TARGET_DECISION_2026-10-25.md,
 *    "Superseded"): narrowed per-key / per-format / per-tool credential rules ARE
 *    admitted to the secrets pack, because the key, header, format or flag is the
 *    content that lets an engine name the credential. The conditions are in
 *    docs/ASSET_METHODOLOGY.md §2 and are enforced here: unique signal per cell,
 *    unique record description, at least one negative that stays silent without the
 *    EXAMPLE denylist, and an evaluation pair per rule. Same-signal respellings stay
 *    forbidden; the generic rules DPK-SEC-003 / -007 / -106 remain and overlap by
 *    design (stated in docs/PACKS.md).
 *  - SAST-004 was narrowed to bare md5( so dotted calls belong to
 *    language-specific cells (documented in that rule).
 *
 * Id allocation is STABLE: data/asset-cells/.manifest.json maps every cell
 * to its allocated ids; reruns reuse them, new cells take next numbers,
 * removed cells are retired (never reused). Rerunning on unchanged data
 * produces byte-identical files (verified in CI by re-run + clean tree).
 *
 * Usage: node scripts/generate-assets.mjs   (root = cwd; writes files)
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { evalDastCheck, lintRedos, validatePackFile } from './validate-packs.mjs';
import { validatePattern, validateRecord } from './validate-assets.mjs';
import { CANONICAL_CWE_VERSION } from './validate-cwe.mjs';

const ROOT = process.cwd();
const CELLS_DIR = join(ROOT, 'data', 'asset-cells');
const MANIFEST_FILE = join(CELLS_DIR, '.manifest.json');
const QUARANTINE_FILE = join(CELLS_DIR, 'quarantine.json');
const LEGACY_BODIES_FILE = join(ROOT, 'data', 'legacy-record-bodies.json');

// --- leak pre-screen mirror (same shapes as test-consistency §13) -------------
const STRICT = [
  new RegExp('-----BEGIN (' + 'RSA |EC |OPENSSH )?PRIVATE KEY-----'),
  new RegExp('AK' + 'IA[0-9A-Z]{16}'),
  new RegExp('ghp' + '_[A-Za-z0-9]{36}'),
  new RegExp('xox' + '[bap]-[A-Za-z0-9-]+'),
  // eslint-disable-next-line no-useless-escape
  new RegExp("(api[_-]?key|secret|passwd|password|token)\\s*[:=]\\s*['\"][A-Za-z0-9_\\-+/=]{12,}['\"]", 'i'),
];
const MARKERS = [/EXAMPLE/i, /(.)\1{7,}/, /1234567890/];

function leakCheck(relativePath, content) {
  const inAuditZone = relativePath.startsWith('packs/secrets/');
  for (const line of content.split('\n')) {
    const fires = STRICT.some((re) => re.test(line));
    if (!fires) continue;
    if (!inAuditZone) return `strict leak shape outside packs/secrets: ${line.slice(0, 60)}`;
    if (!MARKERS.some((re) => re.test(line))) return `unmarked leak shape in packs/secrets: ${line.slice(0, 60)}`;
  }
  return null;
}

function fill(template, vars) {
  return template.replace(/\{(\w+)\}/g, (_, key) => vars[key] ?? `{${key}}`);
}

function unescapeLiteral(fragment) {
  return fragment.replace(/\\(.)/g, '$1');
}

function padRuleNumber(kind, n) {
  const width = n < 1000 ? 3 : String(n).length;
  return `DPK-${kind === 'sast' ? 'SAST' : kind === 'secrets' ? 'SEC' : 'DAST'}-${String(n).padStart(width, '0')}`;
}

// --- test execution -----------------------------------------------------------
export function runLineTests(source, flags, tests, denylist) {
  // eslint-disable-next-line require-unicode-regexp
  const regex = new RegExp(source, flags ?? '');
  for (const test of tests) {
    let actual = regex.test(test.line);
    // Denylist entries are case-insensitive substrings (docs/PACKS.md; same rule as validate-packs.mjs).
    const lowered = test.line.toLowerCase();
    if (actual && denylist.some((d) => lowered.includes(d.toLowerCase()))) actual = false;
    if (actual !== test.match) return `line ${JSON.stringify(test.line.slice(0, 70))}: got ${actual}, want ${test.match}`;
  }
  return null;
}

function runCheckTests(check, tests) {
  for (const test of tests) {
    let actual;
    try {
      actual = evalDastCheck(check, test.observation);
    } catch (err) {
      return `check threw: ${err.message}`;
    }
    if (actual !== test.match) return `observation: got ${actual}, want ${test.match}`;
  }
  return null;
}

// --- composition --------------------------------------------------------------
function composeCallCell(cls, lang, sink) {
  const [frag, literal, safe] = sink;
  const source = `\\b(?:${frag})\\s*\\(`;
  const tests = [
    { line: `${literal}(payload)`, match: true },
    { line: `out = ${literal}(data)`, match: true },
    { line: `my${literal.replace(/\W/g, '')}(x)`, match: false },
    { line: `${literal}_safe()`, match: false },
  ];
  return { source, flags: undefined, tests, literal, safe };
}

// Split a fragment on top-level `|` (ignoring groups, classes and escapes) and
// add a word boundary to each alternative that starts with a word character.
// Wrapping the whole alternation instead would wrongly require a boundary
// before alternatives that begin with punctuation (for example `\\$"`).
function splitAlternatives(frag) {
  const parts = [];
  let current = '';
  let depth = 0;
  let inClass = false;
  for (let i = 0; i < frag.length; i += 1) {
    const ch = frag[i];
    if (ch === '\\' && i + 1 < frag.length) {
      current += ch + frag[i + 1];
      i += 1;
      continue;
    }
    if (inClass) {
      if (ch === ']') inClass = false;
      current += ch;
      continue;
    }
    if (ch === '[') { inClass = true; current += ch; continue; }
    if (ch === '(') { depth += 1; current += ch; continue; }
    if (ch === ')') { depth -= 1; current += ch; continue; }
    if (ch === '|' && depth === 0) { parts.push(current); current = ''; continue; }
    current += ch;
  }
  parts.push(current);
  return parts;
}

function boundFragment(frag) {
  return splitAlternatives(frag)
    .map((part) => {
      const bare = part.replace(/^\(\?:/, '');
      if (part.startsWith('\\b') || !/^[A-Za-z0-9_]/.test(bare)) return part;
      return `\\b(?:${part})`;
    })
    .join('|');
}

function composeFlagCell(cls, lang, sink) {
  const [frag, posLit, negLit, safeNote, extraTests] = sink;
  // A flag fragment is matched anywhere on the line, so a bare identifier also
  // matches longer identifiers (`mypermissions:` for `permissions:`). Prefix a
  // word boundary when the fragment (or its first alternative) starts with a
  // word character; fragments that already anchor (`\b`) or start with a
  // non-word character are left untouched.
  const bounded = boundFragment(frag);
  const pos2 = cls.pos2ctx !== undefined ? fill(cls.pos2ctx, { v: posLit }) : `# audit: ${posLit} present`;
  const neg2 = cls.neg2ctx !== undefined ? fill(cls.neg2ctx, { v: negLit }) : `# verified: ${negLit}`;
  const tests = [
    { line: posLit, match: true },
    { line: pos2, match: true },
    { line: negLit, match: false },
    { line: neg2, match: false },
  ];
  // Optional appended cases (data-declared, per-language). They follow the four
  // fixed tests so existing testIndex pointers never move. Malformed entries
  // fail loudly (same contract as secrets extraTests).
  for (const [i, extra] of (extraTests ?? []).entries()) {
    if (typeof extra?.line !== 'string' || typeof extra?.match !== 'boolean') {
      throw new Error(`${cls.class}/${lang} flag extraTests[${i}] must have string line and boolean match`);
    }
    tests.push({ line: extra.line, match: extra.match });
  }
  return { source: bounded, flags: cls.flags, tests, literal: unescapeLiteral(frag).slice(0, 60), safe: safeNote };
}

function unescapeSecretFragment(fragment) {
  return fragment.replace(/\\b/g, '').replace(/\\(.)/g, '$1');
}

// Compose a secrets cell from prefix fragments + placeholder runs. Fragments
// stay split in data files (never a joined secret shape on disk); the join
// happens only in memory at generation time.
function buildSecretsCell(cell) {
  let fixture = '';
  let source = '';
  for (const seg of cell.build.segments) {
    if (seg.t === 'lit') {
      const joined = seg.v.join('');
      source += joined;
      fixture += unescapeSecretFragment(joined);
    } else if (seg.t === 'run') {
      source += `[${seg.cls}]{${seg.n},}`;
      fixture += seg.ch.repeat(seg.n);
    } else if (seg.t === 'ex') {
      source += seg.sig;
      fixture += seg.fix;
    }
  }
  const v = cell.build.var;
  const pos1 = `${v} = "${fixture}"`;
  const tests = [
    { line: pos1, match: true },
    { line: `# audit: ${pos1} present`, match: true },
    { line: `${v} = "xy"`, match: false },
    { line: `${v} = "EXAMPLE-NOT-A-REAL-VALUE"`, match: false },
  ];
  // Optional appended cases (data-declared). They follow the four fixed tests so
  // existing testIndex pointers never move. Malformed entries fail loudly here.
  for (const [i, extra] of (cell.build.extraTests ?? []).entries()) {
    if (typeof extra?.line !== 'string' || typeof extra?.match !== 'boolean') {
      throw new Error(`secrets extraTests[${i}] must have string line and boolean match`);
    }
    tests.push({ line: extra.line, match: extra.match });
  }
  return { source, flags: undefined, literal: fixture.slice(0, 60), safe: '', tests };
}

// The dataset's generic `shell` cells also tag the Main App `bash` family
// (apps/api/src/scans/sast/languages.ts). `shell-posix` is not tagged: its id has a
// hyphen, which the language id schema (^[a-z][a-z0-9]{0,31}$) rejects by design.
// Dataset cell languages that name a Main App catalog family under a different id.
// `hcl` is the HCL/Terraform surface: the catalog's `terraform` family ("Terraform / HCL",
// extensions .tf/.hcl/.tfvars) is the one the engine gates on. Matching by id alone would
// leave these rules unreachable (engine gate: rule.languages.includes(file.family)).
const APP_LANGUAGE_ALIASES = { hcl: 'terraform' };

function appLanguage(lang) {
  return APP_LANGUAGE_ALIASES[lang] ?? lang;
}

function languageTags(lang) {
  return lang === 'shell' ? ['shell', 'bash'] : [appLanguage(lang)];
}

// `{sink}` appears in human-readable prose (title, description, record text),
// so it must be a readable name, never a regex. Cell literals are readable for
// call cells, but flag/custom cells store regex fragments: interpolating those
// (with escapes stripped) produced text like `bprintfs*(s*[A-Za-z_]w*s*)` in
// 200 SAST rules. Use the first declared positive example for those cells, and
// keep secrets literals untouched (they are fixture placeholders, not regexes).
const READABLE_SINK = /^[A-Za-z_][A-Za-z0-9_.]*$/;
function displaySink(signal) {
  const literal = signal.literal ?? '';
  if (READABLE_SINK.test(literal)) return literal;
  const positive = (signal.tests ?? []).find((t) => t?.match === true && typeof t.line === 'string' && t.line.trim());
  if (positive) {
    const line = positive.line.trim();
    return line.length > 48 ? `${line.slice(0, 47)}…` : line;
  }
  return literal;
}

// Text fields a cell may override (documented deprecation path). IDs, kind,
// class, sinks and signal are never overridable, so ID allocation and detection
// semantics stay owned by the cell data itself.
const TEXT_OVERRIDABLE = ['title', 'description', 'remediation', 'limitation', 'why', 'fix', 'verifyT', 'recordDesc', 'risk', 'fp', 'scopeT', 'severity'];
// A per-sink override may also correct the weakness mapping, because one class
// can legitimately hold constructs that belong to different CWEs (a .NET class
// mixing request validation with certificate validation is the motivating case).
const SINK_OVERRIDABLE = [...TEXT_OVERRIDABLE, 'cwe'];

// Merge `cls.sinkOverrides[key]` into a class for one sink. Fail-closed on an
// unknown sink key or an unknown field: a typo must quarantine the cell, never
// silently produce a rule that keeps the generic text.
function applySinkOverride(cls, key, cweIds) {
  const map = cls.sinkOverrides;
  if (map === undefined) return cls;
  if (typeof map !== 'object' || map === null || Array.isArray(map)) {
    throw new Error(`${cls.class}: sinkOverrides must be an object keyed by sink id`);
  }
  for (const k of Object.keys(map)) {
    if (!Object.prototype.hasOwnProperty.call(cls.sinks ?? {}, k)) {
      throw new Error(`${cls.class}: sinkOverrides key "${k}" is not a declared sink`);
    }
  }
  const own = map[key];
  if (own === undefined) return cls;
  for (const field of Object.keys(own)) {
    if (!SINK_OVERRIDABLE.includes(field)) {
      throw new Error(`${cls.class}/${key}: sinkOverrides field "${field}" is not allowed`);
    }
    if (typeof own[field] !== 'string' || own[field].trim() === '') {
      throw new Error(`${cls.class}/${key}: sinkOverrides.${field} must be a non-empty string`);
    }
  }
  if (own.cwe !== undefined && !cweIds.has(own.cwe)) {
    throw new Error(`${cls.class}/${key}: sinkOverrides.cwe ${own.cwe} has no knowledge/cwe entry`);
  }
  return { ...cls, ...own };
}

function buildFiles({ kind, cellId, ruleId, patId, recId, cls, lang, signal, tests, extra }) {
  const vars = { lang, fw: extra?.fw ?? lang, sink: kind === 'secrets' ? (signal.literal ?? '') : displaySink(signal), safe: extra?.safe ?? signal.safe ?? '', name: extra?.name ?? '' };
  const files = {};
  const ruleTitle = fill(cls.title, vars);
  const rule = {
    schemaVersion: `drobon.pack.${kind}/v1`,
    id: ruleId,
    title: ruleTitle,
    description: fill(cls.description, vars),
    severity: cls.severity,
    cwe: cls.cwe,
    category: cls.category,
    remediation: fill(cls.remediation, vars),
    limitation: fill(cls.limitation, vars),
    // Any-file rules (cell language key `universal`) omit `languages` entirely:
    // the Main App contract treats a missing `languages` field as universal
    // (`languages: undefined` = any file, DPK-SAST-004 convention). The literal
    // tag `universal` is not a catalog id and would leave the rule unreachable.
    ...(kind === 'sast' && lang !== 'universal' ? { languages: languageTags(lang) } : {}),
    ...(kind === 'dast' ? { check: signal.check } : { patterns: [{ source: signal.source, ...(signal.flags ? { flags: signal.flags } : {}) }] }),
    ...(kind === 'secrets' ? { confidence: extra?.confidence ?? cls.confidence ?? 'HIGH', denylist: ['EXAMPLE'], redact: true } : {}),
    tests: kind === 'dast' ? tests.map((t) => ({ observation: t.observation, match: t.match })) : tests,
    patternRefs: [patId],
  };
  files[join('packs', kind, 'v1', 'rules', `${ruleId}.json`)] = rule;
  const pattern = {
    schemaVersion: 'drobon.knowledge.pattern/v1',
    id: patId,
    title: `Signal: ${ruleTitle}`,
    targets: kind === 'dast' ? ['http'] : [appLanguage(lang)],
    signal:
      kind === 'dast'
        ? { kind: 'check', check: signal.check }
        : { kind: 'regex', source: signal.source, ...(signal.flags ? { flags: signal.flags } : {}) },
    scope: fill(cls.scopeT, vars),
    limitations: fill(cls.limitation, vars),
    examples: kind === 'dast' ? tests.map((t) => ({ observation: t.observation, match: t.match })) : tests.map((t) => ({ line: t.line, match: t.match })),
    fpNotes: fill(cls.fp, vars),
    linkedRules: [ruleId],
    origin: 'original-authored',
    cell: cellId,
    validationStatus: 'VALIDATED',
  };
  files[join('knowledge', 'patterns', `${patId}.json`)] = pattern;
  const record = {
    schemaVersion: 'drobon.knowledge.record/v1',
    id: recId,
    category: cls.category,
    subcategory: kind === 'dast' ? 'observed-response' : `${lang}-context`,
    title: `Concept: ${ruleTitle}`,
    description: fill(cls.recordDesc, vars),
    applicability: fill(cls.applicability, vars),
    risk: fill(cls.risk, vars),
    relatedPatterns: [patId],
    relatedRules: [ruleId],
    origin: 'original-authored',
    cell: cellId,
    validationStatus: 'VALIDATED',
  };
  files[join('knowledge', 'records', `${recId}.json`)] = record;
  const remediation = {
    schemaVersion: 'drobon.knowledge.remediation/v1',
    ruleId,
    whyItMatters: fill(cls.why, vars),
    actions: (cls.fix ?? []).map((step) => fill(step, vars)),
    verification: fill(cls.verifyT, vars),
    standardId: cls.cwe,
  };
  files[join('knowledge', 'remediation', `${ruleId}.json`)] = remediation;
  return files;
}

// --- main ---------------------------------------------------------------------
function loadCellData() {
  const classes = [];
  const files = readdirSync(CELLS_DIR).filter((f) => f.endsWith('.json') && f !== '.manifest.json' && f !== 'quarantine.json').sort();
  for (const file of files) {
    const parsed = JSON.parse(readFileSync(join(CELLS_DIR, file), 'utf8'));
    if (!Array.isArray(parsed)) throw new Error(`${file}: top level must be an array of classes`);
    for (const cls of parsed) classes.push({ ...cls, file });
  }
  return classes;
}

function existingMaxNumberIn(dir, prefix) {
  if (!existsSync(dir)) return 0;
  let max = 0;
  for (const file of readdirSync(dir)) {
    if (!file.startsWith(prefix) || !file.endsWith('.json')) continue;
    const n = Number.parseInt(file.slice(prefix.length), 10);
    if (Number.isFinite(n) && n > max) max = n;
  }
  return max;
}

function existingMaxNumber(kind) {
  const dir = join(ROOT, 'packs', kind, 'v1', 'rules');
  const prefix = kind === 'sast' ? 'DPK-SAST-' : kind === 'secrets' ? 'DPK-SEC-' : 'DPK-DAST-';
  let max = 0;
  for (const file of readdirSync(dir)) {
    if (file.startsWith(prefix)) {
      const n = Number.parseInt(file.slice(prefix.length), 10);
      if (Number.isFinite(n) && n > max) max = n;
    }
  }
  return max;
}

function main() {
  const manifest = existsSync(MANIFEST_FILE) ? JSON.parse(readFileSync(MANIFEST_FILE, 'utf8')) : { cells: {}, legacy: [] };
  const classes = loadCellData();
  const quarantined = [];
  // Weakness ids that actually resolve in knowledge/cwe. A per-sink CWE
  // override is checked against this set before any file is composed, so a
  // typo cannot ship a rule whose CWE the App cannot resolve.
  const cweIds = new Set(readdirSync(join(ROOT, 'knowledge', 'cwe'))
    .filter((f) => f.endsWith('.json'))
    .map((f) => JSON.parse(readFileSync(join(ROOT, 'knowledge', 'cwe', f), 'utf8')).id));
  const nextIds = { sast: existingMaxNumber('sast'), secrets: existingMaxNumber('secrets'), dast: existingMaxNumber('dast') };
  // Id allocation floors. Patterns and records are allocated from the manifest,
  // but a hand-authored file (or a record composed for a legacy rule) is not in
  // `manifest.cells`, so the on-disk maximum is read first: allocation can then
  // never collide with, or silently overwrite, an existing asset.
  let nextPat = Math.max(40, existingMaxNumberIn(join(ROOT, 'knowledge', 'patterns'), 'DPK-PAT-'));
  let nextRec = existingMaxNumberIn(join(ROOT, 'knowledge', 'records'), 'DPK-REC-');
  const legacyBodies = existsSync(LEGACY_BODIES_FILE)
    ? JSON.parse(readFileSync(LEGACY_BODIES_FILE, 'utf8')).records ?? {}
    : {};
  for (const cell of Object.values(manifest.cells)) {
    const patN = Number.parseInt(cell.patId.slice('DPK-PAT-'.length), 10);
    const recN = Number.parseInt(cell.recId.slice('DPK-REC-'.length), 10);
    if (patN > nextPat) nextPat = patN;
    if (recN > nextRec) nextRec = recN;
    const m = /^DPK-(SAST|SEC|DAST)-(\d+)$/.exec(cell.ruleId);
    if (m) {
      const k = m[1] === 'SAST' ? 'sast' : m[1] === 'SEC' ? 'secrets' : 'dast';
      const n = Number.parseInt(m[2], 10);
      if (n > nextIds[k]) nextIds[k] = n;
    }
  }
  // Rule numbers: never go below the on-disk max (hand files included).
  const wanted = new Map(); // relpath -> object
  const seenSignals = new Map();
  const seenDescriptions = new Set();
  const emittedCwe = new Set();

  function useCwe(cls) {
    if (cls.cweDef === undefined) return null;
    const id = cls.cwe;
    const rel = join('knowledge', 'cwe', `${id}.json`);
    if (wanted.has(rel)) return null;
    // Managed-output ownership (R3 fix): a pre-existing curated file that this
    // generator never emitted (absent from the previous manifest's file list)
    // is left untouched — never adopted, never overwritten, never deleted.
    // Previously-managed files are re-adopted into `wanted` every run so the
    // stale-file removal below keeps them instead of deleting them.
    // NOTE: manifest.files still holds the previous run's list here (it is
    // only rewritten at the end of main), so this membership test is exact.
    const onDisk = existsSync(join(ROOT, rel));
    const wasManaged = (manifest.files ?? []).includes(rel);
    if (onDisk && !wasManaged) return null;
    const number = id.slice('CWE-'.length);
    wanted.set(rel, {
      schemaVersion: 'drobon.knowledge.cwe/v1',
      id,
      name: cls.cweDef.name,
      summary: `${cls.cweDef.summary} Drobon summary in our own words; canonical definition at the linked MITRE page.`,
      url: `https://cwe.mitre.org/data/definitions/${number}.html`,
      // Per-entry catalog version (Phase 5): repo-pinned canonical value from
      // validate-cwe.mjs; validated in-repo only, never fetched from MITRE.
      cweVersion: CANONICAL_CWE_VERSION,
    });
    if (!onDisk) emittedCwe.add(id);
    return null;
  }

  function gateAndStage({ kind, cellId, cls, lang, signal, tests, extra }) {
    const fail = (reason) => quarantined.push({ cell: cellId, reason });
    if (tests.filter((t) => t.match === true).length < 1 || tests.filter((t) => t.match === false).length < 1) {
      fail('needs >=1 positive and >=1 negative test');
      return;
    }
    if (kind !== 'dast') {
      try {
        // eslint-disable-next-line require-unicode-regexp
        new RegExp(signal.source, signal.flags ?? '');
      } catch {
        fail('signal does not compile');
        return;
      }
      const lint = lintRedos(signal.source);
      if (lint !== null) {
        fail(`ReDoS lint: ${lint}`);
        return;
      }
      const err = runLineTests(signal.source, signal.flags, tests, kind === 'secrets' ? ['EXAMPLE'] : []);
      if (err !== null) {
        fail(`test execution: ${err}`);
        return;
      }
    } else {
      const err = runCheckTests(signal.check, tests);
      if (err !== null) {
        fail(`check execution: ${err}`);
        return;
      }
    }
    const sigKey = kind === 'dast' ? `check:${JSON.stringify(signal.check)}` : `re:${appLanguage(lang)}::${signal.source}::${signal.flags ?? ''}`;
    if (seenSignals.has(sigKey)) {
      fail(`duplicate signal of ${seenSignals.get(sigKey)}`);
      return;
    }
    // Allocate or reuse stable ids.
    let alloc = manifest.cells[cellId];
    if (alloc === undefined) {
      nextIds[kind] += 1;
      nextPat += 1;
      nextRec += 1;
      alloc = {
        ruleId: padRuleNumber(kind, nextIds[kind]),
        patId: `DPK-PAT-${String(nextPat).padStart(4, '0')}`,
        recId: `DPK-REC-${String(nextRec).padStart(4, '0')}`,
      };
      manifest.cells[cellId] = alloc;
    }
    const files = buildFiles({ kind, cellId, ruleId: alloc.ruleId, patId: alloc.patId, recId: alloc.recId, cls, lang, signal, tests, extra });
    // Schema + leak gates on every composed file.
    for (const [rel, obj] of Object.entries(files)) {
      const content = `${JSON.stringify(obj, null, 2)}\n`;
      const leak = leakCheck(rel, content);
      if (leak !== null) {
        fail(leak);
        delete manifest.cells[cellId];
        return;
      }
      let errors = [];
      if (rel.startsWith('packs/')) errors = validatePackFile(obj);
      else if (rel.includes('/patterns/')) errors = validatePattern(obj);
      else if (rel.includes('/records/')) errors = validateRecord(obj);
      if (errors.length > 0) {
        fail(`schema: ${errors[0]}`);
        delete manifest.cells[cellId];
        return;
      }
    }
    const descKey = files[join('knowledge', 'records', `${alloc.recId}.json`)].description;
    if (seenDescriptions.has(descKey)) {
      fail('duplicate record description');
      delete manifest.cells[cellId];
      return;
    }
    useCwe(cls);
    seenSignals.set(sigKey, cellId);
    seenDescriptions.add(descKey);
    for (const [rel, obj] of Object.entries(files)) wanted.set(rel, obj);
  }

  // Legacy patterns (DPK-PAT-0001..0040) derived from the 40 hand rules.
  const legacyRuleFiles = ['sast', 'secrets', 'dast'].flatMap((kind) =>
    readdirSync(join(ROOT, 'packs', kind, 'v1', 'rules'))
      .filter((f) => f.endsWith('.json'))
      .map((f) => ({ kind, file: f })),
  );
  // Only rules WITHOUT a generated cell (legacy hand rules predate the pump).
  const generatedRuleIds = new Set(Object.values(manifest.cells).map((c) => c.ruleId));
  const legacyRules = legacyRuleFiles
    .map(({ kind, file }) => ({ kind, record: JSON.parse(readFileSync(join(ROOT, 'packs', kind, 'v1', 'rules', file), 'utf8')) }))
    .filter(({ record }) => !generatedRuleIds.has(record.id))
    .sort((a, b) => (a.record.id < b.record.id ? -1 : 1));
  // Legacy entries keep their allocated pattern id, and gain a record id the
  // first time they are seen. Both ids are persisted in the manifest so the
  // assets stay stable across runs.
  const previousLegacy = new Map((manifest.legacy ?? []).map((entry) => [entry.ruleId, entry]));
  manifest.legacy = [];
  legacyRules.forEach(({ kind, record }, index) => {
    const patId = `DPK-PAT-${String(index + 1).padStart(4, '0')}`;
    const previous = previousLegacy.get(record.id);
    let recId = previous?.recId;
    if (recId === undefined) {
      nextRec += 1;
      recId = `DPK-REC-${String(nextRec).padStart(4, '0')}`;
    }
    manifest.legacy.push({ ruleId: record.id, recId, patId });
    const signal =
      kind === 'dast'
        ? { kind: 'check', check: record.check }
        : { kind: 'regex', source: record.patterns[0].source, ...(record.patterns[0].flags ? { flags: record.patterns[0].flags } : {}) };
    // Secrets examples point at the rule's own test line (ruleRef + testIndex) so
    // credential-shaped text never leaves packs/secrets; other kinds keep inline lines.
    const examples =
      kind === 'dast'
        ? record.tests.map((t) => ({ observation: t.observation, match: t.match }))
        : kind === 'secrets'
          ? record.tests.map((t, testIndex) => ({ ruleRef: record.id, testIndex, match: t.match }))
          : record.tests.map((t) => ({ line: t.line, match: t.match }));
    const pattern = {
      schemaVersion: 'drobon.knowledge.pattern/v1',
      id: patId,
      title: `Signal: ${record.title}`,
      targets: kind === 'dast' ? ['http'] : (record.languages ?? ['universal']),
      signal,
      scope: `Legacy signal mirrored from ${record.id}.`,
      limitations: record.limitation,
      examples,
      fpNotes: record.limitation,
      linkedRules: [record.id],
      origin: 'original-authored',
      cell: `legacy:${record.id}`,
      validationStatus: 'VALIDATED',
    };
    const errors = validatePattern(pattern);
    if (errors.length > 0) {
      quarantined.push({ cell: `legacy:${record.id}`, reason: `schema: ${errors[0]}` });
      return;
    }
    const sigKey = kind === 'dast' ? `check:${JSON.stringify(record.check)}` : `re:${[...(record.languages ?? ['universal'])].sort().join(',')}::${record.patterns[0].source}::${record.patterns[0].flags ?? ''}`;
    seenSignals.set(sigKey, `legacy:${record.id}`);
    wanted.set(join('knowledge', 'patterns', `${patId}.json`), pattern);

    // The legacy rule predates the cell pipeline, so the generator used to emit
    // its pattern but never its record: 40 rules ended up with a rule, a
    // pattern, a remediation entry and no concept record. The bodies are
    // authored in data/legacy-record-bodies.json; a missing body is reported as
    // a quarantine, never silently skipped.
    const body = legacyBodies[record.id];
    if (body === undefined) {
      quarantined.push({ cell: `legacy:${record.id}`, reason: 'legacy record body missing' });
      return;
    }
    const legacyRecord = {
      schemaVersion: 'drobon.knowledge.record/v1',
      id: recId,
      category: record.category,
      subcategory: kind === 'dast' ? 'observed-response' : `${record.languages?.[0] ?? 'universal'}-context`,
      title: body.title,
      description: body.description,
      applicability: body.applicability,
      risk: body.risk,
      relatedPatterns: [patId],
      relatedRules: [record.id],
      origin: 'original-authored',
      cell: `legacy:${record.id}`,
      validationStatus: 'VALIDATED',
    };
    const recordErrors = validateRecord(legacyRecord);
    if (recordErrors.length > 0) {
      quarantined.push({ cell: `legacy:${record.id}`, reason: `record schema: ${recordErrors[0]}` });
      return;
    }
    if (seenDescriptions.has(legacyRecord.description)) {
      quarantined.push({ cell: `legacy:${record.id}`, reason: 'duplicate record description' });
      return;
    }
    seenDescriptions.add(legacyRecord.description);
    wanted.set(join('knowledge', 'records', `${recId}.json`), legacyRecord);
  });

  // Compile cells (sorted for determinism).
  const jobs = [];
  for (const cls of classes) {
    if (cls.framing === 'call' || cls.framing === 'flag') {
      for (const key of Object.keys(cls.sinks ?? {}).sort()) {
        const [lang, fw] = key.split(':');
        jobs.push({ kind: cls.kind, cellId: `${cls.kind}:${cls.class}:${key}`, cls, sinkKey: key, lang, fw: fw ?? lang, sink: cls.sinks[key] });
      }
    } else if (cls.framing === 'custom') {
      for (const cell of cls.cells ?? []) {
        jobs.push({ kind: cls.kind, cellId: `${cls.kind}:${cls.class}:${cell.suffix}`, cls, lang: cell.lang, custom: cell });
      }
    }
  }
  jobs.sort((a, b) => (a.cellId < b.cellId ? -1 : 1));
  for (const job of jobs) {
    if (job.custom !== undefined) {
      const cell = job.custom;
      let signal = cell.signal ?? (cell.check !== undefined ? { check: cell.check } : undefined);
      let tests = cell.tests;
      if (cell.build !== undefined) {
        const built = buildSecretsCell(cell);
        signal = { source: built.source, flags: built.flags, literal: built.literal, safe: built.safe };
        tests = built.tests;
      }
      // Per-cell text overrides (documented deprecation, see docs/ASSET_METHODOLOGY.md).
      // Only whitelisted text fields and severity may be overridden; IDs, kind,
      // class and sinks are never overridable, so ID allocation is unaffected.
      const overrides = cell.overrides ?? {};
      for (const key of Object.keys(overrides)) {
        if (!TEXT_OVERRIDABLE.includes(key)) {
          throw new Error(`cell ${job.cellId}: override "${key}" is not allowed`);
        }
      }
      const effCls = Object.keys(overrides).length > 0 ? { ...job.cls, ...overrides } : job.cls;
      gateAndStage({ kind: job.kind, cellId: job.cellId, cls: effCls, lang: job.lang, signal, tests, extra: { name: cell.name, fw: cell.fw, safe: cell.safe, confidence: cell.build?.confidence } });
    } else if (job.cls.framing === 'call') {
      const cls = applySinkOverride(job.cls, job.sinkKey, cweIds);
      const signal = composeCallCell(cls, job.lang, job.sink);
      gateAndStage({ kind: job.kind, cellId: job.cellId, cls, lang: job.lang, signal, tests: signal.tests, extra: { fw: job.fw } });
    } else {
      const cls = applySinkOverride(job.cls, job.sinkKey, cweIds);
      const signal = composeFlagCell(cls, job.lang, job.sink);
      gateAndStage({ kind: job.kind, cellId: job.cellId, cls, lang: job.lang, signal, tests: signal.tests, extra: { fw: job.fw } });
    }
  }

  // Fail-loud guard (Pump 3): a quarantined cell means its previously generated
  // files would be silently removed below (stale-file cleanup) and the run would
  // still exit 0. Refuse before touching any file; the report goes to stderr.
  if (quarantined.length > 0) {
    process.stderr.write(
      `generate-assets: FAIL — ${quarantined.length} cell(s) quarantined; no files written or removed.\n` +
        quarantined.map((q) => `  - ${q.cell}: ${q.reason}`).join('\n') +
        '\n',
    );
    process.exitCode = 1;
    return;
  }

  // Write wanted files; remove stale generated files via previous manifest.
  mkdirSync(join(ROOT, 'knowledge', 'patterns'), { recursive: true });
  mkdirSync(join(ROOT, 'knowledge', 'records'), { recursive: true });
  const previous = existsSync(MANIFEST_FILE) ? JSON.parse(readFileSync(MANIFEST_FILE, 'utf8')) : null;
  const previousFiles = new Set(previous?.files ?? []);
  let written = 0;
  for (const [rel, obj] of [...wanted.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const full = join(ROOT, rel);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, `${JSON.stringify(obj, null, 2)}\n`);
    written += 1;
  }
  let removed = 0;
  for (const rel of previousFiles) {
    if (!wanted.has(rel) && existsSync(join(ROOT, rel))) {
      rmSync(join(ROOT, rel));
      removed += 1;
    }
  }
  manifest.files = [...wanted.keys()].sort();
  writeFileSync(MANIFEST_FILE, `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(QUARANTINE_FILE, `${JSON.stringify({ generatedAt: undefined, quarantined }, null, 2)}\n`);

  const counts = { sast: 0, secrets: 0, dast: 0, patterns: 0, records: 0, remediation: 0 };
  for (const rel of wanted.keys()) {
    if (rel.startsWith('packs/sast/')) counts.sast += 1;
    else if (rel.startsWith('packs/secrets/')) counts.secrets += 1;
    else if (rel.startsWith('packs/dast/')) counts.dast += 1;
    else if (rel.includes('/patterns/')) counts.patterns += 1;
    else if (rel.includes('/records/')) counts.records += 1;
    else if (rel.includes('/remediation/')) counts.remediation += 1;
  }
  process.stdout.write(`${JSON.stringify({ written, removed, counts, cweEmitted: [...emittedCwe].sort(), quarantined }, null, 2)}\n`);
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (invokedAsScript) {
  main();
}
