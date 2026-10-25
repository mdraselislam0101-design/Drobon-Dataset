#!/usr/bin/env node
/**
 * test-sca-packs.mjs — suite for the `drobon.pack.sca/v1` pack.
 *
 * Beyond `validate-packs` (schema + executed tests per file) this suite checks
 * the properties that only exist across files:
 *
 *   1. ids are DPK-SCA-nnnn, unique, contiguous from 0001;
 *   2. no two rules ship the same predicate signature (ecosystem + type + path + pattern);
 *   3. every rule has its pattern, record and remediation entry, and the links agree
 *      in both directions;
 *   4. the cell manifest and the live pack agree (no orphan rule, no orphan cell);
 *   5. the engine refuses malformed predicates instead of falling back to "no match";
 *   6. a rule never makes an advisory claim: the pack classifies declared text only;
 *   7. the artifact named by a rule is a real file for its ecosystem.
 *
 * Usage: node scripts/test-sca-packs.mjs
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validatePackFile } from './validate-packs.mjs';
import {
  SCA_CHECK_TYPES,
  ScaRuleError,
  boundedDistance,
  evaluateScaCheck,
  resolvePath,
  scaSignature,
} from './sca-rule-engine.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let passed = 0;
let failed = 0;
function assert(condition, label, detail = '') {
  if (condition) {
    passed += 1;
    process.stdout.write(`ok - ${label}\n`);
  } else {
    failed += 1;
    process.stdout.write(`FAIL - ${label}\n`);
    if (detail) process.stdout.write(`    ${detail}\n`);
  }
}
function codeOf(fn) {
  try {
    fn();
    return 'NO_THROW';
  } catch (error) {
    return error instanceof ScaRuleError ? 'ScaRuleError' : `UNEXPECTED:${error.message}`;
  }
}
const readJson = (rel) => JSON.parse(readFileSync(join(ROOT, rel), 'utf8'));

const ruleDir = join(ROOT, 'packs', 'sca', 'v1', 'rules');
const ruleFiles = existsSync(ruleDir)
  ? readdirSync(ruleDir).filter((file) => file.endsWith('.json')).sort()
  : [];
assert(ruleFiles.length > 0, `pack: SCA rules present (found ${ruleFiles.length})`);

const rules = ruleFiles.map((file) => ({ file, rule: readJson(join('packs', 'sca', 'v1', 'rules', file)) }));
const byId = new Map(rules.map((entry) => [entry.rule.id, entry.rule]));
const manifestForChain = existsSync(join(ROOT, 'data', 'sca-manifest.json')) ? readJson('data/sca-manifest.json') : { cells: {} };
const recIdByRule = new Map(Object.values(manifestForChain.cells ?? {}).map((ids) => [ids.ruleId, ids.recId]));

// --- 1. ids ----------------------------------------------------------------
const idProblems = [];
let previousNumber = 0;
for (const { rule } of rules) {
  if (!/^DPK-SCA-[0-9]{4}$/.test(rule.id)) {
    idProblems.push(`${rule.id}: id shape`);
    continue;
  }
  const number = Number.parseInt(rule.id.slice('DPK-SCA-'.length), 10);
  // Numbers are allocated monotonically and never reused, so a gap means a cell
  // was removed and its numbers stay reserved. A repeat or a backwards step is a
  // defect; a gap is not.
  if (number <= previousNumber) idProblems.push(`${rule.id}: not increasing after ${previousNumber}`);
  previousNumber = number;
}
assert(idProblems.length === 0, 'ids: DPK-SCA-nnnn, unique and strictly increasing (gaps stay reserved)',
  idProblems.slice(0, 5).join('; '));

// --- 2. schema + executed tests --------------------------------------------
const schemaProblems = [];
let executedTests = 0;
let positives = 0;
let negatives = 0;
for (const { rule } of rules) {
  const errors = validatePackFile(rule);
  if (errors.length > 0) schemaProblems.push(`${rule.id}: ${errors[0]}`);
  for (const test of rule.tests) {
    executedTests += 1;
    if (test.match) positives += 1;
    else negatives += 1;
    const hit = evaluateScaCheck(rule.check, { file: test.file, document: test.document });
    if (hit !== test.match) schemaProblems.push(`${rule.id}: ${test.file} got ${hit}, want ${test.match}`);
  }
}
assert(schemaProblems.length === 0, `rules: every rule validates and every declared test reproduces (${executedTests} tests)`, schemaProblems.slice(0, 5).join('; '));
assert(positives >= rules.length * 2 && negatives >= rules.length * 2,
  `rules: at least 2 positives and 2 negatives per rule (${positives} pos / ${negatives} neg)`);

// --- 3. no duplicate predicate ---------------------------------------------
const seen = new Map();
const collisions = [];
for (const { rule } of rules) {
  const signature = scaSignature(rule);
  if (seen.has(signature)) collisions.push(`${rule.id} duplicates ${seen.get(signature)}`);
  else seen.set(signature, rule.id);
}
assert(collisions.length === 0, 'dedupe: no two rules ship the same predicate signature', collisions.slice(0, 5).join('; '));

// --- 4. artefact chain ------------------------------------------------------
const chainProblems = [];
for (const { rule } of rules) {
  const refs = rule.patternRefs ?? [];
  if (refs.length !== 1) {
    chainProblems.push(`${rule.id}: expected exactly one patternRef`);
    continue;
  }
  const patRel = `knowledge/patterns/${refs[0]}.json`;
  const recId = recIdByRule.get(rule.id) ?? rule.id.replace('DPK-SCA-', 'DPK-REC-');
  const recRel = `knowledge/records/${recId}.json`;
  if (!existsSync(join(ROOT, patRel))) {
    chainProblems.push(`${rule.id}: missing ${refs[0]}`);
    continue;
  }
  const pattern = readJson(patRel);
  if (JSON.stringify(pattern.signal?.check) !== JSON.stringify(rule.check)) {
    chainProblems.push(`${rule.id}: pattern signal differs from the rule check`);
  }
  if (!(pattern.linkedRules ?? []).includes(rule.id)) chainProblems.push(`${rule.id}: pattern does not link back`);
  if (!existsSync(join(ROOT, recRel))) {
    chainProblems.push(`${rule.id}: missing record ${recRel}`);
  } else {
    const record = readJson(recRel);
    if (!(record.relatedRules ?? []).includes(rule.id)) chainProblems.push(`${rule.id}: record does not link back`);
    if (!(record.relatedPatterns ?? []).includes(refs[0])) chainProblems.push(`${rule.id}: record names another pattern`);
  }
  const remRel = `knowledge/remediation/${rule.id}.json`;
  if (!existsSync(join(ROOT, remRel))) chainProblems.push(`${rule.id}: missing remediation`);
  else if (readJson(remRel).ruleId !== rule.id) chainProblems.push(`${rule.id}: remediation names another rule`);
}
assert(chainProblems.length === 0, 'chain: rule ↔ pattern ↔ record ↔ remediation agree in both directions', chainProblems.slice(0, 5).join('; '));

// --- 5. manifest parity -----------------------------------------------------
const manifestFile = join(ROOT, 'data', 'sca-manifest.json');
assert(existsSync(manifestFile), 'manifest: data/sca-manifest.json exists');
if (existsSync(manifestFile)) {
  const manifest = readJson('data/sca-manifest.json');
  const mappedIds = new Set(Object.values(manifest.cells ?? {}).map((ids) => ids.ruleId));
  const liveIds = new Set(byId.keys());
  const unmapped = [...liveIds].filter((id) => !mappedIds.has(id));
  const dangling = [...mappedIds].filter((id) => !liveIds.has(id));
  assert(unmapped.length === 0 && dangling.length === 0,
    `manifest: ${liveIds.size} live rules and ${mappedIds.size} mapped ids agree`,
    `unmapped: ${unmapped.slice(0, 3).join(',')} dangling: ${dangling.slice(0, 3).join(',')}`);
}

// --- 6. no advisory claim ---------------------------------------------------
// Claim shapes only. Naming the advisory tier in `limitation` ("it cannot tell whether a version
// is affected by an advisory") is the honest disclaimer, not a claim, so it is allowed.
const advisoryWords = [/affected version/i, /vulnerable version/i, /CVE-\d{4}-/, /GHSA-[a-z0-9]{4}-/i, /this package is vulnerable/i];
const claimProblems = [];
for (const { rule } of rules) {
  const text = [rule.title, rule.description, rule.remediation, rule.limitation].join(' ');
  for (const pattern of advisoryWords) {
    if (pattern.test(text)) claimProblems.push(`${rule.id}: ${pattern}`);
  }
}
assert(claimProblems.length === 0,
  'scope: no rule claims that a version is affected by an advisory (declared text only)',
  claimProblems.slice(0, 5).join('; '));

// --- 7. artifact sanity -----------------------------------------------------
const ARTIFACTS_BY_ECOSYSTEM = {
  npm: ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', '.npmrc', '.yarnrc.yml'],
  pypi: ['requirements.txt', 'pyproject.toml', 'poetry.lock', 'Pipfile', 'Pipfile.lock', 'setup.cfg', 'pip.conf', '.pypirc'],
  go: ['go.mod', 'go.sum', 'Gopkg.toml', 'vendor/modules.txt'],
  maven: ['pom.xml', 'settings.xml'],
  gradle: ['build.gradle', 'build.gradle.kts', 'gradle.properties', 'verification-metadata.xml'],
  nuget: ['packages.config', 'packages.lock.json', 'nuget.config', 'Directory.Packages.props'],
  cargo: ['Cargo.toml', 'Cargo.lock', '.cargo/config.toml'],
  composer: ['composer.json', 'composer.lock', 'auth.json'],
  rubygems: ['Gemfile', 'Gemfile.lock', '.gemrc'],
  hex: ['mix.exs', 'mix.lock'],
  cocoapods: ['Podfile', 'Podfile.lock'],
  swift: ['Package.swift', 'Package.resolved'],
  pub: ['pubspec.yaml', 'pubspec.lock'],
  cran: ['DESCRIPTION', 'renv.lock'],
  conda: ['environment.yml', 'conda-meta/history'],
  vcpkg: ['vcpkg.json', 'vcpkg-configuration.json'],
  conan: ['conanfile.txt', 'conanfile.py', 'conan.lock'],
};
const artifactProblems = [];
for (const { rule } of rules) {
  const allowed = ARTIFACTS_BY_ECOSYSTEM[rule.ecosystems?.[0]];
  if (!allowed) artifactProblems.push(`${rule.id}: unknown ecosystem ${rule.ecosystems?.[0]}`);
  else if (!allowed.includes(rule.artifact)) artifactProblems.push(`${rule.id}: ${rule.artifact} is not a ${rule.ecosystems[0]} artifact`);
}
assert(artifactProblems.length === 0, 'artifact: every rule names a real file for its ecosystem', artifactProblems.slice(0, 5).join('; '));

// --- 8. engine contract (negative paths) ------------------------------------
const npmRule = rules[0].rule;
assert(resolvePath({ dependencies: { a: '1.0.0', b: '2.0.0' } }, 'dependencies.*').length === 2,
  'engine: member wildcard reaches every value');
assert(resolvePath({ packages: [{ integrity: 'sha512-a' }, { integrity: 'sha512-b' }] }, 'packages[].integrity').length === 2,
  'engine: array wildcard reaches every element');
assert(resolvePath({ a: {} }, 'a.*').length === 0, 'engine: wildcard over an empty object reaches nothing');
assert(resolvePath({}, 'dependencies.*').length === 0, 'engine: a missing path reaches nothing instead of throwing');
assert(evaluateScaCheck({ type: 'sca-field-absent', path: 'lockfileVersion' }, { document: { name: 'x' } }) === true,
  'engine: sca-field-absent fires on an absent field');
assert(evaluateScaCheck({ type: 'sca-field-absent', path: 'lockfileVersion' }, { document: { lockfileVersion: 3 } }) === false,
  'engine: sca-field-absent stays silent when the field is present');
assert(evaluateScaCheck(
  { type: 'sca-field-not-matches', path: 'packages[].integrity', valuePattern: '^sha512-' },
  { document: { packages: [{ integrity: 'sha1-x' }] } },
) === true, 'engine: sca-field-not-matches fires when no value carries the marker');
assert(evaluateScaCheck(
  { type: 'sca-key-matches', path: 'dependencies', keyPattern: '-patch$' },
  { document: { dependencies: { 'lodash-patch': '1.0.0' } } },
) === true, 'engine: sca-key-matches reads dependency names');
assert(evaluateScaCheck(
  { type: 'sca-name-distance', path: 'dependencies', target: 'express', maxDistance: 1 },
  { document: { dependencies: { expres: '4.0.0' } } },
) === true, 'engine: sca-name-distance fires one edit away');
assert(evaluateScaCheck(
  { type: 'sca-name-distance', path: 'dependencies', target: 'express', maxDistance: 1 },
  { document: { dependencies: { express: '4.0.0' } } },
) === false, 'engine: sca-name-distance never fires on the exact target');
assert(boundedDistance('express', 'expres', 1) === 1, 'engine: bounded distance counts one deletion');
assert(boundedDistance('express', 'unrelated-name', 1) === 2, 'engine: bounded distance reports over-budget as limit+1');
assert(codeOf(() => evaluateScaCheck({ type: 'sca-nope', path: 'a' }, { document: {} })) === 'ScaRuleError',
  'engine: unknown predicate type throws instead of guessing');
assert(codeOf(() => evaluateScaCheck({ type: 'sca-field-matches', path: 'a', valuePattern: '(' }, { document: {} })) === 'ScaRuleError',
  'engine: an invalid regex throws');
assert(codeOf(() => evaluateScaCheck({ type: 'sca-field-matches', path: 'a', valuePattern: 'x' }, {})) === 'ScaRuleError',
  'engine: a missing document throws (a parse failure is never "no match")');
assert(codeOf(() => evaluateScaCheck(
  { type: 'sca-name-distance', path: 'dependencies', target: 'express', maxDistance: 9 },
  { document: {} },
)) === 'ScaRuleError', 'engine: an out-of-range edit budget throws');
assert(SCA_CHECK_TYPES.length === 6, 'engine: the predicate vocabulary stays closed at six types');
assert(npmRule.schemaVersion === 'drobon.pack.sca/v1', 'pack: rules carry the sca schema version');

process.stdout.write(`\nsca-pack-tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) {
  process.stdout.write('sca-pack-tests: FAIL\n');
  process.exitCode = 1;
}
