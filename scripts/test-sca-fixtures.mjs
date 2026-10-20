#!/usr/bin/env node
/**
 * test-sca-fixtures.mjs — contract tests for the offline SCA fixture corpus
 * (data/sca-fixtures/*.json) and the identity / dependency logic that backs it.
 *
 * Scope: original logic + synthetic fixtures only. No real advisory data, no
 * package metadata, no network, no third-party identifiers. Every refusal is
 * proven as a refusal, and the corpus is checked to be synthetically labelled
 * before any case is executed.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SCA_DATASET_STATUS,
  canonicalPackageName,
  createSyntheticProvider,
  resolveAlias,
  resolveDependencyGraph,
  validateSyntheticRecord,
} from './sca-engine.mjs';
import { satisfiesRange, validateRange } from './range.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let passed = 0;
let failed = 0;
function assert(condition, name, detail = '') {
  if (condition) {
    passed += 1;
    process.stdout.write(`ok - ${name}\n`);
  } else {
    failed += 1;
    process.stdout.write(`FAIL - ${name}${detail === '' ? '' : `\n    ${detail}`}\n`);
  }
}
const readCorpus = (name) => JSON.parse(readFileSync(join(ROOT, 'data', 'sca-fixtures', name), 'utf8'));

const files = ['coordinates.json', 'ranges.json', 'dependencies.json', 'aliases.json', 'advisories.json', 'cycles.json', 'edges.json', 'collisions.json', 'direct-flags.json'];
const corpora = Object.fromEntries(files.map((f) => [f, readCorpus(f)]));

// --- 1. corpus integrity ----------------------------------------------------
for (const file of files) {
  const doc = corpora[file];
  assert(doc.schemaVersion === 'drobon.sca.fixture-corpus/v1', `corpus: ${file} carries the fixture schema`);
  assert(doc.synthetic === true && doc.productionData === false,
    `corpus: ${file} is labelled synthetic and not production data`);
  assert(typeof doc.note === 'string' && doc.note.length > 40, `corpus: ${file} states its synthetic scope`);
}
const corpusText = files.map((f) => readFileSync(join(ROOT, 'data', 'sca-fixtures', f), 'utf8')).join('\n');
for (const pattern of ['GHSA-', 'CVE-', 'OSV-', 'DSA-', 'RUSTSEC-']) {
  assert(!corpusText.includes(pattern), `corpus: no third-party identifier shape (${pattern})`);
}

// --- 2. coordinate normalisation -------------------------------------------
const coordCases = corpora['coordinates.json'].cases;
assert(coordCases.length >= 12, `coordinates: corpus has boundary breadth (${coordCases.length} cases)`);
assert(new Set(coordCases.map((c) => c.id)).size === coordCases.length, 'coordinates: case ids are unique');
for (const testCase of coordCases) {
  const result = canonicalPackageName(testCase.ecosystem, testCase.input);
  if (testCase.expected.ok) {
    assert(result.ok === true && result.name === testCase.expected.name,
      `coordinates: ${testCase.id} canonicalises to ${testCase.expected.name}`, JSON.stringify(result));
  } else {
    assert(result.ok === false && result.code === testCase.expected.code,
      `coordinates: ${testCase.id} is refused with ${testCase.expected.code}`, JSON.stringify(result));
  }
  assert(typeof testCase.reason === 'string' && testCase.reason.length > 10, `coordinates: ${testCase.id} documents its reason`);
}
assert(canonicalPackageName('pypi', 'Django').name === canonicalPackageName('pypi', 'django').name,
  'coordinates: pypi normalisation is case-insensitive and stable');
assert(canonicalPackageName('npm', '@scope/pkg').ok === false,
  'coordinates: scoped npm names are refused rather than mangled');
assert(canonicalPackageName('maven', 'x').ok === false,
  'coordinates: an unsupported ecosystem never resolves');

// --- 3. alias / canonical identity -----------------------------------------
const aliasTable = corpora['aliases.json'].table;
const aliasCases = corpora['aliases.json'].cases;
assert(aliasCases.length >= 6, `aliases: identity cases present (${aliasCases.length})`);
for (const testCase of aliasCases) {
  const result = resolveAlias(aliasTable, testCase.ecosystem, testCase.input);
  assert(result.ok === true && result.name === testCase.expected.name && result.via === testCase.expected.via,
    `aliases: ${testCase.id} resolves to ${testCase.expected.name} via ${testCase.expected.via}`, JSON.stringify(result));
}
assert(resolveAlias(aliasTable, 'npm', 'broken-entry').name === 'broken-entry',
  'aliases: a malformed table entry is ignored, never guessed');
assert(resolveAlias(aliasTable, 'npm', '@scope/pkg').ok === false,
  'aliases: an unsupported identity is refused before lookup');
assert(resolveAlias('not-a-table', 'pypi', 'bs4').ok === false,
  'aliases: a non-array table is refused');

// --- 4. version-range boundaries -------------------------------------------
const rangeCases = corpora['ranges.json'].cases;
assert(rangeCases.length >= 16, `ranges: boundary corpus breadth (${rangeCases.length})`);
for (const testCase of rangeCases) {
  const actual = satisfiesRange(testCase.ecosystem, testCase.version, testCase.range);
  assert(actual === testCase.expected,
    `ranges: ${testCase.id} ${testCase.ecosystem} ${testCase.version} in ${testCase.range} is ${testCase.expected}`,
    `got ${actual}`);
}
for (const bad of corpora['ranges.json'].invalidRanges) {
  const reason = validateRange(bad.ecosystem, bad.range);
  assert(reason !== null && reason.includes(bad.reasonFragment),
    `ranges: ${bad.id} rejects ${bad.range} with a specific reason`, String(reason));
}
assert(new Set(rangeCases.map((c) => c.ecosystem)).size === 2, 'ranges: both ecosystems are exercised');
assert(rangeCases.some((c) => c.range.includes('-')) && rangeCases.some((c) => c.range.includes('||')),
  'ranges: hyphen and OR branches are exercised');

// --- 5. dependency graph ---------------------------------------------------
const graph = resolveDependencyGraph(corpora['dependencies.json'].entries);
const expectedGraph = corpora['dependencies.json'].expected;
assert(graph.nodes.length === expectedGraph.nodes, `graph: ${expectedGraph.nodes} unique nodes`, String(graph.nodes.length));
assert(graph.direct.length === expectedGraph.direct, `graph: ${expectedGraph.direct} direct roots`, String(graph.direct.length));
assert(graph.transitive.length === expectedGraph.transitive, `graph: ${expectedGraph.transitive} transitive nodes`, String(graph.transitive.length));
assert(graph.unreachable.length === expectedGraph.unreachable, `graph: ${expectedGraph.unreachable} unreachable node`, JSON.stringify(graph.unreachable));
assert(graph.duplicates.length === expectedGraph.duplicates, `graph: ${expectedGraph.duplicates} duplicate coordinates recorded`, JSON.stringify(graph.duplicates));
assert(graph.invalid.length === expectedGraph.invalid, `graph: ${expectedGraph.invalid} invalid entry recorded`, JSON.stringify(graph.invalid));
assert(JSON.stringify(graph.conflicts) === JSON.stringify(expectedGraph.conflicts), 'graph: conflicting versions are reported exactly');
assert(graph.rangeIssues.length === expectedGraph.rangeIssues.length, 'graph: every range issue is reported');
assert(JSON.stringify(graph.rangeIssues) === JSON.stringify(expectedGraph.rangeIssues),
  'graph: range issues carry from/missing/reason in deterministic order', JSON.stringify(graph.rangeIssues));
assert(graph.nodes.every((node, i) => i === 0 || graph.nodes[i - 1].id <= node.id), 'graph: nodes are sorted by id');
assert(graph.nodes.some((node) => node.name === 'requests'), 'graph: pypi normalisation applies inside the graph');
assert(graph.invalid.some((line) => line.includes('bad name')), 'graph: an invalid name is reported, not dropped');
const graphAgain = resolveDependencyGraph(corpora['dependencies.json'].entries);
assert(JSON.stringify(graph) === JSON.stringify(graphAgain), 'graph: identical input yields byte-identical output');
assert(Object.isFrozen(graph) && Object.isFrozen(graph.nodes), 'graph: result is frozen');
assert(resolveDependencyGraph([]).nodes.length === 0, 'graph: an empty listing resolves to an empty graph');
let threw = false;
try { resolveDependencyGraph('nope'); } catch { threw = true; }
assert(threw, 'graph: a non-array listing is refused');

// --- 5b. dependency cycles (explicit SCC reporting) -------------------------
{
  const cycleCorpus = corpora['cycles.json'];
  const cycleGraph = resolveDependencyGraph(cycleCorpus.entries);
  assert(cycleGraph.nodes.length === cycleCorpus.expected.nodes,
    `cycles: ${cycleCorpus.expected.nodes} unique nodes`, String(cycleGraph.nodes.length));
  assert(JSON.stringify(cycleGraph.cycles) === JSON.stringify(cycleCorpus.expected.cycles),
    'cycles: the two-package cycle and the self-edge are reported exactly', JSON.stringify(cycleGraph.cycles));
  assert(cycleGraph.cycles.every((c) => c.reason === 'DEPENDENCY_CYCLE'),
    'cycles: every component carries the DEPENDENCY_CYCLE reason');
  assert(Array.isArray(cycleGraph.cycles) && cycleGraph.cycles.every(Object.isFrozen),
    'cycles: components are frozen');
  assert(JSON.stringify(cycleGraph.unreachable) === JSON.stringify(cycleCorpus.expected.unreachable),
    'cycles: a node outside the cycle and outside reach is only unreachable', JSON.stringify(cycleGraph.unreachable));
  assert(cycleGraph.rangeIssues.length === 0, 'cycles: in-range edges produce no range issue');
  assert(JSON.stringify(resolveDependencyGraph(cycleCorpus.entries)) === JSON.stringify(cycleGraph),
    'cycles: identical input yields byte-identical cycle output');
}

// --- 5c. ambiguous aliases fail closed -------------------------------------
{
  const table = corpora['aliases.json'].table;
  const expected = corpora['aliases.json'].expectedAmbiguity;
  if (expected !== undefined) {
    const ambiguous = resolveAlias(table, 'pypi', expected.alias);
    assert(ambiguous.ok === false && ambiguous.code === expected.reason,
      'aliases: two entries claiming one alias are refused, never resolved by table order', JSON.stringify(ambiguous));
    const repeated = resolveAlias(table, 'pypi', 'twice');
    assert(repeated.ok === true && repeated.name === 'repeat-target',
      'aliases: the same target declared twice is not ambiguous', JSON.stringify(repeated));
  }
}

// --- 5d. duplicate graph edges collapse deterministically ------------------
{
  const edgeDoc = corpora['edges.json'];
  const graph = resolveDependencyGraph(edgeDoc.entries);
  assert(graph.nodes.length === edgeDoc.expected.nodes,
    `edges: ${edgeDoc.expected.nodes} unique nodes`, String(graph.nodes.length));
  const root = graph.nodes.find((n) => n.name === 'dup-root');
  assert(root !== undefined && root.requires.length === edgeDoc.expected.requiresForRoot,
    'edges: a repeated target+range pair collapses to one edge', JSON.stringify(root?.requires));
  assert(graph.rangeIssues.length === edgeDoc.expected.rangeIssues,
    'edges: the distinct range still reports its mismatch once', JSON.stringify(graph.rangeIssues));
  assert(JSON.stringify(resolveDependencyGraph(edgeDoc.entries)) === JSON.stringify(graph),
    'edges: duplicate-edge resolution is byte-identical across runs');
}

// --- 5e. ecosystem-scoped identity, edges and aliases ----------------------
{
  const collisionDoc = corpora['collisions.json'];
  const graph = resolveDependencyGraph(collisionDoc.entries);
  assert(graph.nodes.length === collisionDoc.expected.nodes,
    'collisions: one name in two ecosystems produces separate nodes', String(graph.nodes.length));
  const npmNodes = graph.nodes.filter((n) => n.ecosystem === 'npm' && n.name === 'shared-name');
  assert(npmNodes.length === collisionDoc.expected.npmVersions,
    'collisions: versions of one ecosystem stay on that ecosystem', String(npmNodes.length));
  const pypiNode = graph.nodes.find((n) => n.ecosystem === 'pypi' && n.name === 'shared-name');
  assert(pypiNode !== undefined, 'collisions: the other ecosystem keeps its own node');
  const root = npmNodes.find((n) => n.version === '1.0.0');
  assert(root !== undefined && root.requires[0].ecosystem === 'pypi',
    'collisions: an edge stays inside its declared ecosystem', JSON.stringify(root?.requires));
  assert(graph.conflicts.length === collisionDoc.expected.conflicts
    && graph.conflicts[0].package === 'npm:shared-name',
    'collisions: conflicting versions are reported per ecosystem', JSON.stringify(graph.conflicts));
  assert(graph.cycles.length === collisionDoc.expected.cycles,
    'collisions: a same-name dependency in another ecosystem is not a cycle');
  const table = corpora['aliases.json'].table;
  const npmAlias = resolveAlias(table, 'npm', 'shared');
  const pypiAlias = resolveAlias(table, 'pypi', 'shared');
  assert(npmAlias.ok === true && pypiAlias.ok === true
    && npmAlias.name === 'npm-shared' && pypiAlias.name === 'pypi-shared',
    'aliases: the same alias resolves differently per ecosystem');
}

// --- 5f. duplicate coordinates with conflicting direct flags ----------------
// A coordinate declared twice must resolve to one classification regardless of
// listing order (SCA-CONTRACT-01). Direct is a monotone property: any declaration
// that says direct makes the coordinate a root, and the duplicate is still noted.
{
  const doc = corpora['direct-flags.json'];
  const byId = Object.fromEntries(doc.scenarios.map((scenario) => [scenario.id, scenario.entries]));
  const first = resolveDependencyGraph(byId['direct-first']);
  const last = resolveDependencyGraph(byId['direct-last']);
  const transitiveOnly = resolveDependencyGraph(byId['all-transitive']);
  assert(JSON.stringify(first.direct) === JSON.stringify(doc.expected.directForOrderA),
    'direct-flags: direct declared first makes the coordinate a root', JSON.stringify(first.direct));
  assert(JSON.stringify(last.direct) === JSON.stringify(doc.expected.directForOrderA),
    'direct-flags: the same flag declared last resolves identically', JSON.stringify(last.direct));
  assert(JSON.stringify(first) === JSON.stringify(last),
    'direct-flags: resolution is byte-identical under a reordered listing');
  assert(JSON.stringify(transitiveOnly.direct) === JSON.stringify(doc.expected.directForOrderB),
    'direct-flags: a coordinate never declared direct stays transitive',
    JSON.stringify(transitiveOnly.direct));
  assert(first.duplicates.includes(doc.expected.duplicateNoted[0])
    && transitiveOnly.duplicates.includes(doc.expected.duplicateNoted[1]),
    'direct-flags: the duplicate coordinate is still reported',
    JSON.stringify({ a: first.duplicates, b: transitiveOnly.duplicates }));
  assert(first.nodes.length === 1 && transitiveOnly.nodes.length === 1,
    'direct-flags: a duplicate coordinate produces one node',
    String(first.nodes.length) + '/' + String(transitiveOnly.nodes.length));
}

// --- 6. advisory provider over the fixture corpus --------------------------
const records = corpora['advisories.json'].records;
assert(records.length >= 4, `advisories: corpus breadth (${records.length} records)`);
for (const [index, record] of records.entries()) {
  const reasons = validateSyntheticRecord(record);
  assert(reasons.length === 0, `advisories: record[${index}] validates as a synthetic fixture`, reasons.join('; '));
}
const provider = createSyntheticProvider(records);
assert(provider.datasetStatus === SCA_DATASET_STATUS.ASSESSED, 'advisories: a loaded corpus reports ASSESSED');
for (const testCase of corpora['advisories.json'].cases) {
  const answer = provider.assess(testCase.coordinate);
  assert(answer.datasetStatus === testCase.expected.status,
    `advisories: ${testCase.id} reports ${testCase.expected.status}`, answer.datasetStatus);
  assert(JSON.stringify(answer.advisories.map((a) => a.id)) === JSON.stringify(testCase.expected.ids),
    `advisories: ${testCase.id} matches ${JSON.stringify(testCase.expected.ids)}`,
    JSON.stringify(answer.advisories.map((a) => a.id)));
}
const ordered = provider.assess({ ecosystem: 'npm', name: 'left-pad', version: '1.2.5' }).advisories;
assert(ordered[0].severity === 'HIGH' && ordered[1].severity === 'LOW', 'advisories: severity ordering is deterministic');
assert(provider.assess({ ecosystem: 'npm', name: 'left-pad', version: '1.2.5' }).advisories.every((a) => a.range !== undefined),
  'advisories: each match carries the range that produced it');
const emptyProvider = createSyntheticProvider([]);
assert(emptyProvider.assess({ ecosystem: 'npm', name: 'lodash', version: '4.17.21' }).datasetStatus === SCA_DATASET_STATUS.NO_DATA_LOADED,
  'advisories: an empty corpus reports NO_DATA_LOADED, never a clean bill of health');
const partial = provider.assess({ ecosystem: 'npm', name: 'left-pad', version: '1.2' });
assert(partial.datasetStatus === SCA_DATASET_STATUS.NOT_ASSESSED && partial.advisories.length === 0,
  'advisories: an unprovable version is NOT_ASSESSED with no advisories');
const realStyle = { ...records[0], fixture: false, id: 'DROBON-SAMPLE-999' };
assert(validateSyntheticRecord(realStyle).some((reason) => reason.includes('REAL_RECORD_REFUSED')),
  'advisories: a non-fixture record is refused at validation');
let refused = false;
try { createSyntheticProvider([realStyle]); } catch { refused = true; }
assert(refused, 'advisories: the provider refuses to be constructed over non-fixture records');
const firstPass = JSON.stringify(provider.assess({ ecosystem: 'npm', name: 'left-pad', version: '1.2.5' }));
const secondPass = JSON.stringify(provider.assess({ ecosystem: 'npm', name: 'left-pad', version: '1.2.5' }));
assert(firstPass === secondPass, 'advisories: repeated assessments are byte-identical');

// --- 7. no network / no live feed -----------------------------------------
const engineSource = readFileSync(join(ROOT, 'scripts', 'sca-engine.mjs'), 'utf8')
  + readFileSync(join(ROOT, 'scripts', 'range.mjs'), 'utf8');
for (const token of ['node:http', 'node:https', 'node:net', 'node:tls', 'fetch(', 'XMLHttpRequest']) {
  assert(!engineSource.includes(token), `offline: the SCA engine never imports ${token}`);
}
assert(!corpusText.includes('https://'), 'offline: the fixture corpus carries no remote references');

// --- summary ---------------------------------------------------------------
process.stdout.write(`\nsca-fixtures: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
