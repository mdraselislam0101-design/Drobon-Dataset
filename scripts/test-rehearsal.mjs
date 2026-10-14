/**
 * Synthetic ingestion rehearsal runner (1K + 10K scales).
 *
 * Exercises generation, validation, grouping, manifests, pagination,
 * incremental merge, interrupted recovery, invalid-input rejection, and
 * production isolation using deterministic synthetic corpora in tmp dirs.
 * Rehearsal corpora are NEVER committed and NEVER counted as production:
 * ids `SYNTH-*`, source `synthetic-rehearsal`, example.invalid URLs.
 * A green rehearsal proves the harness - never production authorization.
 */
import { appendFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateRecord } from './validate.mjs';
import { countAdvisoryItems, groupAdvisoryRecords, groupFiles, identityOf } from './dedup-report.mjs';
import { computeManifest, verifyManifest } from './manifest.mjs';
import { generateCorpus, REHEARSAL_SOURCE } from './rehearse.mjs';
import { backoffDelayMs, HttpError, isTransientError, MAX_ATTEMPTS, RETRY_DELAYS_MS, withRetries } from './retry.mjs';
import { appendCursor, lastCursorFor, loadCheckpoint } from './checkpoint.mjs';
import { listQuarantined, quarantineRecord } from './quarantine.mjs';
import { fetchAdvisories, parseLinkNext, parseArgs as parseGhsaArgs } from './import-ghsa.mjs';
import { fetchOsvForPackage, parseArgs as parseOsvArgs } from './import-osv.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let passed = 0;
let failed = 0;

function assert(condition, message, detail = '') {
  if (condition) {
    passed += 1;
    process.stdout.write(`ok - ${message}\n`);
  } else {
    failed += 1;
    process.stdout.write(`FAIL - ${message}\n`);
    if (detail) {
      process.stdout.write(`    ${detail}\n`);
    }
  }
}

function collectFiles(dir) {
  const found = [];
  const walk = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    )) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith('.json')) found.push(full);
    }
  };
  walk(dir);
  return found;
}

function readRecord(file) {
  return JSON.parse(readFileSync(file, 'utf8'));
}

function validateAll(files) {
  const bad = [];
  for (const file of files) {
    const errors = validateRecord(readRecord(file));
    if (errors.length > 0) bad.push(`${file}: ${errors.join('; ')}`);
  }
  return bad;
}

const scratch = mkdtempSync(join(tmpdir(), 'drobon-rehearse-'));

// --- 1. deterministic 1K generation ------------------------------------------
const gen1k = join(scratch, 'gen-1k');
const stats1k = generateCorpus({ seed: 42, count: 1000, outDir: gen1k });
assert(stats1k.files === 1017 && stats1k.primary === 1000 && stats1k.extra === 17,
  `rehearsal: 1K gen produces 1017 files / 1000 primary / 17 extra (got ${stats1k.files}/${stats1k.primary}/${stats1k.extra})`);
const gen1kAgain = join(scratch, 'gen-1k-again');
generateCorpus({ seed: 42, count: 1000, outDir: gen1kAgain });
const manifest1kA = computeManifest(gen1k, 'records');
const manifest1kB = computeManifest(gen1kAgain, 'records');
assert(JSON.stringify(manifest1kA) === JSON.stringify(manifest1kB), 'rehearsal: 1K generation is byte-deterministic across runs');
const genOtherSeed = join(scratch, 'gen-other-seed');
generateCorpus({ seed: 43, count: 1000, outDir: genOtherSeed });
assert(JSON.stringify(computeManifest(genOtherSeed, 'records')) !== JSON.stringify(manifest1kA),
  'rehearsal: different seeds produce different corpora (seed matters)');
assert(verifyManifest(gen1k, manifest1kA).ok, 'rehearsal: 1K manifest verifies against its tree');

// --- 2. schema validation of every synthetic record --------------------------
const files1k = collectFiles(join(gen1k, 'vuln-intel'));
assert(files1k.length === 1017, `rehearsal: 1K tree holds 1017 files (got ${files1k.length})`);
const bad1k = validateAll(files1k);
assert(bad1k.length === 0, `rehearsal: all 1017 synthetic records validate (${bad1k.length} bad)`, bad1k.slice(0, 3).join(' | '));

// --- 3. grouping: files vs items, shards, splits, aliases --------------------
const group1k = groupAdvisoryRecords(gen1k);
assert(group1k.items.length === 1000, `rehearsal: 1K groups to 1000 items (got ${group1k.items.length})`);
assert(group1k.multiFile.length === 17, `rehearsal: 1K has 17 multi-file tuples (got ${group1k.multiFile.length})`);
assert(group1k.conflicts.length === 0, 'rehearsal: 1K has zero conflicting tuples (shards differ only in affected)');
const extraAccounted = group1k.multiFile.reduce((sum, item) => sum + (item.files.length - 1), 0);
assert(extraAccounted === 17, `rehearsal: all 17 extra files land on existing tuples (got ${extraAccounted})`);
const aliasRecord = readRecord(join(gen1k, 'vuln-intel', 'npm', 'SYNTH-000251.json'));
const aliasPartner = readRecord(join(gen1k, 'vuln-intel', 'npm', 'SYNTH-000241.json'));
assert(aliasRecord.package === aliasPartner.package && aliasRecord.affected[0].range === aliasPartner.affected[0].range,
  'rehearsal: alias pair shares package+range by construction');
assert(JSON.stringify(identityOf(aliasRecord)) !== JSON.stringify(identityOf(aliasPartner)),
  'rehearsal: alias pair keeps distinct identities (manual-review boundary, never auto-merged)');
const splitRecord = readRecord(join(gen1k, 'vuln-intel', 'npm', 'SYNTH-000204.json'));
const splitBase = readRecord(join(gen1k, 'vuln-intel', 'pypi', 'SYNTH-000204.json'));
assert(splitRecord.id === splitBase.id && splitRecord.package === 'synth-split-02' && splitBase.package === 'synth-pkg-03',
  'rehearsal: cross-package split twin shares the id with a different package');

// --- 4. pagination, incremental merge, interrupted recovery -------------------
const sorted1k = [...files1k].sort();
const pageSize = 250;
const pagedGroups = [];
for (let page = 0; page * pageSize < sorted1k.length; page += 1) {
  pagedGroups.push(groupFiles(sorted1k.slice(page * pageSize, (page + 1) * pageSize), gen1k));
}
assert(pagedGroups.length === 5, `rehearsal: 1017 files paginate into 5 pages of <=250 (got ${pagedGroups.length})`);
const pagedFiles = pagedGroups.reduce((sum, page) => sum + page.files, 0);
assert(pagedFiles === 1017, `rehearsal: paged processing covers all 1017 files (got ${pagedFiles})`);
const mergedFromPages = groupFiles(sorted1k, gen1k);
assert(mergedFromPages.items.length === group1k.items.length, 'rehearsal: paged merge equals single-shot grouping');
const batchA = join(scratch, 'batch-a');
const batchB = join(scratch, 'batch-b');
generateCorpus({ seed: 1, count: 500, outDir: batchA, idPrefix: 'SYN-A' });
generateCorpus({ seed: 2, count: 500, outDir: batchB, idPrefix: 'SYN-B' });
const filesA = collectFiles(join(batchA, 'vuln-intel'));
for (const file of filesA.slice(0, 50)) {
  const rel = file.split('vuln-intel/')[1];
  const dest = join(batchB, 'vuln-intel', rel);
  mkdirSync(dirname(dest), { recursive: true });
  cpSync(file, dest);
}
const groupA = groupAdvisoryRecords(batchA);
const groupB = groupAdvisoryRecords(batchB);
const mergedAB = groupFiles([...filesA, ...collectFiles(join(batchB, 'vuln-intel'))], scratch);
assert(mergedAB.items.length === groupA.items.length + groupB.items.length - 50,
  `rehearsal: incremental merge dedups 50 re-delivered files (got ${mergedAB.items.length})`);
const crashDir = join(scratch, 'crash');
mkdirSync(join(crashDir, 'vuln-intel', 'npm'), { recursive: true });
mkdirSync(join(crashDir, 'vuln-intel', 'pypi'), { recursive: true });
const crashPages = [sorted1k.slice(0, 300), sorted1k.slice(300, 600), sorted1k.slice(600, 900), sorted1k.slice(900)];
for (const file of crashPages.slice(0, 3).flat()) {
  const rel = file.split('vuln-intel/')[1];
  cpSync(file, join(crashDir, 'vuln-intel', rel));
}
assert(collectFiles(join(crashDir, 'vuln-intel')).length === 900, 'rehearsal: interrupted batch holds 900/1017 files (no manifest = crashed)');
for (const file of crashPages[3]) {
  const rel = file.split('vuln-intel/')[1];
  cpSync(file, join(crashDir, 'vuln-intel', rel));
}
const crashManifest = computeManifest(crashDir, 'records');
assert(verifyManifest(crashDir, crashManifest).ok, 'rehearsal: resumed batch manifests + verifies (recovery)');
assert(groupAdvisoryRecords(crashDir).items.length === 1000, 'rehearsal: resumed batch groups to the same 1000 items');

// --- 5. invalid input rejection (synthetic bad records) -----------------------
const goodRecord = readRecord(files1k[0]);
const badCases = {
  'not-an-object': 42,
  'missing-provenance': { ...goodRecord, provenance: undefined },
  'bad-range': { ...goodRecord, affected: [{ range: '>>> nope <<<' }] },
  'bad-severity': { ...goodRecord, severity: 'CATASTROPHIC' },
  'control-char': { ...goodRecord, summary: 'bad\u0007summary' },
  'unknown-property': { ...goodRecord, aliases: ['X'] },
};
let badRejected = 0;
for (const [name, value] of Object.entries(badCases)) {
  if (validateRecord(value).length > 0) badRejected += 1;
  else process.stdout.write(`    class accepted unexpectedly: ${name}\n`);
}
assert(badRejected === 6, `rehearsal: 6/6 malformed classes rejected (got ${badRejected}/6)`);
assert(validateRecord(goodRecord).length === 0, 'rehearsal: valid synthetic control record passes');

// --- 6. manifest tamper / missing / extra on a rehearsal tree -----------------
const tamperDir = join(scratch, 'tamper');
cpSync(join(gen1k, 'vuln-intel'), join(tamperDir, 'vuln-intel'), { recursive: true });
const tamperManifest = computeManifest(tamperDir, 'records');
const victim = join(tamperDir, tamperManifest.files[0].path);
appendFileSync(victim, ' ');
const tamperCheck = verifyManifest(tamperDir, tamperManifest);
assert(!tamperCheck.ok && tamperCheck.problems.length === 1 && tamperCheck.problems[0].startsWith('tampered:'),
  'rehearsal: manifest catches a tampered rehearsal file', tamperCheck.problems.join('; '));
const missingDir = join(scratch, 'missing');
cpSync(join(gen1k, 'vuln-intel'), join(missingDir, 'vuln-intel'), { recursive: true });
rmSync(join(missingDir, tamperManifest.files[1].path));
const missingCheck = verifyManifest(missingDir, tamperManifest);
assert(!missingCheck.ok && missingCheck.problems.some((problem) => problem.startsWith('missing:')),
  'rehearsal: manifest catches a missing rehearsal file', missingCheck.problems.join('; '));
const extraDir = join(scratch, 'extra');
cpSync(join(gen1k, 'vuln-intel'), join(extraDir, 'vuln-intel'), { recursive: true });
writeFileSync(join(extraDir, 'vuln-intel', 'npm', 'SYNTH-INTRUDER.json'), '{}\n');
const extraCheck = verifyManifest(extraDir, tamperManifest);
assert(!extraCheck.ok && extraCheck.problems.some((problem) => problem.startsWith('extra:')),
  'rehearsal: manifest catches an extra rehearsal file', extraCheck.problems.join('; '));

// --- 7. production isolation --------------------------------------------------
assert(countAdvisoryItems(ROOT) === 84, `rehearsal: repo recount still 84 items after rehearsals (got ${countAdvisoryItems(ROOT)})`);
const markersOk = files1k.every((file) => {
  const record = readRecord(file);
  return record.id.startsWith('SYN') && record.provenance.source === REHEARSAL_SOURCE;
});
assert(markersOk, 'rehearsal: all 1017 synthetic records carry unmistakable markers');
const targetsDoc = JSON.parse(readFileSync(join(ROOT, 'docs', 'CORPUS_TARGETS.json'), 'utf8'));
assert(targetsDoc.totals.verifiedProduction === 0, 'rehearsal: verifiedProduction stays 0 (synthetic never counts)');
const repoRecordFiles = collectFiles(join(ROOT, 'vuln-intel'));
const leaks = repoRecordFiles.filter((file) => readFileSync(file, 'utf8').includes(REHEARSAL_SOURCE));
assert(repoRecordFiles.length > 0 && leaks.length === 0,
  'rehearsal: zero rehearsal markers in ' + repoRecordFiles.length + ' repo record files (no leak)');

// --- 8. bounded 10K rehearsal --------------------------------------------------
const startedAt = Date.now();
const gen10k = join(scratch, 'gen-10k');
const stats10k = generateCorpus({ seed: 7, count: 10000, outDir: gen10k });
const files10k = collectFiles(join(gen10k, 'vuln-intel'));
const bad10k = validateAll(files10k);
const group10k = groupAdvisoryRecords(gen10k);
const manifest10k = computeManifest(gen10k, 'records');
const gen10kAgain = join(scratch, 'gen-10k-again');
generateCorpus({ seed: 7, count: 10000, outDir: gen10kAgain });
const manifest10kAgain = computeManifest(gen10kAgain, 'records');
const elapsedMs = Date.now() - startedAt;
const rssMb = Math.round(process.memoryUsage().rss / 1024 / 1024);
assert(stats10k.files === 10172 && stats10k.extra === 172, `rehearsal: 10K gen produces 10172 files / 172 extra (got ${stats10k.files}/${stats10k.extra})`);
assert(bad10k.length === 0, `rehearsal: all 10172 synthetic records validate (${bad10k.length} bad)`);
assert(group10k.items.length === 10000, `rehearsal: 10K groups to 10000 items (got ${group10k.items.length})`);
assert(group10k.conflicts.length === 0, 'rehearsal: 10K has zero conflicting tuples');
assert(JSON.stringify(manifest10k) === JSON.stringify(manifest10kAgain), 'rehearsal: 10K generation is byte-deterministic');
assert(verifyManifest(gen10k, manifest10k).ok, 'rehearsal: 10K manifest verifies');
assert(rssMb < 1024, `rehearsal: 10K peak RSS ${rssMb}MB stays under 1024MB`);
assert(elapsedMs < 120000, `rehearsal: 10K completes in ${elapsedMs}ms (under 120000ms)`);

// --- 9. conflicting records ------------------------------------------------------
const conflictDir = join(scratch, 'conflict');
mkdirSync(join(conflictDir, 'vuln-intel', 'npm'), { recursive: true });
const conflictBase = readRecord(join(gen1k, 'vuln-intel', 'npm', 'SYNTH-000001.json'));
writeFileSync(join(conflictDir, 'vuln-intel', 'npm', 'SYNTH-000001.json'), JSON.stringify(conflictBase, null, 2));
const conflictRival = { ...conflictBase, severity: conflictBase.severity === 'LOW' ? 'HIGH' : 'LOW' };
writeFileSync(join(conflictDir, 'vuln-intel', 'npm', 'SYNTH-000001--2.json'), JSON.stringify(conflictRival, null, 2));
const conflictGroup = groupAdvisoryRecords(conflictDir);
assert(conflictGroup.items.length === 1, 'rehearsal: conflicting pair still groups to 1 item');
assert(
  conflictGroup.conflicts.length === 1 && conflictGroup.conflicts[0].field === 'severity',
  'rehearsal: same-tuple severity disagreement is reported as a conflict',
  JSON.stringify(conflictGroup.conflicts),
);
const shardPair = [
  join(gen1k, 'vuln-intel', 'npm', 'SYNTH-000137.json'),
  join(gen1k, 'vuln-intel', 'npm', 'SYNTH-000137--2.json'),
];
const shardPairGroup = groupFiles(shardPair, gen1k);
assert(
  shardPairGroup.items.length === 1 && shardPairGroup.conflicts.length === 0,
  'rehearsal: affected-only shard differences are NOT conflicts',
);
const summaryPairDir = join(scratch, 'conflict-summary');
mkdirSync(join(summaryPairDir, 'vuln-intel', 'npm'), { recursive: true });
const summaryRival = { ...conflictBase, summary: 'SYNTHETIC rival summary with different words.' };
writeFileSync(join(summaryPairDir, 'vuln-intel', 'npm', 'SYNTH-000001.json'), JSON.stringify(conflictBase, null, 2));
writeFileSync(join(summaryPairDir, 'vuln-intel', 'npm', 'SYNTH-000001--2.json'), JSON.stringify(summaryRival, null, 2));
const summaryPairGroup = groupAdvisoryRecords(summaryPairDir);
assert(
  summaryPairGroup.conflicts.length === 1 && summaryPairGroup.conflicts[0].field === 'summary',
  'rehearsal: same-tuple summary disagreement is reported as a conflict',
);

// --- 10. versioned rollback rehearsal -------------------------------------------------
const versionDir = join(scratch, 'versions');
const v1Dir = join(versionDir, 'v1');
mkdirSync(join(v1Dir, 'vuln-intel', 'npm'), { recursive: true });
mkdirSync(join(v1Dir, 'vuln-intel', 'pypi'), { recursive: true });
const v1Subset = collectFiles(join(gen1k, 'vuln-intel')).slice(0, 100);
for (const file of v1Subset) {
  const rel = file.split('vuln-intel/')[1];
  const dest = join(v1Dir, 'vuln-intel', rel);
  mkdirSync(dirname(dest), { recursive: true });
  cpSync(file, dest);
}
const manifestV1 = computeManifest(v1Dir, 'records');
assert(verifyManifest(v1Dir, manifestV1).ok, 'rehearsal: version v1 manifests + verifies');
const v1Items = groupAdvisoryRecords(v1Dir).items.length;
const v2Batch = collectFiles(join(gen1k, 'vuln-intel')).slice(100, 150);
for (const file of v2Batch) {
  const rel = file.split('vuln-intel/')[1];
  cpSync(file, join(v1Dir, 'vuln-intel', rel));
}
const manifestV2 = computeManifest(v1Dir, 'records');
assert(JSON.stringify(manifestV1) !== JSON.stringify(manifestV2), 'rehearsal: batch upgrade changes the manifest (v1 vs v2)');
assert(!verifyManifest(v1Dir, manifestV1).ok, 'rehearsal: v1 manifest fails against the upgraded tree (drift detected)');
for (const file of v2Batch) {
  rmSync(join(v1Dir, 'vuln-intel', file.split('vuln-intel/')[1]));
}
assert(verifyManifest(v1Dir, manifestV1).ok, 'rehearsal: rollback restores v1 bytes (v1 manifest verifies again)');
assert(groupAdvisoryRecords(v1Dir).items.length === v1Items, `rehearsal: rollback restores ${v1Items} v1 items`);
// --- 11. pipeline units: retry, checkpoint, quarantine, stubbed retrieval ----------------
const noWait = { sleep: async () => {}, random: () => 0 };
assert(JSON.stringify(RETRY_DELAYS_MS) === JSON.stringify([2000, 4000, 8000, 16000, 32000]) && MAX_ATTEMPTS === 5,
  'pipeline: retry schedule is 2s/4s/8s/16s/32s over 5 attempts');
assert(backoffDelayMs(1) === 2000 && backoffDelayMs(5) === 32000 && backoffDelayMs(9) === 32000,
  'pipeline: backoffDelayMs clamps past the table');
assert(isTransientError(new HttpError(429, 'x', 'u')) && isTransientError(new HttpError(503, 'x', 'u')) && isTransientError(Object.assign(new Error('t'), { status: 500 })),
  'pipeline: 429/5xx are transient');
assert(!isTransientError(new HttpError(400, 'x', 'u')) && !isTransientError(new HttpError(404, 'x', 'u')) && !isTransientError(new Error('nope')) && !isTransientError(null),
  'pipeline: 4xx/plain/unknown errors are not transient');
assert(isTransientError(Object.assign(new Error('x'), { code: 'ECONNRESET' })) && isTransientError(new TypeError('fetch failed')),
  'pipeline: reset/fetch-failed are transient');
let flakyCalls = 0;
const flakyDelays = [];
const flakyResult = await withRetries(async () => {
  flakyCalls += 1;
  if (flakyCalls < 3) throw new HttpError(503, 'x', 'u');
  return 'recovered';
}, { sleep: async (ms) => { flakyDelays.push(ms); }, random: () => 0 });
assert(flakyResult === 'recovered' && flakyCalls === 3 && JSON.stringify(flakyDelays) === JSON.stringify([2000, 4000]),
  'pipeline: withRetries recovers after transient failures with scheduled delays');
let exhaustedCalls = 0;
let exhaustedErr = null;
try {
  await withRetries(async () => { exhaustedCalls += 1; throw new HttpError(500, 'x', 'u'); }, noWait);
} catch (err) {
  exhaustedErr = err;
}
assert(exhaustedCalls === 5 && exhaustedErr instanceof HttpError, 'pipeline: withRetries gives up after 5 attempts');
let immediateCalls = 0;
try {
  await withRetries(async () => { immediateCalls += 1; throw new HttpError(404, 'x', 'u'); }, noWait);
} catch {
  // expected: non-transient, no retry
}
assert(immediateCalls === 1, 'pipeline: non-transient errors throw immediately without retry');
const checkpointFile = join(scratch, 'checkpoint', 'probe.json');
assert(loadCheckpoint(checkpointFile).cursors.length === 0, 'pipeline: missing checkpoint loads empty');
appendCursor(checkpointFile, { source: 'ghsa', kind: 'advisories:npm', value: '1', at: '2026-10-14T00:00:00.000Z' });
appendCursor(checkpointFile, { source: 'ghsa', kind: 'advisories:npm', value: '2', at: '2026-10-14T00:00:01.000Z' });
const reloadedCheckpoint = loadCheckpoint(checkpointFile);
assert(reloadedCheckpoint.cursors.length === 2 && lastCursorFor(reloadedCheckpoint, 'ghsa', 'advisories:npm').value === '2',
  'pipeline: checkpoint append/load round-trips with latest-wins');
assert(lastCursorFor(reloadedCheckpoint, 'osv', 'nope') === null, 'pipeline: lastCursorFor returns null for unknown pairs');
const badCheckpoint = join(scratch, 'checkpoint', 'bad.json');
writeFileSync(badCheckpoint, '{not json');
let badCheckpointThrew = false;
try { loadCheckpoint(badCheckpoint); } catch { badCheckpointThrew = true; }
assert(badCheckpointThrew, 'pipeline: malformed checkpoint JSON throws fail-closed');
let badCursorThrew = false;
try { appendCursor(join(scratch, 'checkpoint', 'bad2.json'), { source: 'ghsa' }); } catch { badCursorThrew = true; }
assert(badCursorThrew, 'pipeline: malformed cursor shape throws fail-closed');
const quarantineRoot = join(scratch, 'quarantine-probe');
const quarantined = quarantineRecord(quarantineRoot, 'probe-batch', 'GHSA', 'GHSA-xxxx-yyyy-zzzz', { id: 'x' }, 'synthetic conflict probe', '2026-10-14T00:00:00.000Z');
assert(existsSync(quarantined.file) && readFileSync(quarantined.reasonsFile, 'utf8').includes('GHSA-xxxx-yyyy-zzzz'),
  'pipeline: quarantine writes the candidate + a REASONS.md row');
quarantineRecord(quarantineRoot, 'probe-batch', 'OSV', 'PYSEC-1', { id: 'y' }, 'second probe', '2026-10-14T00:00:01.000Z');
const listedBatch = listQuarantined(quarantineRoot, 'probe-batch');
assert(listedBatch.files.length === 2 && listedBatch.reasons === true, 'pipeline: second quarantine appends without clobbering');
const listedMissing = listQuarantined(quarantineRoot, 'no-such-batch');
assert(listedMissing.files.length === 0 && listedMissing.reasons === false, 'pipeline: missing quarantine batch lists empty');
quarantineRecord(quarantineRoot, 'probe-batch', 'GHSA', 'GHSA/a b:c', { id: 'z' }, 'weird id probe', '2026-10-14T00:00:02.000Z');
assert(listQuarantined(quarantineRoot, 'probe-batch').files.every((name) => !name.includes('/') && !name.includes(' ')),
  'pipeline: quarantine filenames are sanitized');
let emptyReasonThrew = false;
try { quarantineRecord(quarantineRoot, 'probe-batch', 'GHSA', 'GHSA-q', {}, '', '2026-10-14T00:00:03.000Z'); } catch { emptyReasonThrew = true; }
assert(emptyReasonThrew, 'pipeline: unexplained quarantine throws fail-closed');
const ghsaFirstLink = '<https://api.github.com/advisories?page=2>; rel="next", <https://api.github.com/advisories?page=9>; rel="last"';
assert(parseLinkNext(ghsaFirstLink) === 'https://api.github.com/advisories?page=2', 'pipeline: parseLinkNext extracts the next URL');
assert(parseLinkNext(null) === null && parseLinkNext('<https://x>; rel="last"') === null, 'pipeline: parseLinkNext returns null without a next relation');
const ghsaStub = async (url) => {
  const text = String(url);
  if (text.includes('page=2')) {
    return { ok: true, status: 200, statusText: 'OK', headers: { get: () => '<https://api.github.com/advisories?page=3>; rel="next"' }, json: async () => [{ ghsa_id: 'GHSA-2' }] };
  }
  if (text.includes('page=3')) {
    return { ok: true, status: 200, statusText: 'OK', headers: { get: () => null }, json: async () => [{ ghsa_id: 'GHSA-3' }] };
  }
  return { ok: true, status: 200, statusText: 'OK', headers: { get: () => ghsaFirstLink }, json: async () => [{ ghsa_id: 'GHSA-1' }] };
};
const ghsaAll = await fetchAdvisories('npm', '', { fetchImpl: ghsaStub, ...{ retry: noWait } });
assert(ghsaAll.length === 3, 'pipeline: GHSA stub follows Link pagination across 3 pages');
const ghsaCapped = await fetchAdvisories('npm', '', { fetchImpl: ghsaStub, maxPages: 2, retry: noWait });
assert(ghsaCapped.length === 2, 'pipeline: GHSA maxPages caps retrieval');
const ghsaResumeFile = join(scratch, 'checkpoint', 'ghsa-resume.json');
appendCursor(ghsaResumeFile, { source: 'ghsa', kind: 'advisories:npm', value: '2', at: '2026-10-14T00:00:00.000Z' });
const ghsaResumed = await fetchAdvisories('npm', '', { fetchImpl: ghsaStub, checkpointFile: ghsaResumeFile, retry: noWait });
assert(ghsaResumed.length === 1 && ghsaResumed[0].ghsa_id === 'GHSA-3', 'pipeline: GHSA resumes after checkpointed pages');
assert(lastCursorFor(loadCheckpoint(ghsaResumeFile), 'ghsa', 'advisories:npm').value === '3',
  'pipeline: GHSA run leaves a page-3 checkpoint');
let ghsaFlakyCalls = 0;
const ghsaFlaky = async () => {
  ghsaFlakyCalls += 1;
  if (ghsaFlakyCalls < 3) {
    return { ok: false, status: 503, statusText: 'x', headers: { get: () => null }, json: async () => ({}) };
  }
  return { ok: true, status: 200, statusText: 'OK', headers: { get: () => null }, json: async () => [{ ghsa_id: 'GHSA-r' }] };
};
const ghsaRecovered = await fetchAdvisories('npm', '', { fetchImpl: ghsaFlaky, retry: noWait });
assert(ghsaRecovered.length === 1 && ghsaFlakyCalls === 3, 'pipeline: GHSA page fetch retries transient 503s');
const osvStub = async (url, opts) => {
  const body = JSON.parse(opts.body);
  if (body.page_token === 't2') {
    return { ok: true, status: 200, statusText: 'OK', json: async () => ({ vulns: [{ id: 'PYSEC-2' }] }) };
  }
  return { ok: true, status: 200, statusText: 'OK', json: async () => ({ vulns: [{ id: 'PYSEC-1' }], next_page_token: 't2' }) };
};
const osvAll = await fetchOsvForPackage('pkg', 'PyPI', { fetchImpl: osvStub, retry: noWait });
assert(osvAll.length === 2, 'pipeline: OSV stub follows page_token across 2 pages');
const osvCapped = await fetchOsvForPackage('pkg', 'PyPI', { fetchImpl: osvStub, maxPages: 1, retry: noWait });
assert(osvCapped.length === 1, 'pipeline: OSV maxPages caps retrieval');
assert(parseGhsaArgs(['--max-pages', '7']).maxPages === 7, 'pipeline: ghsa --max-pages parses');
let badMaxThrew = false;
try { parseOsvArgs(['--max-pages', '99']); } catch { badMaxThrew = true; }
assert(badMaxThrew, 'pipeline: osv --max-pages rejects out-of-range values');
rmSync(scratch, { recursive: true, force: true });

// --- summary --------------------------------------------------------------------
const total = passed + failed;
process.stdout.write(failed === 0 ? `rehearsal-tests: PASS (${passed}/${total} passed)\n` : `rehearsal-tests: FAIL (${passed}/${total} passed)\n`);
if (failed > 0) {
  process.exitCode = 1;
}
