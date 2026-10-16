/**
 * Importer engineering tests (Batch C) — ALL network is mocked, ALL writes
 * stay in os.tmpdir() sandboxes. Nothing here can import real advisories or
 * write into the repository.
 *
 * Covers the required pipeline contract:
 *   pagination (Link + page_token) · cursor traversal · termination ·
 *   repeated-cursor protection · unsafe-URL protection · HTTP error/timeout/
 *   retry/rate-limit handling · bounded retries · fail-closed batching (a
 *   failed run writes nothing) · dry-run (zero writes) · schema validation
 *   before acceptance · provenance capture · conflict quarantine (never
 *   overwrite) · summary metrics separating discovered vs production-approved.
 *
 * Runs in `npm test`.
 */
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  fetchAdvisories,
  isSafeNextUrl,
  parseArgs as parseGhsaArgs,
  parseLinkNext,
  runImport,
  SAFE_NEXT_PREFIX,
} from './import-ghsa.mjs';
import { fetchOsvForPackage, parseArgs as parseOsvArgs } from './import-osv.mjs';
import { HttpError } from './retry.mjs';

const ROOT = resolve(new URL('.', import.meta.url).pathname, '..');
let passed = 0;
let failed = 0;
function assert(condition, name, detail = '') {
  if (condition) {
    passed += 1;
    process.stdout.write(`ok - ${name}\n`);
  } else {
    failed += 1;
    process.stdout.write(`NOT OK - ${name}${detail ? ` (${detail})` : ''}\n`);
  }
}

const noWait = { sleep: async () => {}, random: () => 0, attempts: 5 };

function response(status, body, link = null) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: `HTTP ${status}`,
    json: async () => {
      if (typeof body === 'function') return body();
      return body;
    },
    headers: { get: (h) => (h.toLowerCase() === 'link' ? link : null) },
  };
}

function advisory(id, overrides = {}) {
  return {
    ghsa_id: id,
    severity: 'high',
    summary: `Synthetic test advisory ${id} — not a real vulnerability.`,
    html_url: `https://github.com/advisories/${id}`,
    withdrawn_at: null,
    vulnerabilities: [
      {
        package: { ecosystem: 'npm', name: `synthetic-pkg-${id.toLowerCase()}` },
        vulnerable_version_range: '< 1.0.0',
        first_patched_version: '1.0.0',
      },
    ],
    ...overrides,
  };
}

const ROOT_SINK = []; // all sandboxes, cleaned at the end
function sandbox() {
  const dir = mkdtempSync(join(tmpdir(), 'drobon-importers-'));
  ROOT_SINK.push(dir);
  return dir;
}

// --- unit: Link parsing + URL safety ----------------------------------------
assert(parseLinkNext('<https://api.github.com/advisories?page=2>; rel="next", <x>; rel="last"') === 'https://api.github.com/advisories?page=2',
  'unit: parseLinkNext extracts rel="next"');
assert(parseLinkNext(null) === null && parseLinkNext('') === null && parseLinkNext('<x>; rel="last"') === null,
  'unit: parseLinkNext null-safe');
assert(isSafeNextUrl('https://api.github.com/advisories?page=2') && !isSafeNextUrl('https://evil.example/advisories')
  && !isSafeNextUrl('http://api.github.com/advisories') && !isSafeNextUrl('https://api.github.com.evil.example/x'),
  'unit: isSafeNextUrl pins the advisory API host');

// --- args: dry-run accepted, junk rejected ---------------------------------
{
  const a = parseGhsaArgs(['--dry-run', '--limit', '5']);
  assert(a.dryRun === true && a.limit === 5, 'args: --dry-run parsed');
  let threw = false;
  try { parseGhsaArgs(['--nope']); } catch { threw = true; }
  assert(threw, 'args: unknown argument rejected');
  const o = parseOsvArgs(['--max-pages', '20']);
  assert(o.maxPages === 20, 'args: osv --max-pages parsed');
}

// --- pagination happy path + summary metrics + dry-run zero writes ----------
{
  const sb = sandbox();
  const pages = {
    'https://api.github.com/advisories?ecosystem=npm&type=reviewed&sort=updated&direction=desc&per_page=100':
      response(200, [advisory('GHSA-aaaa-aaaa-aaaa')], '<https://api.github.com/advisories?page=2>; rel="next"'),
    'https://api.github.com/advisories?page=2':
      response(200, [advisory('GHSA-bbbb-bbbb-bbbb')], '<https://api.github.com/advisories?page=3>; rel="next"'),
    'https://api.github.com/advisories?page=3': response(200, [advisory('GHSA-cccc-cccc-cccc')]),
  };
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    return pages[url] ?? response(404, {});
  };
  const summary = await runImport({
    fetchImpl, ecosystems: ['npm'], outRoot: join(sb, 'out'), quarantineRoot: sb,
    retry: noWait, dryRun: true, retrievedAt: '2026-10-16T00:00:00.000Z',
  });
  assert(summary.fetched === 3 && calls.length === 3, 'pagination: 3 pages fetched in order', JSON.stringify(summary));
  assert(summary.discovered === 3 && summary.accepted === 0, 'dry-run: discovered 3, accepted 0');
  assert(!existsSync(join(sb, 'out')) && readdirSync(sb).length === 0, 'dry-run: zero writes');
  assert(summary.productionApproved === 0, 'summary: productionApproved is always 0');
  assert(summary.notes.some((n) => n.includes('NOT written')), 'dry-run: note records non-write');
}

// --- real run writes files; shard naming; provenance present ----------------
{
  const sb = sandbox();
  const twoRanges = advisory('GHSA-dddd-dddd-dddd', {
    vulnerabilities: [
      { package: { ecosystem: 'npm', name: 'synth-multi' }, vulnerable_version_range: '< 1.2.0' },
      { package: { ecosystem: 'npm', name: 'synth-multi' }, vulnerable_version_range: '>= 2.0.0, < 2.1.0' },
    ],
  });
  const fetchImpl = async () => response(200, [twoRanges, advisory('GHSA-eeee-eeee-eeee')]);
  const summary = await runImport({
    fetchImpl, ecosystems: ['npm'], outRoot: join(sb, 'out'), quarantineRoot: sb,
    retry: noWait, retrievedAt: '2026-10-16T00:00:00.000Z',
  });
  const files = readdirSync(join(sb, 'out', 'npm')).sort();
  assert(summary.accepted === 3 && files.join(',') === 'GHSA-dddd-dddd-dddd--2.json,GHSA-dddd-dddd-dddd.json,GHSA-eeee-eeee-eeee.json',
    'commit: files written with --N shard naming', files.join(','));
  const rec = JSON.parse(readFileSync(join(sb, 'out', 'npm', 'GHSA-eeee-eeee-eeee.json'), 'utf8'));
  assert(rec.provenance.source === 'GHSA' && rec.provenance.sourceUrl === 'https://github.com/advisories/GHSA-eeee-eeee-eeee'
    && rec.provenance.retrievedAt === '2026-10-16T00:00:00.000Z' && rec.fixture === false,
    'commit: provenance captured on every record');
}

// --- empty page terminates cleanly -----------------------------------------
{
  const summary = await runImport({
    fetchImpl: async () => response(200, []), ecosystems: ['npm'],
    outRoot: join(sandbox(), 'out'), quarantineRoot: sandbox(), retry: noWait,
    dryRun: true,
  });
  assert(summary.fetched === 0 && summary.failed === 0 && summary.error === null, 'termination: empty page is a clean empty batch');
}

// --- repeated-cursor guard --------------------------------------------------
{
  const notes = [];
  let calls = 0;
  const start = 'https://api.github.com/advisories?ecosystem=npm&type=reviewed&sort=updated&direction=desc&per_page=100';
  // page=2 always links back to page=2 itself (after first hop) — simulates a cursor loop
  const looping = async (url) => {
    calls += 1;
    if (url === start) return response(200, [advisory('GHSA-ffff-ffff-ffff')], '<https://api.github.com/advisories?page=2>; rel="next"');
    return response(200, [advisory('GHSA-gggg-gggg-gggg')], '<https://api.github.com/advisories?page=2>; rel="next"');
  };
  const items = await fetchAdvisories('npm', '', { fetchImpl: looping, retry: noWait, onNote: (t) => notes.push(t) });
  assert(calls <= 3 && items.length === 2, 'cursor guard: loop stops, no double count', `calls=${calls} items=${items.length}`);
  assert(notes.some((n) => n.includes('repeated cursor guard')), 'cursor guard: note recorded');
}

// --- unsafe next-URL protection --------------------------------------------
{
  const notes = [];
  const fetchImpl = async () => response(200, [advisory('GHSA-hhhh-hhhh-hhhh')], '<https://evil.example/steal>; rel="next"');
  const items = await fetchAdvisories('npm', '', { fetchImpl, retry: noWait, onNote: (t) => notes.push(t) });
  assert(items.length === 1 && notes.some((n) => n.includes('unsafe next-URL rejected')),
    'cursor guard: off-host Link next is refused fail-closed');
}

// --- transform-time skips and rejections ------------------------------------
{
  const sb = sandbox();
  const fetchImpl = async () => response(200, [
    { ...advisory('GHSA-1111-1111-1111'), ghsa_id: undefined },
    advisory('GHSA-2222-2222-2222', { withdrawn_at: '2026-01-01T00:00:00Z' }),
    advisory('GHSA-3333-3333-3333', { severity: 'apocalyptic' }),
    advisory('GHSA-4444-4444-4444', { summary: '   ' }),
    advisory('GHSA-5555-5555-5555', {
      vulnerabilities: [{ package: { ecosystem: 'npm', name: 'synth-norange' }, vulnerable_version_range: '  ' }],
    }),
    advisory('GHSA-6666-6666-6666', { summary: 'bad\u0001control' }),
  ]);
  const summary = await runImport({
    fetchImpl, ecosystems: ['npm'], outRoot: join(sb, 'out'), quarantineRoot: sb, retry: noWait, dryRun: true,
  });
  assert(summary.skips.some((s) => s.includes('missing ghsa_id')), 'skips: missing id recorded');
  assert(summary.skips.some((s) => s.includes('withdrawn')), 'skips: withdrawn advisory excluded');
  assert(summary.skips.some((s) => s.includes('unknown severity')), 'skips: unknown severity rejected');
  assert(summary.skips.some((s) => s.includes('empty summary')), 'skips: empty summary rejected');
  assert(summary.skips.some((s) => s.includes('no vulnerable version range')), 'skips: missing range rejected');
  assert(summary.rejected >= 1 && summary.discovered === 0, 'skips: control-char summary -> schema rejected', JSON.stringify(summary));
}

// --- filename injection cannot escape --------------------------------------
{
  const sb = sandbox();
  const fetchImpl = async () => response(200, [
    advisory('GHSA-7777-7777-7777', {
      vulnerabilities: [{ package: { ecosystem: 'npm', name: 'ok-pkg' }, vulnerable_version_range: '< 1.0.0' }],
    }),
    advisory('../../evil', {
      vulnerabilities: [{ package: { ecosystem: 'npm', name: 'ok-pkg2' }, vulnerable_version_range: '< 1.0.0' }],
    }),
  ]);
  const summary = await runImport({
    fetchImpl, ecosystems: ['npm'], outRoot: join(sb, 'out'), quarantineRoot: sb, retry: noWait, dryRun: true,
  });
  assert(summary.rejected >= 1 && summary.discovered === 1,
    'security: path-traversal advisory id rejected by schema before any write', JSON.stringify(summary.skips.slice(0, 4)));
  assert(!existsSync(resolve(sb, '..', 'evil.json')), 'security: no file escaped the sandbox');
}

// --- duplicates and conflicts ----------------------------------------------
{
  const sb = sandbox();
  const outRoot = join(sb, 'out');
  mkdirSync(join(outRoot, 'npm'), { recursive: true });
  const rec = advisory('GHSA-8888-8888-8888');
  const fetchImpl = async () => response(200, [rec]);
  // 0) fresh write
  const s0 = await runImport({
    fetchImpl, ecosystems: ['npm'], outRoot, quarantineRoot: sb, retry: noWait,
    retrievedAt: '2026-10-16T00:00:00.000Z',
  });
  assert(s0.accepted === 1 && existsSync(join(outRoot, 'npm', 'GHSA-8888-8888-8888.json')),
    'dup: fresh record written');
  // 1) file exists, no --force
  const s1 = await runImport({
    fetchImpl, ecosystems: ['npm'], outRoot, quarantineRoot: sb, retry: noWait,
    retrievedAt: '2026-10-16T00:00:00.000Z',
  });
  assert(s1.duplicate === 1 && s1.accepted === 0 && s1.skips.some((s) => s.includes('file exists')),
    'dup: existing file skipped without --force');
  // 2) --force with byte-identical content
  writeFileSync(join(outRoot, 'npm', 'GHSA-8888-8888-8888.json'),
    `${JSON.stringify(JSON.parse(readFileSync(join(outRoot, 'npm', 'GHSA-8888-8888-8888.json'), 'utf8')), null, 2)}\n`);
  const s2 = await runImport({
    fetchImpl, ecosystems: ['npm'], outRoot, quarantineRoot: sb, retry: noWait, force: true,
    retrievedAt: '2026-10-16T00:00:00.000Z',
  });
  assert(s2.duplicate === 1 && s2.skips.some((s) => s.includes('duplicate, unchanged')),
    'dup: --force on identical bytes counts duplicate, no rewrite churn');
  // 3) --force with differing content -> quarantine, never overwrite
  writeFileSync(join(outRoot, 'npm', 'GHSA-8888-8888-8888.json'), '{"tampered": true}\n');
  const s3 = await runImport({
    fetchImpl, ecosystems: ['npm'], outRoot, quarantineRoot: sb, retry: noWait, force: true,
    retrievedAt: '2026-10-16T00:00:00.000Z', batchId: 'ghsa-test',
  });
  assert(s3.skips.some((s) => s.includes('conflict quarantined')) && s3.accepted === 0,
    'conflict: differing file quarantined, never overwritten');
  assert(JSON.parse(readFileSync(join(outRoot, 'npm', 'GHSA-8888-8888-8888.json'), 'utf8')).tampered === true,
    'conflict: original bytes preserved');
  assert(existsSync(join(sb, 'quarantine', 'ghsa-test', 'GHSA-GHSA-8888-8888-8888.json'))
    || readdirSync(join(sb, 'quarantine', 'ghsa-test')).some((n) => n.endsWith('.json')),
    'conflict: quarantine bucket written with reasons');
}

// --- fail-closed: malformed JSON / retries / exhaustion / partial failure ---
{
  const sb = sandbox();
  const s1 = await runImport({
    fetchImpl: async () => response(200, () => { throw new SyntaxError('unexpected token'); }),
    ecosystems: ['npm'], outRoot: join(sb, 'out1'), quarantineRoot: sb, retry: noWait, dryRun: true,
  });
  assert(s1.failed === 1 && s1.error !== null, 'fail-closed: malformed response aborts');

  let attempt = 0;
  const flaky = async () => {
    attempt += 1;
    return attempt <= 2 ? response(429, {}) : response(200, [advisory('GHSA-9999-9999-9999')]);
  };
  attempt = 0;
  const s2 = await runImport({
    fetchImpl: flaky, ecosystems: ['npm'], outRoot: join(sb, 'out2'), quarantineRoot: sb,
    retry: noWait, dryRun: true,
  });
  assert(s2.failed === 0 && s2.fetched === 1, 'retry: 429 rate-limit retried then succeeds');

  attempt = 0;
  const timeouty = async () => {
    attempt += 1;
    if (attempt <= 2) {
      const err = new TypeError('fetch failed');
      err.code = 'ETIMEDOUT';
      throw err;
    }
    return response(200, [advisory('GHSA-aaaa-bbbb-cccc')]);
  };
  const s3 = await runImport({
    fetchImpl: timeouty, ecosystems: ['npm'], outRoot: join(sb, 'out3'), quarantineRoot: sb,
    retry: noWait, dryRun: true,
  });
  assert(s3.failed === 0 && s3.fetched === 1, 'retry: timeout retried then succeeds');

  attempt = 0;
  const dead = async () => { attempt += 1; return response(503, {}); };
  const s4 = await runImport({
    fetchImpl: dead, ecosystems: ['npm'], outRoot: join(sb, 'out4'), quarantineRoot: sb,
    retry: noWait, dryRun: true,
  });
  assert(s4.failed === 1 && attempt === 5, 'retry: bounded (5 attempts) then fail-closed', `attempts=${attempt}`);

  // partial failure across ecosystems: npm page1 OK, pip always 500 -> NOTHING written
  const out5 = join(sb, 'out5');
  const partial = async (url) => {
    if (url.includes('ecosystem=npm')) return response(200, [advisory('GHSA-dead-beef-0000')]);
    return response(500, {});
  };
  const s5 = await runImport({
    fetchImpl: partial, ecosystems: ['npm', 'pip'], outRoot: out5, quarantineRoot: sb, retry: noWait,
  });
  assert(s5.failed === 1 && s5.accepted === 0 && !existsSync(out5),
    'fail-closed batching: partial fetch failure writes NOTHING (staged commit)');
}

// --- limit cap --------------------------------------------------------------
{
  const sb = sandbox();
  const fetchImpl = async () => response(200, [advisory('GHSA-0000-0000-0001'), advisory('GHSA-0000-0000-0002')]);
  const s = await runImport({
    fetchImpl, ecosystems: ['npm'], outRoot: join(sb, 'out'), quarantineRoot: sb,
    retry: noWait, limit: 1, retrievedAt: '2026-10-16T00:00:00.000Z',
  });
  assert(s.accepted === 1 && s.skips.some((x) => x.includes('limit 1 reached')),
    'limit: --limit caps accepted records with explicit skip reason');
}

// --- OSV repeated page_token guard ------------------------------------------
{
  const notes = [];
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return response(200, { vulns: [{ id: 'OSV-TEST-1', summary: 'synthetic', affected: [] }], next_page_token: 'tok-same' });
  };
  const vulns = await fetchOsvForPackage('synth-pkg', 'npm', {
    fetchImpl, retry: noWait, maxPages: 10, onNote: (t) => notes.push(t),
  });
  assert(vulns.length === 2 && calls === 2, 'osv cursor guard: looping next_page_token stops after one pass (bounded)',
    `calls=${calls} vulns=${vulns.length}`);
  assert(notes.some((n) => n.includes('repeated page_token guard')), 'osv cursor guard: note recorded');
}

// --- identical repeated items collapse (no shard duplication) --------------
{
  const sb = sandbox();
  const twin = advisory('GHSA-abcd-abcd-abcd');
  const fetchImpl = async () => response(200, [twin, { ...twin }]);
  const s = await runImport({
    fetchImpl, ecosystems: ['npm'], outRoot: join(sb, 'out'), quarantineRoot: sb,
    retry: noWait, retrievedAt: '2026-10-16T00:00:00.000Z',
  });
  const files = existsSync(join(sb, 'out', 'npm')) ? readdirSync(join(sb, 'out', 'npm')) : [];
  assert(s.accepted === 1 && s.duplicate === 1 && files.join(',') === 'GHSA-abcd-abcd-abcd.json',
    'dup-page: identical repeated item collapses to one file (no --2 shard)', files.join(','));
}

// --- reordered input is deterministic: same accepted set, byte-identical output
// Dedup/merge path contract (pump Phase 6): reordering the incoming advisory
// sequence must never change which records are accepted or their bytes —
// only the processing order may differ.
{
  const items = ['GHSA-1111-1111-1111', 'GHSA-2222-2222-2222', 'GHSA-3333-3333-3333', 'GHSA-4444-4444-4444'];
  const runWith = async (order, outDir) => {
    const sb = sandbox();
    const fetchImpl = async () => response(200, order.map((id) => advisory(id)));
    const summary = await runImport({
      fetchImpl, ecosystems: ['npm'], outRoot: join(sb, outDir), quarantineRoot: sb, retry: noWait,
      retrievedAt: '2026-10-14T00:00:00.000Z', batchId: 'reorder-test', limit: 10,
    });
    const files = readdirSync(join(sb, outDir, 'npm')).sort();
    const contents = files.map((f) => [f, readFileSync(join(sb, outDir, 'npm', f), 'utf8')]);
    return { summary, files, contents };
  };
  const forward = await runWith(items, 'a');
  const shuffled = await runWith([items[2], items[0], items[3], items[1]], 'b');
  assert(forward.summary.accepted === 4 && shuffled.summary.accepted === 4,
    'reordered input: same accepted count (4)', `${forward.summary.accepted}/${shuffled.summary.accepted}`);
  assert(JSON.stringify(forward.files) === JSON.stringify(shuffled.files),
    'reordered input: identical staged file set', JSON.stringify([forward.files, shuffled.files]));
  assert(JSON.stringify(forward.contents) === JSON.stringify(shuffled.contents),
    'reordered input: staged files byte-identical across orderings', '');
  // Harness self-check: the comparison must be order-sensitive enough to catch
  // a real divergence (a missing file in one run fails the set comparison).
  assert(forward.files.length === 4 && forward.files[0] === 'GHSA-1111-1111-1111.json',
    'reordered input: harness observes the expected four files', forward.files.join(','));
}

for (const dir of ROOT_SINK) {
  rmSync(dir, { recursive: true, force: true });
}

process.stdout.write(`\nimporter-tests: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exitCode = 1;

const invokedAsScript =
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (invokedAsScript && failed > 0) {
  process.stderr.write('importer-tests: FAIL\n');
}
