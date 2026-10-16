/**
 * test-determinism.mjs — Batch H (release-gate G12).
 *
 * Contract: two fresh copies of the repository, each run through the same
 * generation + validation sequence, must produce byte-identical trees and
 * byte-identical validation output. The regenerated tree must also match the
 * checked-in working tree (generation is idempotent, never a drift source).
 *
 * Everything happens in os.tmpdir() sandboxes. The real repository is never
 * written to. No network.
 *
 * Usage: node scripts/test-determinism.mjs
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

const ROOT = join(resolve(import.meta.dirname, '..'));
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

const SKIP = new Set(['.git', 'node_modules', '.arena']);
function listFiles(root) {
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (SKIP.has(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) out.push(relative(root, full));
    }
  };
  walk(root);
  return out.sort();
}
function sha256(root, rel) {
  return createHash('sha256').update(readFileSync(join(root, rel))).digest('hex');
}
function treeDigest(root) {
  const hash = createHash('sha256');
  for (const rel of listFiles(root)) {
    hash.update(rel);
    hash.update('\0');
    hash.update(sha256(root, rel));
    hash.update('\0');
  }
  return hash.digest('hex');
}
function freshCopy(sink, name) {
  const dir = join(mkdtempSync(join(tmpdir(), `drobon-det-${name}-`)));
  sink.push(dir);
  const work = join(dir, 'work');
  cpSync(ROOT, work, {
    recursive: true,
    filter: (src) => !SKIP.has(src.split(sep).pop() ?? ''),
  });
  return work;
}

const GENERATION = [
  ['node', ['scripts/generate-assets.mjs']],
  ['node', ['scripts/validate-packs.mjs', 'packs']],
  ['node', ['scripts/validate.mjs', 'vuln-intel']],
  ['node', ['scripts/validate-sources.mjs']],
  ['node', ['scripts/validate-corpus.mjs']],
  ['node', ['scripts/validate-cwe.mjs']],
  ['node', ['scripts/validate-audiences.mjs']],
  ['node', ['scripts/check-vectors.mjs']],
];
function runSequence(work) {
  const logs = [];
  for (const [cmd, args] of GENERATION) {
    const stdout = execFileSync(cmd, args, { cwd: work, encoding: 'utf8' });
    logs.push(`${cmd} ${args.join(' ')}\n${stdout}`);
  }
  return logs;
}

const SINK = [];
try {
  const workA = freshCopy(SINK, 'a');
  const workB = freshCopy(SINK, 'b');

  const logsA = runSequence(workA);
  const logsB = runSequence(workB);

  // 1. validation + generation logs identical (same wording, same counts)
  assert(JSON.stringify(logsA) === JSON.stringify(logsB),
    'determinism: generation+validation logs byte-identical across fresh copies', '');
  // 2. entire regenerated trees byte-identical
  const filesA = listFiles(workA);
  const filesB = listFiles(workB);
  assert(JSON.stringify(filesA) === JSON.stringify(filesB),
    'determinism: regenerated file sets identical', `${filesA.length} vs ${filesB.length}`);
  let firstDiff = '';
  for (const rel of filesA) {
    if (!firstDiff && sha256(workA, rel) !== sha256(workB, rel)) firstDiff = rel;
  }
  assert(firstDiff === '', 'determinism: every regenerated file byte-identical', firstDiff);
  // 3. regeneration is idempotent against the checked-in tree (no drift source)
  let driftDiff = '';
  for (const rel of filesA) {
    const inRepo = join(ROOT, rel);
    if (!existsSync(inRepo)) {
      if (!driftDiff) driftDiff = `missing in repo: ${rel}`;
      continue;
    }
    if (!driftDiff && sha256(workA, rel) !== sha256(ROOT, rel)) driftDiff = rel;
  }
  assert(driftDiff === '', 'determinism: regenerated tree matches the checked-in tree', driftDiff);
  // 4. single reproducibility digest (evidence artifact for the report)
  const digest = treeDigest(workA);
  assert(/^[0-9a-f]{64}$/.test(digest) && digest === treeDigest(workB),
    `determinism: whole-tree sha256 digest reproducible (${digest.slice(0, 16)}…)`, '');
  process.stdout.write(`tree-digest: ${digest}\n`);
} finally {
  for (const dir of SINK) rmSync(dir, { recursive: true, force: true });
}

process.stdout.write(`\ndeterminism: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exitCode = 1;

const invokedAsScript =
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (invokedAsScript && failed > 0) {
  process.stderr.write('determinism: FAIL — two fresh-copy runs diverged\n');
}
