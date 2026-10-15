/**
 * Provenance evidence reporter for original Dataset content (read-only).
 *
 * Independent-creation evidence comes from git history itself: for every
 * pack rule, remediation entry, lesson, template, engagement aid, and CWE
 * entry, this reports the file's creation commit, date, and author exactly
 * as recorded by git. Nothing is inferred or backfilled: untracked files
 * report status PENDING (evidence appears when they are committed), and
 * --check exits 1 while any PENDING file remains.
 *
 * Usage:
 *   node scripts/provenance-report.mjs            (human-readable report)
 *   node scripts/provenance-report.mjs --check     (exit 0 clean / 1 pending)
 *   node scripts/provenance-report.mjs --json      (machine-readable)
 */
import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const SCOPES = [
  'packs/sast/v1/rules',
  'packs/secrets/v1/rules',
  'packs/dast/v1/rules',
  'knowledge/remediation',
  'knowledge/cwe',
  'knowledge/lessons',
  'knowledge/templates',
  'knowledge/engagements',
];

function collectFiles(root) {
  const found = [];
  for (const scope of SCOPES) {
    let entries = [];
    try {
      entries = readdirSync(join(root, scope));
    } catch {
      continue;
    }
    for (const name of entries) {
      if (name.endsWith('.json')) found.push(`${scope}/${name}`);
    }
  }
  return found.sort();
}

function gitLines(root, args) {
  try {
    return execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim().split('\n').filter(Boolean);
  } catch {
    return null;
  }
}

/** Creation evidence per file: { file, status, commit, date, author }. */
export function provenanceEvidence(root = process.cwd()) {
  const files = collectFiles(root);
  const tracked = new Set(gitLines(root, ['ls-files', ...files]) ?? []);
  const rows = [];
  for (const file of files) {
    if (!tracked.has(file)) {
      rows.push({ file, status: 'PENDING', commit: null, date: null, author: null });
      continue;
    }
    const info = gitLines(root, ['log', '--diff-filter=A', '--format=%H %ad %an', '--date=short', '--', file]);
    if (info === null || info.length === 0) {
      rows.push({ file, status: 'UNKNOWN', commit: null, date: null, author: null });
      continue;
    }
    const [commit, date, ...authorParts] = info[info.length - 1].split(' ');
    rows.push({ file, status: 'RECORDED', commit, date, author: authorParts.join(' ') });
  }
  return rows;
}

const invokedAsScript = (() => {
  try {
    return pathToFileURL(resolve(process.argv[1] ?? '')).href === import.meta.url;
  } catch {
    return false;
  }
})();

if (invokedAsScript) {
  const root = process.cwd();
  const rows = provenanceEvidence(root);
  const pending = rows.filter((row) => row.status !== 'RECORDED');
  if (process.argv.includes('--json')) {
    process.stdout.write(`${JSON.stringify(rows, null, 2)}\n`);
  } else {
    for (const row of rows) {
      process.stdout.write(
        row.status === 'RECORDED'
          ? `RECORDED ${row.file} ${row.commit.slice(0, 7)} ${row.date} ${row.author}\n`
          : `${row.status} ${row.file}\n`,
      );
    }
    process.stdout.write(`provenance: ${rows.length - pending.length}/${rows.length} recorded\n`);
  }
  if (process.argv.includes('--check') && pending.length > 0) {
    process.exitCode = 1;
  }
}
