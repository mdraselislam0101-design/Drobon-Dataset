/**
 * Identity-key grouping for advisory records (COUNTING_POLICY.md §1).
 *
 * Groups real (fixture === false) records under a directory into corpus items
 * keyed by (source, sourceId, ecosystem, package). Same-tuple files (base +
 * `<ID>--N.json` shards) collapse to ONE item. Read-only: never writes.
 *
 * Usage:
 *   node scripts/dedup-report.mjs [dir]   (default: vuln-intel)
 * Prints a JSON summary to stdout.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

function collectJsonFilesRecursive(root) {
  const found = [];
  const walk = (dir) => {
    const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && entry.name.endsWith('.json') && entry.name !== 'sources.json') {
        // sources.json is registry metadata, not a record (validated by validate-sources.mjs).
        found.push(full);
      }
    }
  };
  walk(root);
  return found;
}

function identityOf(record) {
  return {
    source: record?.provenance?.source ?? null,
    sourceId: record?.id ?? null,
    ecosystem: record?.ecosystem ?? null,
    package: record?.package ?? null,
  };
}

/**
 * Group explicit file paths into items. Pure over file bytes (read-only).
 * Returns { files, items: [{ key, files: [rel...] }], multiFile: [...] }.
 */
export function groupFiles(filePaths, root = process.cwd()) {
  const groups = new Map();
  let files = 0;
  for (const file of filePaths) {
    const record = JSON.parse(readFileSync(file, 'utf8'));
    if (record.fixture !== false) {
      continue;
    }
    files += 1;
    const key = identityOf(record);
    const flat = JSON.stringify([key.source, key.sourceId, key.ecosystem, key.package]);
    if (!groups.has(flat)) {
      groups.set(flat, { key, files: [] });
    }
    groups.get(flat).files.push(relative(root, file));
  }
  const items = [...groups.values()].sort((a, b) =>
    JSON.stringify(a.key) < JSON.stringify(b.key) ? -1 : 1,
  );
  for (const item of items) {
    item.files.sort();
  }
  return { files, items, multiFile: items.filter((item) => item.files.length > 1) };
}

/** Group every real record under <root>/vuln-intel. */
export function groupAdvisoryRecords(root = process.cwd()) {
  return groupFiles(collectJsonFilesRecursive(join(root, 'vuln-intel')), root);
}

/** Corpus item count for the advisory-record category. */
export function countAdvisoryItems(root = process.cwd()) {
  return groupAdvisoryRecords(root).items.length;
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
  const target = process.argv[2] !== undefined ? resolve(root, process.argv[2]) : join(root, 'vuln-intel');
  const stat = (await import('node:fs')).statSync(target);
  const report = stat.isDirectory() && target.endsWith('vuln-intel')
    ? groupAdvisoryRecords(root)
    : groupFiles(collectJsonFilesRecursive(target), root);
  process.stdout.write(
    `${JSON.stringify({ files: report.files, items: report.items.length, multiFileTuples: report.multiFile.length }, null, 2)}\n`,
  );
}
