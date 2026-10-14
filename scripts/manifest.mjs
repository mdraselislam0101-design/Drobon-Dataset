/**
 * SHA-256 integrity manifests for corpus scopes (GATE_PLAN G11).
 *
 * Generates deterministic (sorted) file manifests and verifies trees against
 * them: tampered, missing, and extra files all fail loudly. Read-only except
 * for `--write <file>`, which writes the manifest itself.
 *
 * Usage:
 *   node scripts/manifest.mjs [--scope records|packs|audiences|planning|all] [--write FILE] [--check FILE]
 *   (no --check: prints the manifest JSON to stdout; --check: verifies and exits 0/1)
 */
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const MANIFEST_SCOPES = ['records', 'packs', 'audiences', 'planning', 'all'];

function scopeDirs(scope) {
  switch (scope) {
    case 'records':
      return ['vuln-intel'];
    case 'packs':
      return ['packs'];
    case 'audiences':
      return ['knowledge', 'learning', 'assessments', 'engagements'];
    case 'planning':
      return ['docs'];
    case 'all':
      return ['vuln-intel', 'packs', 'knowledge', 'learning', 'assessments', 'engagements', 'interop', 'data', 'schema', 'docs'];
    default:
      throw new Error(`unknown scope "${scope}" (expected one of ${MANIFEST_SCOPES.join(', ')})`);
  }
}

function scopeAllows(scope, relPath) {
  if (scope === 'planning') {
    return relPath.startsWith('docs/') && relPath.endsWith('.json');
  }
  return relPath.endsWith('.json') || relPath.endsWith('.md');
}

function collectScopeFiles(root, scope) {
  const found = [];
  for (const dir of scopeDirs(scope)) {
    const abs = join(root, dir);
    if (!existsSync(abs)) {
      continue;
    }
    const walk = (current) => {
      const entries = readdirSync(current, { withFileTypes: true }).sort((a, b) =>
        a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
      );
      for (const entry of entries) {
        const full = join(current, entry.name);
        if (entry.isDirectory()) {
          walk(full);
        } else if (entry.isFile()) {
          const rel = relative(root, full);
          if (scopeAllows(scope, rel)) {
            found.push(rel);
          }
        }
      }
    };
    walk(abs);
  }
  return [...new Set(found)].sort();
}

function sha256File(absPath) {
  return createHash('sha256').update(readFileSync(absPath)).digest('hex');
}

/** Compute a deterministic manifest object for a scope. Pure (read-only). */
export function computeManifest(root, scope = 'all') {
  const files = collectScopeFiles(root, scope).map((rel) => ({
    path: rel,
    sha256: sha256File(join(root, rel)),
  }));
  return { scope, files };
}

/** Verify a tree against a manifest. Returns { ok, problems[] }. */
export function verifyManifest(root, manifest) {
  const problems = [];
  const expected = new Map((manifest.files ?? []).map((entry) => [entry.path, entry.sha256]));
  const actual = new Map();
  for (const rel of collectScopeFiles(root, manifest.scope ?? 'all')) {
    actual.set(rel, sha256File(join(root, rel)));
  }
  for (const [rel, hash] of expected) {
    if (!actual.has(rel)) {
      problems.push(`missing: ${rel}`);
    } else if (actual.get(rel) !== hash) {
      problems.push(`tampered: ${rel}`);
    }
  }
  for (const rel of actual.keys()) {
    if (!expected.has(rel)) {
      problems.push(`extra: ${rel}`);
    }
  }
  return { ok: problems.length === 0, problems: problems.sort() };
}

function parseArgs(argv) {
  const args = { scope: 'all', write: null, check: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--scope') {
      args.scope = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--write') {
      args.write = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--check') {
      args.check = argv[i + 1] ?? '';
      i += 1;
    } else {
      throw new Error(`unknown argument "${arg}" (expected --scope/--write/--check)`);
    }
  }
  if (!MANIFEST_SCOPES.includes(args.scope)) {
    throw new Error(`unknown scope "${args.scope}" (expected one of ${MANIFEST_SCOPES.join(', ')})`);
  }
  return args;
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
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stdout.write(`manifest: FAIL (${err.message})\n`);
    process.exitCode = 1;
  }
  if (args !== undefined) {
    if (args.check !== null) {
      const manifest = JSON.parse(readFileSync(resolve(root, args.check), 'utf8'));
      const result = verifyManifest(root, manifest);
      for (const problem of result.problems) process.stdout.write(`${problem}\n`);
      process.stdout.write(
        result.ok
          ? `manifest: PASS (${manifest.files.length} files verified)\n`
          : `manifest: FAIL (${result.problems.length} problems)\n`,
      );
      if (!result.ok) process.exitCode = 1;
    } else {
      const manifest = computeManifest(root, args.scope);
      const text = `${JSON.stringify(manifest, null, 2)}\n`;
      if (args.write !== null) {
        writeFileSync(resolve(root, args.write), text);
        process.stdout.write(`manifest: wrote ${manifest.files.length} files (${args.write})\n`);
      } else {
        process.stdout.write(text);
      }
    }
  }
}
