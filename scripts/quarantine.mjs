/**
 * Quarantine buckets for rejected-but-unresolved ingestion candidates.
 *
 * Per INGESTION_PROTOCOL.md section 9, every candidate lands in exactly one
 * bucket; quarantined items (conflicts, ambiguous aliases, license doubt,
 * validation failures) are stored under quarantine/<batch>/ with a REASONS.md
 * row each. Quarantine is never counted and never shipped: items wait for
 * human review, then are accepted or deleted with a note. `at` is injectable
 * so tests stay deterministic.
 */
import { join } from 'node:path';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';

const REASONS_HEADER = '| id | source | reason | quarantinedAt |\n|---|---|---|---|\n';

function safeFileStem(text) {
  const stem = String(text).replace(/[^A-Za-z0-9_.-]+/g, '_').slice(0, 120) || 'item';
  // '.' and '..' survive the charset allowlist and would escape the quarantine
  // directory when joined — never emit them as a path component.
  return stem === '.' || stem === '..' ? 'item' : stem;
}

function escapeReason(reason) {
  return String(reason).replace(/\|/g, '/').replace(/\r?\n/g, ' ').slice(0, 300);
}

/**
 * Quarantine one candidate. Returns { file, reasonsFile }. Throws on empty
 * batch/source/id/reason (fail-closed: an unexplained quarantine is a bug).
 */
export function quarantineRecord(root, batch, source, id, record, reason, at = new Date().toISOString()) {
  for (const [name, value] of [['batch', batch], ['source', source], ['id', id], ['reason', reason]]) {
    if (typeof value !== 'string' || value.length < 1) {
      throw new Error(`quarantineRecord: ${name} must be a non-empty string`);
    }
  }
  const dir = join(root, 'quarantine', safeFileStem(batch));
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${safeFileStem(source)}-${safeFileStem(id)}.json`);
  writeFileSync(file, `${JSON.stringify({ record, reason, quarantinedAt: at }, null, 2)}\n`);
  const reasonsFile = join(dir, 'REASONS.md');
  if (!existsSync(reasonsFile)) {
    writeFileSync(reasonsFile, REASONS_HEADER);
  }
  const row = `| ${id} | ${source} | ${escapeReason(reason)} | ${at} |\n`;
  writeFileSync(reasonsFile, readFileSync(reasonsFile, 'utf8') + row);
  return { file, reasonsFile };
}

/** List a batch: { files: [json names], reasons: bool }. Missing batch = empty. */
export function listQuarantined(root, batch) {
  const dir = join(root, 'quarantine', safeFileStem(batch));
  if (!existsSync(dir)) {
    return { files: [], reasons: false };
  }
  const files = readdirSync(dir).filter((name) => name.endsWith('.json')).sort();
  return { files, reasons: existsSync(join(dir, 'REASONS.md')) };
}
