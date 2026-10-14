/**
 * Crash-recovery checkpoints for importer retrieval.
 *
 * A checkpoint file holds { version: 1, cursors: [...] } where each cursor
 * is a closed { source, kind, value, at } object. Files live in tmp (never
 * committed) per INGESTION_PROTOCOL.md section 8. A missing file means "no
 * progress yet" (empty checkpoint); a malformed file throws fail-closed so
 * a corrupt checkpoint can never silently skip pages.
 */
import { dirname } from 'node:path';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';

export const CHECKPOINT_VERSION = 1;
const CURSOR_KEYS = ['source', 'kind', 'value', 'at'];
const ISO_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$/;

function assertCursor(cursor) {
  if (typeof cursor !== 'object' || cursor === null || Array.isArray(cursor)) {
    throw new Error('checkpoint: cursor must be an object');
  }
  const keys = Object.keys(cursor);
  if (keys.length !== CURSOR_KEYS.length || !CURSOR_KEYS.every((key) => keys.includes(key))) {
    throw new Error('checkpoint: cursor must be exactly { source, kind, value, at }');
  }
  for (const key of ['source', 'kind', 'value']) {
    if (typeof cursor[key] !== 'string' || cursor[key].length < 1 || cursor[key].length > 300) {
      throw new Error(`checkpoint: cursor.${key} must be 1..300 characters`);
    }
  }
  if (typeof cursor.at !== 'string' || !ISO_PATTERN.test(cursor.at)) {
    throw new Error('checkpoint: cursor.at must be an ISO UTC timestamp');
  }
}

/** Load a checkpoint; missing file yields an empty one, malformed throws. */
export function loadCheckpoint(file) {
  if (!existsSync(file)) {
    return { version: CHECKPOINT_VERSION, cursors: [] };
  }
  let parsed = null;
  try {
    parsed = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    throw new Error(`${file}: checkpoint is not valid JSON (${err.message})`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${file}: checkpoint must be an object`);
  }
  if (parsed.version !== CHECKPOINT_VERSION || !Array.isArray(parsed.cursors)) {
    throw new Error(`${file}: checkpoint must be { version: 1, cursors: [...] }`);
  }
  for (const cursor of parsed.cursors) {
    try {
      assertCursor(cursor);
    } catch (err) {
      throw new Error(`${file}: ${err.message}`);
    }
  }
  return parsed;
}

/** Append a cursor (validated) and persist. Returns the updated checkpoint. */
export function appendCursor(file, cursor) {
  assertCursor(cursor);
  const checkpoint = loadCheckpoint(file);
  checkpoint.cursors.push({ ...cursor });
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(checkpoint, null, 2)}\n`);
  return checkpoint;
}

/** Latest cursor for a (source, kind) pair, or null when none exists. */
export function lastCursorFor(checkpoint, source, kind) {
  if (typeof checkpoint !== 'object' || checkpoint === null || !Array.isArray(checkpoint.cursors)) {
    throw new Error('lastCursorFor: checkpoint must be { version: 1, cursors: [...] }');
  }
  const matches = checkpoint.cursors.filter((cursor) => cursor.source === source && cursor.kind === kind);
  return matches.length === 0 ? null : matches[matches.length - 1];
}
