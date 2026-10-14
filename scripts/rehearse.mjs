/**
 * Deterministic synthetic-corpus generator for ingestion rehearsals.
 *
 * Generates clearly-labeled synthetic advisory candidates into a directory
 * (callers use tmp dirs - rehearsal corpora are NEVER committed and NEVER
 * counted as production). Every byte is a pure function of (seed, index):
 * same inputs always produce identical trees. Provenance is unmistakable:
 * ids `SYNTH-*`, source `synthetic-rehearsal`, example.invalid URLs.
 *
 * Scenario injection (deterministic by index):
 * - i % 100 === 99: exact-duplicate extra file (same tuple + content)
 * - i % 137 === 136: shard extra file `<id>--2.json` (same tuple, new range)
 * - i % 211 === 210: cross-package primary (same id as primary i-7, new package)
 * - i % 251 === 250: alias-like primary (new id, same package+range as i-10)
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const REHEARSAL_SOURCE = 'synthetic-rehearsal';
export const REHEARSAL_RETRIEVED_AT = '2026-10-14T00:00:00.000Z';
export const REHEARSAL_LICENSE = 'SYNTHETIC - excluded from production counts';

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const NPM_RANGES = ['<1.0.0', '>=2.0.0 <2.1.0', '=3.4.0', '>=4.0.1 <4.1.0', '>=5.0.0 <6.0.0'];
const PYPI_RANGES = ['<1.0.0', '>=2.0.0,<2.1.0', '==3.4.*', '~=4.0.1', '>=5.0.0,<6.0.0'];

/** Deterministic PRNG (mulberry32). */
export function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let word = state;
    word = Math.imul(word ^ (word >>> 15), word | 1);
    word ^= word + Math.imul(word ^ (word >>> 7), word | 61);
    return ((word ^ (word >>> 14)) >>> 0) / 4294967296;
  };
}

function primaryId(prefix, index) {
  return `${prefix}-${String(index + 1).padStart(6, '0')}`;
}

function buildRecord({ id, ecosystem, packageName, range, summaryNote }) {
  return {
    schemaVersion: 'drobon.vuln-intel/v1',
    fixture: false,
    id,
    ecosystem,
    package: packageName,
    severity: SEVERITIES[id.length % SEVERITIES.length],
    summary: `SYNTHETIC REHEARSAL RECORD ${id} - not real intelligence. ${summaryNote}`,
    url: `https://example.invalid/synth/${id}`,
    affected: [{ range, fixed: '9.9.9' }],
    provenance: {
      source: REHEARSAL_SOURCE,
      sourceUrl: `https://example.invalid/synth/${id}`,
      retrievedAt: REHEARSAL_RETRIEVED_AT,
      license: REHEARSAL_LICENSE,
    },
  };
}

/**
 * Generate a deterministic synthetic corpus. Returns { files, primary, extra }.
 * Layout: <outDir>/vuln-intel/<npm|pypi>/SYNTH-*.json (mirrors the real tree
 * so existing walkers work unchanged on a tmp root).
 */
export function generateCorpus({ seed = 42, count = 1000, outDir, idPrefix = 'SYNTH' }) {
  if (!Number.isInteger(seed) || !Number.isInteger(count) || count < 1 || typeof outDir !== 'string') {
    throw new Error('generateCorpus: need { seed: int, count: int >= 1, outDir: string }');
  }
  const random = mulberry32(seed);
  const npmDir = join(outDir, 'vuln-intel', 'npm');
  const pypiDir = join(outDir, 'vuln-intel', 'pypi');
  mkdirSync(npmDir, { recursive: true });
  mkdirSync(pypiDir, { recursive: true });
  const planned = [];
  for (let i = 0; i < count; i += 1) {
    const ecosystem = i % 2 === 0 ? 'npm' : 'pypi';
    const ranges = ecosystem === 'npm' ? NPM_RANGES : PYPI_RANGES;
    let id = primaryId(idPrefix, i);
    let packageName = `synth-pkg-${String(i % 40).padStart(2, '0')}`;
    let range = ranges[Math.floor(random() * ranges.length)];
    let note = `candidate ${i + 1}/${count}, seed ${seed}.`;
    if (i % 211 === 210 && i >= 7) {
      id = primaryId(idPrefix, i - 7);
      packageName = `synth-split-${String(i % 13).padStart(2, '0')}`;
      note = `cross-package split twin of ${id}.`;
    } else if (i % 251 === 250 && i >= 10) {
      packageName = planned[i - 10].packageName;
      range = planned[i - 10].range;
      note = `alias-like twin of ${planned[i - 10].id} (same package+range, distinct id; manual-review boundary).`;
    }
    planned.push({ id, ecosystem, packageName, range, note });
  }
  let extra = 0;
  const writeRecord = (dir, fileName, record) => {
    writeFileSync(join(dir, fileName), `${JSON.stringify(record, null, 2)}\n`);
  };
  planned.forEach((plan, i) => {
    const dir = plan.ecosystem === 'npm' ? npmDir : pypiDir;
    const record = buildRecord(plan);
    writeRecord(dir, `${plan.id}.json`, record);
    if (i % 100 === 99) {
      const twin = planned[i - 50];
      const twinRecord = buildRecord(twin);
      writeRecord(twin.ecosystem === 'npm' ? npmDir : pypiDir, `${twin.id}--dup.json`, twinRecord);
      extra += 1;
    }
    if (i % 137 === 136) {
      const shardRanges = plan.ecosystem === 'npm' ? NPM_RANGES : PYPI_RANGES;
      const shard = buildRecord({ ...plan, range: shardRanges[(i + 2) % shardRanges.length] });
      writeRecord(dir, `${plan.id}--2.json`, shard);
      extra += 1;
    }
  });
  return { files: count + extra, primary: count, extra };
}
