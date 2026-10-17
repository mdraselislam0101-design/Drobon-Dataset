#!/usr/bin/env node
/**
 * run-eval.mjs — deterministic evaluation runner (Phase 6, W3 workflow).
 *
 * Usage:
 *   node scripts/run-eval.mjs              # all cases
 *   node scripts/run-eval.mjs --case EVAL-SAST-001
 *
 * Reads case manifests from data/eval-cases (read-only), executes the
 * Dataset's own detectors against the declared synthetic fixtures, and prints
 * a drobon.eval.report/v1 JSON document to stdout. Exit codes: 0 = report
 * produced (regardless of detector scores — scores are data, not gatekeeping);
 * 2 = case manifest errors (fail-closed: no report for invalid manifests).
 *
 * The runner never rewrites expected outcomes. Deterministic output: stable
 * sort order, fixed field order.
 */
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildReport, loadCases } from './eval-foundation.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const args = process.argv.slice(2);
const caseIndex = args.indexOf('--case');
const only = caseIndex >= 0 ? args[caseIndex + 1] : null;

const { cases, errors } = loadCases(ROOT);
if (errors.length > 0) {
  process.stderr.write(`run-eval: case manifest errors (fail-closed, no report):\n${errors.map((e) => `  - ${e}`).join('\n')}\n`);
  process.exit(2);
}
const selected = only === null ? cases : cases.filter((c) => c.id === only);
if (only !== null && selected.length === 0) {
  process.stderr.write(`run-eval: no case with id ${only}\n`);
  process.exit(2);
}
const report = buildReport(ROOT, selected);
process.stdout.write(`${JSON.stringify(report, null, 1)}\n`);
process.exit(0);
