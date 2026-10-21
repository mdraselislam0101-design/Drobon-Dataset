#!/usr/bin/env node
/**
 * validate-app-dast-reachability.mjs — can each dataset DAST rule ever fire
 * inside the Main App?
 *
 *   node scripts/validate-app-dast-reachability.mjs --write   # regenerate interop/app-dast-reachability.json
 *   node scripts/validate-app-dast-reachability.mjs --check   # fail when the register drifts
 *
 * Why this exists: both App DAST engines filter the response down to 11 header
 * names before calling `evaluatePackDastCheck()` (scripts/lib/app-evaluator-profile.mjs
 * -> APP_DAST_SURFACE, transcribed from apps/api/src/scans/dast/engine.ts and
 * activeEngine.ts at commit 9360dd1). A rule that reads `Permissions-Policy` or
 * `Referrer-Policy` is a correct rule that can never fire in the product. That is
 * the DAST twin of the SAST language gate, and it stayed invisible until it was
 * measured here.
 *
 * The register is not a wish list: every unreachable rule is listed with its
 * header and a reason, and the check fails in both directions —
 *   - a rule that is unreachable but absent from the register (new silent gap), and
 *   - a rule listed as unreachable that is in fact reachable (stale entry).
 *
 * Reachability rule, derived from the observed surface only:
 *   response-body-matches        -> reachable (body is passed, clipped at 32 768 bytes)
 *   http-url                     -> reachable (the URL is passed)
 *   cookie-missing-flag          -> reachable (reads Set-Cookie)
 *   response-header-host-differs -> reachable (reads Location + URL)
 *   any other type               -> reachable only when `check.header` is one of the
 *                                   11 inspected names (case-insensitive)
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { APP_DAST_SURFACE, APP_PROFILE } from './lib/app-evaluator-profile.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = 'interop/app-dast-reachability.json';
const WRITE = process.argv.includes('--write');

const ALLOW = new Set(APP_DAST_SURFACE.inspectedResponseHeaders);
const URL_OR_BODY_TYPES = new Set(['response-body-matches', 'http-url', 'cookie-missing-flag', 'response-header-host-differs']);

const rules = readdirSync(join(ROOT, 'packs/dast/v1/rules'))
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => JSON.parse(readFileSync(join(ROOT, 'packs/dast/v1/rules', f), 'utf8')));

function classify(rule) {
  const type = rule.check?.type;
  if (URL_OR_BODY_TYPES.has(type)) return { reachable: true, reason: 'type-reads-only-url-body-or-allowed-header' };
  const header = typeof rule.check?.header === 'string' ? rule.check.header : undefined;
  if (header === undefined) return { reachable: false, reason: 'no-header-declared-and-type-needs-one' };
  if (ALLOW.has(header.toLowerCase())) return { reachable: true, reason: 'header-in-app-allowlist' };
  return { reachable: false, reason: 'header-not-forwarded-by-app', header };
}

const perRule = rules.map((rule) => {
  const verdict = classify(rule);
  return {
    id: rule.id,
    category: rule.category,
    checkType: rule.check?.type ?? 'missing',
    header: verdict.header ?? null,
    reachable: verdict.reachable,
    reason: verdict.reason,
  };
});

const reachable = perRule.filter((r) => r.reachable);
const unreachable = perRule.filter((r) => !r.reachable);

/** Group the unreachable rules by header, so the App side gets an actionable list. */
const byHeader = {};
for (const r of unreachable) {
  const key = r.header ?? '(no header)';
  byHeader[key] = (byHeader[key] ?? 0) + 1;
}
const headerActions = Object.entries(byHeader)
  .map(([header, count]) => ({ header, rulesThatBecomeReachable: count }))
  .sort((a, b) => (b.rulesThatBecomeReachable - a.rulesThatBecomeReachable) || (a.header < b.header ? -1 : 1));

const register = {
  schemaVersion: 'drobon.interop.app-dast-reachability/v1',
  asOf: '2026-10-21',
  app: { repo: APP_PROFILE.repo, commit: APP_PROFILE.commit },
  measuredFrom: [
    'scripts/lib/app-evaluator-profile.mjs#APP_DAST_SURFACE',
    'packs/dast/v1/rules/DPK-DAST-*.json',
  ],
  appSources: [
    'apps/api/src/scans/dast/engine.ts (INSPECTED_RESPONSE_HEADERS, boundedResponseHeaders)',
    'apps/api/src/scans/dast/activeEngine.ts (INSPECTED_HEADERS, boundedHeaders)',
  ],
  surface: {
    inspectedResponseHeaders: APP_DAST_SURFACE.inspectedResponseHeaders,
    headerValueChars: APP_DAST_SURFACE.headerValueChars,
    maxHeaderArrayEntries: APP_DAST_SURFACE.maxHeaderArrayEntries,
    bodyInspectionBytes: APP_DAST_SURFACE.bodyInspectionBytes,
  },
  totals: {
    dastRules: rules.length,
    reachable: reachable.length,
    unreachable: unreachable.length,
    reachablePct: Math.round((reachable.length / rules.length) * 1000) / 10,
  },
  headerActions,
  unreachable: unreachable.map((r) => ({ id: r.id, header: r.header, checkType: r.checkType })),
  countingNotes: [
    'Reachability is a property of the App response surface, not of rule correctness. An unreachable rule keeps its tests, its evaluation case and its severity; it simply cannot be evaluated by the App until the header is forwarded.',
    'Body rules are reachable but bounded: the App clips the body to 32,768 bytes and reports truncation, so evidence beyond that limit is invisible to every body check.',
  ],
};

const serialized = `${JSON.stringify(register, null, 2)}\n`;
const target = join(ROOT, OUT);

if (WRITE) {
  writeFileSync(target, serialized);
  console.log(`wrote ${OUT}`);
  console.log(`  ${register.totals.reachable}/${register.totals.dastRules} reachable (${register.totals.reachablePct}%), ${register.totals.unreachable} unreachable across ${headerActions.length} headers`);
} else {
  let current;
  try {
    current = readFileSync(target, 'utf8');
  } catch {
    console.error(`NOT OK - ${OUT} is missing; run with --write`);
    process.exit(1);
  }
  if (current !== serialized) {
    console.error(`NOT OK - ${OUT} no longer reproduces from the tree; run node scripts/validate-app-dast-reachability.mjs --write`);
    process.exit(1);
  }
  console.log(`ok - app-dast-reachability: ${register.totals.reachable}/${register.totals.dastRules} rules reachable through the App surface (${register.totals.unreachable} documented)`);
  console.log(`ok - app-dast-reachability: ${headerActions.length} header(s) would unlock ${register.totals.unreachable} rule(s)`);
}
