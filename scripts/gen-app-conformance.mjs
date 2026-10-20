#!/usr/bin/env node
/**
 * gen-app-conformance.mjs — measure this repository's pack semantics against the
 * Main App's loader implementation, and publish the result as a runnable artefact
 * the App can consume.
 *
 *   node scripts/gen-app-conformance.mjs --write   # regenerate interop/app-conformance.json + APP_CONFORMANCE.md
 *   node scripts/gen-app-conformance.mjs --check   # fail if either file no longer reproduces
 *
 * What it measures (all from the tree, never from prose):
 *   1. Acceptance + behaviour parity of every declared pack test through the App's
 *      documented conversion path (SAST line matcher, Secrets matcher + denylist
 *      veto, DAST seven-check evaluator), using scripts/lib/app-evaluator-profile.mjs
 *      — a transcription of the App source at the pinned commit.
 *   2. Language reachability: which pack language ids the App catalog resolves.
 *   3. The App loader checklist (docs/PACKS.md) status, recorded as facts with the
 *      App file each one was observed in (validated for shape and coverage, not
 *      re-derived — the App is a separate repository).
 *   4. The SCA status-surface mapping table, so both sides implement one contract.
 *
 * No network, no writes unless --write. Runs in `npm test` (check mode).
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  APP_PROFILE,
  appAcceptsDast,
  appEvaluateDast,
  appSastMatches,
  appSecretsMatches,
} from './lib/app-evaluator-profile.mjs';
import { renderAppConformance } from './lib/app-conformance-md.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = 'interop/app-conformance.json';
const MD_OUT = 'interop/APP_CONFORMANCE.md';
const WRITE = process.argv.includes('--write');

const read = (rel) => readFileSync(join(ROOT, rel), 'utf8');
const readJson = (rel) => JSON.parse(read(rel));
const rules = (family) => readdirSync(join(ROOT, 'packs', family, 'v1', 'rules'))
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => JSON.parse(read(join('packs', family, 'v1', 'rules', f))));

// ---------------------------------------------------------------- parity ----
const sast = rules('sast');
const secrets = rules('secrets');
const dast = rules('dast');

const parityOf = (familyRules, runOne) => {
  let declared = 0;
  let accepted = 0;
  let mismatches = 0;
  for (const rule of familyRules) {
    for (const test of rule.tests ?? []) {
      declared += 1;
      const { accepted: ok, fires } = runOne(rule, test);
      if (ok) accepted += 1;
      if (fires !== test.match) mismatches += 1;
    }
  }
  return { rules: familyRules.length, declaredTests: declared, acceptedTests: accepted, mismatches };
};

const sastParity = parityOf(sast, (rule, test) => appSastMatches(rule, test.line));
const secretsParity = parityOf(secrets, (rule, test) => appSecretsMatches(rule, test.line));

const causes = {
  COOKIE_MODEL_ABSENT: 'The App parses Set-Cookie with a string split and compares whole attributes case-insensitively. This repository models the browser: a discarded header stores no cookie, Secure/HttpOnly ignore their value (Secure=0 is the flag on), and SameSite only counts with a recognised Strict/Lax/None value (scripts/lib/set-cookie.mjs).',
  BLANK_VALUE_ARRAY: 'The App joins repeated header values with ", " and trims the result, so "present but every value blank" never looks empty. This repository treats an all-blank header as absent (docs/PACKS.md, missing-response-header).',
  ARRAY_JOIN_CROSS_VALUE: 'The App evaluates a repeated header as one ", "-joined string, so a pattern can match across a value boundary. This repository evaluates the header semantics per docs/PACKS.md.',
};

function causeOf(checkType) {
  if (checkType === 'cookie-missing-flag') return 'COOKIE_MODEL_ABSENT';
  if (checkType === 'missing-response-header') return 'BLANK_VALUE_ARRAY';
  if (checkType === 'response-header-matches') return 'ARRAY_JOIN_CROSS_VALUE';
  return 'UNCLASSIFIED';
}

const dastDivergences = [];
let dastDeclared = 0;
let dastAccepted = 0;
for (const rule of dast) {
  if (appAcceptsDast(rule)) dastAccepted += 1;
  for (const [testIndex, test] of (rule.tests ?? []).entries()) {
    dastDeclared += 1;
    // Node-realistic observation: incoming header names are lowercased, arrays kept.
    const headers = {};
    for (const [k, v] of Object.entries(test.observation?.headers ?? {})) headers[k.toLowerCase()] = v;
    const obs = { ...test.observation, headers };
    const appYields = appAcceptsDast(rule) ? appEvaluateDast(rule.check, obs) : false;
    if (appYields !== test.match) {
      dastDivergences.push({
        ruleId: rule.id,
        testIndex,
        checkType: rule.check.type,
        observation: obs,
        datasetExpects: test.match,
        appYields,
        cause: causeOf(rule.check.type),
      });
    }
  }
}
const dastParity = {
  rules: dast.length,
  declaredTests: dastDeclared,
  acceptedRules: dastAccepted,
  mismatches: dastDivergences.length,
  mismatchedRules: [...new Set(dastDivergences.map((d) => d.ruleId))].sort(),
};

// ------------------------------------------------------- reachability ------
const catalog = readJson('data/app-language-catalog.json');
const appIds = new Set(catalog.ids);
const aliases = catalog.aliases;
const usage = new Map();
const universal = [];
for (const rule of sast) {
  const langs = Array.isArray(rule.languages) ? rule.languages : [];
  if (langs.length === 0) {
    universal.push(rule.id);
    continue;
  }
  for (const id of langs) {
    if (!usage.has(id)) usage.set(id, []);
    usage.get(id).push(rule.id);
  }
}
const direct = [...usage.keys()].filter((id) => appIds.has(id));
const aliased = [...usage.keys()].filter((id) => !appIds.has(id) && aliases[id] !== undefined);
const needsFamily = [...usage.keys()].filter((id) => !appIds.has(id) && aliases[id] === undefined);
const unreachable = sast
  .filter((rule) => (rule.languages ?? []).length > 0)
  .filter((rule) => !rule.languages.some((id) => appIds.has(id) || aliases[id] !== undefined))
  .map((rule) => rule.id);

const languageReachability = {
  catalogCommit: catalog.appCommit,
  idsUsed: usage.size,
  resolvedDirectly: direct.length,
  resolvedByAlias: aliased.length,
  needsAppFamily: needsFamily.length,
  universalRules: universal.length,
  rulesReachable: sast.length - unreachable.length,
  rulesUnreachable: unreachable.length,
  unreachableRuleIds: unreachable,
};

// ------------------------------------------------ loader checklist facts ---
const loaderChecklist = [
  {
    step: 1,
    requirement: 'Validate packs with this repo\'s validator semantics; fail closed on unknown schema, field or check type',
    status: 'PARTIAL',
    appEvidence: 'apps/api/src/external/service.ts (shape guard: string schemaVersion + string id only)',
    gap: 'Unknown fields are unchecked and an unknown DAST check type silently evaluates to false instead of refusing the pack.',
  },
  {
    step: 2,
    requirement: 'Gate SAST rules by the App language catalog',
    status: 'DONE',
    appEvidence: 'apps/api/src/scans/sast/engine.ts (rule.languages.includes(file.family))',
    gap: 'Implemented; the residual reachability gap is a catalog-coverage problem, measured above.',
  },
  {
    step: 3,
    requirement: 'Re-run bounded-time ReDoS regression over all pack patterns',
    status: 'MISSING',
    appEvidence: 'apps/api/src/external/packProvider.ts (compiles patterns, no budget)',
    gap: 'No pathological-input budget runs over the pack patterns before they go live.',
  },
  {
    step: 4,
    requirement: 'Execute every rule\'s declared examples at load and refuse failing packs',
    status: 'MISSING',
    appEvidence: 'apps/api/src/external/packProvider.ts (converts only, never runs rule.tests)',
    gap: 'The direct cause of the DAST divergences recorded above: a rule whose declared tests disagree ships silently.',
  },
  {
    step: 5,
    requirement: 'Redact secrets evidence per redact / matchOnlyEvidence before persisting',
    status: 'DONE',
    appEvidence: 'apps/api/src/scans/secrets/engine.ts (positional redaction, fail-closed fallback)',
    gap: 'Implemented and covered by the App secrets suite.',
  },
  {
    step: 6,
    requirement: 'Surface pack id + version in scan metadata so findings trace to data versions',
    status: 'MISSING',
    appEvidence: 'apps/api/src/external/service.ts (pack.json is never read)',
    gap: 'A finding cannot be traced to the dataset version that produced it.',
  },
];

// ------------------------------------------------------- status mapping ----
const scaStatusMapping = [
  { case: 'provider none', providerDatasetStatus: 'NO_DATA_LOADED', advisories: 0, scanState: 'NOT_ASSESSED', honestMeaning: 'no data was consulted' },
  { case: 'path wrong or unreadable', providerDatasetStatus: 'DATASET_UNAVAILABLE', advisories: 0, scanState: 'NOT_ASSESSED', honestMeaning: 'data was not reachable at scan time' },
  { case: 'loaded, coordinate absent from corpus', providerDatasetStatus: 'DATASET_AVAILABLE', advisories: 0, scanState: 'NOT_ASSESSED', honestMeaning: 'not in this corpus — not "clean"' },
  { case: 'loaded, package present, version outside every range', providerDatasetStatus: 'DATASET_AVAILABLE', advisories: 0, scanState: 'NOT_ASSESSED', honestMeaning: 'no known advisory applies to this dataset version' },
  { case: 'loaded, range matches', providerDatasetStatus: 'DATASET_AVAILABLE', advisories: '>=1', scanState: 'ASSESSED', honestMeaning: 'verified match with per-record provenance' },
  {
    case: 'dataset-side simulator, zero matches with data loaded',
    providerDatasetStatus: 'ASSESSED (simulator naming)',
    advisories: 0,
    scanState: 'NOT_ASSESSED (App mapping)',
    honestMeaning: 'the two fields move differently by design; advisory sets agree (16/16 vectors)',
  },
];

const out = {
  schemaVersion: 'drobon.app.conformance/v1',
  note: 'Measured parity between this repository\'s pack semantics and the Main App loader at the pinned commit. Generated by scripts/gen-app-conformance.mjs; do not edit by hand. The divergence list is a defect register for the App, not an adjustment of our semantics: the declared pack tests remain the ground truth.',
  generatedFrom: {
    appProfile: APP_PROFILE,
    packs: {
      sast: sast.length,
      secrets: secrets.length,
      dast: dast.length,
    },
  },
  parity: {
    sast: sastParity,
    secrets: secretsParity,
    dast: dastParity,
  },
  causes,
  dastDivergences,
  languageReachability,
  loaderChecklist,
  scaStatusMapping,
  counting: {
    statusSurfaceReports: 100,
    canonicalItems: 84,
    canonicalIds: 78,
    note: 'The App reports the raw advisory file count; docs/COUNTING_POLICY.md defines 84 identity items and 78 advisory ids for the same tree.',
  },
};

const serialized = `${JSON.stringify(out, null, 2)}\n`;
const renderedMd = renderAppConformance(out);

if (WRITE) {
  writeFileSync(join(ROOT, OUT), serialized);
  writeFileSync(join(ROOT, MD_OUT), renderedMd);
  process.stdout.write(`wrote ${OUT} and ${MD_OUT}\n`);
  process.stdout.write(`  sast ${sastParity.mismatches}/${sastParity.declaredTests} mismatches · secrets ${secretsParity.mismatches}/${secretsParity.declaredTests} · dast ${dastParity.mismatches}/${dastParity.declaredTests}\n`);
  process.stdout.write(`  language: ${languageReachability.rulesReachable}/${sast.length} rules reachable, ${languageReachability.rulesUnreachable} unreachable\n`);
  process.exit(0);
}

for (const [file, expected] of [[OUT, serialized], [MD_OUT, renderedMd]]) {
  let current;
  try {
    current = read(file);
  } catch {
    process.stderr.write(`app-conformance: MISSING ${file} — run node scripts/gen-app-conformance.mjs --write\n`);
    process.exit(1);
  }
  if (current !== expected) {
    process.stderr.write(`app-conformance: STALE ${file} — the tree changed; run node scripts/gen-app-conformance.mjs --write\n`);
    process.exit(1);
  }
}
process.stdout.write(`app-conformance: OK — ${OUT} reproduces from the tree\n`);
process.stdout.write(`  parity: sast ${sastParity.mismatches}/${sastParity.declaredTests} · secrets ${secretsParity.mismatches}/${secretsParity.declaredTests} · dast ${dastParity.mismatches}/${dastParity.declaredTests} mismatches\n`);
process.stdout.write(`  reachability: ${languageReachability.rulesReachable}/${sast.length} SAST rules reachable through the App catalog\n`);
process.stdout.write(`  loader checklist: ${loaderChecklist.filter((s) => s.status === 'DONE').length}/6 done, ${loaderChecklist.filter((s) => s.status === 'PARTIAL').length} partial, ${loaderChecklist.filter((s) => s.status === 'MISSING').length} missing\n`);
