/**
 * DROBON AEGIS — CSP semantic differential gate.
 *
 * The DAST corpus detects CSP weaknesses with regular expressions over one
 * header value. That is fast and auditable, but a regex cannot tell you *why*
 * `default-src 'self'` makes `object-src` unnecessary, or that
 * `'unsafe-inline'` stops counting once the directive carries a nonce.
 *
 * This gate builds the missing semantic layer (scripts/lib/csp.mjs) and runs it
 * as an **independent oracle**: every CSP rule is executed through the real
 * evaluator and compared with the parser's answer on the same observation.
 * Any disagreement is either a defect in the rule or a defect in the oracle —
 * both must be resolved, never skipped.
 *
 * Suites
 * ------
 *   A. Parser unit tests (grammar, fallback chain, duplicate directives).
 *   B. Semantic predicate unit tests.
 *   C. Curated single-policy differential matrix (rule vs oracle).
 *   D. Generated differential corpus (deterministic, 400 policies).
 *   E. Characterisation of the one known limitation class that a single-value
 *      regex cannot express (multi-policy intersection).
 *
 * Determinism: the generator is a fixed LCG with a fixed seed; no randomness,
 * no clock, no I/O beyond the rule files. Two runs produce identical output.
 */
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { evalDastCheck } from './validate-packs.mjs';
import {
  allowsScheme,
  declaresDirective,
  effectiveSources,
  hasBareWildcard,
  hasNonceOrHash,
  hasUnsafeEval,
  hasUnsafeInline,
  headerAllowsEval,
  headerAllowsInlineScripting,
  headerDirectiveAllowsPlaintext,
  headerHasBaseUriWildcard,
  headerHasDirectiveWildcard,
  headerHasFormActionWildcard,
  headerSandboxEscapable,
  headerHasConnectSrcWildcard,
  headerHasDefaultSrcWildcard,
  headerHasFrameAncestorsWildcard,
  headerHasScriptSrcWildcard,
  headerObjectSrcUnconstrained,
  headerReportUriAllowsPlaintext,
  headerScriptAllowsData,
  headerScriptAllowsPlaintext,
  parseCspHeader,
} from './lib/csp.mjs';

const ROOT = resolve(import.meta.dirname, '..');
let passed = 0;
const failures = [];

function assert(condition, label, detail) {
  if (condition) {
    passed += 1;
    return;
  }
  failures.push(`${label}${detail === undefined ? '' : `\n    ${detail}`}`);
}

function loadRule(id) {
  return JSON.parse(readFileSync(join(ROOT, 'packs', 'dast', 'v1', 'rules', `${id}.json`), 'utf8'));
}

function evaluate(ruleId, cspValue) {
  const rule = loadRule(ruleId);
  const headers = cspValue === null ? {} : { 'Content-Security-Policy': cspValue };
  return evalDastCheck(rule.check, { url: 'https://app.example/', status: 200, headers }) === true;
}

function oracle(ruleId, cspValue) {
  const parsed = parseCspHeader(cspValue ?? '');
  switch (ruleId) {
    case 'DPK-DAST-021': return headerAllowsInlineScripting(parsed);
    case 'DPK-DAST-022': return headerHasDefaultSrcWildcard(parsed);
    case 'DPK-DAST-061': return headerAllowsEval(parsed);
    case 'DPK-DAST-070': return headerHasScriptSrcWildcard(parsed);
    case 'DPK-DAST-075': return headerObjectSrcUnconstrained(parsed);
    case 'DPK-DAST-086': return headerHasConnectSrcWildcard(parsed);
    case 'DPK-DAST-092': return headerHasFrameAncestorsWildcard(parsed);
    case 'DPK-DAST-093': return headerScriptAllowsPlaintext(parsed);
    case 'DPK-DAST-095': return headerScriptAllowsData(parsed);
    case 'DPK-DAST-098': return headerHasBaseUriWildcard(parsed);
    case 'DPK-DAST-099': return headerHasFormActionWildcard(parsed);
    case 'DPK-DAST-102': return headerDirectiveAllowsPlaintext(parsed, 'connect-src');
    case 'DPK-DAST-103': return headerDirectiveAllowsPlaintext(parsed, 'form-action');
    case 'DPK-DAST-104': return headerHasDirectiveWildcard(parsed, 'frame-src');
    case 'DPK-DAST-105': return headerHasDirectiveWildcard(parsed, 'object-src');
    case 'DPK-DAST-106': return headerSandboxEscapable(parsed);
    case 'DPK-DAST-107': return headerHasDirectiveWildcard(parsed, 'style-src');
    case 'DPK-DAST-108': return headerHasDirectiveWildcard(parsed, 'worker-src');
    case 'DPK-DAST-115': return headerReportUriAllowsPlaintext(parsed);
    default: throw new Error(`no oracle mapped for ${ruleId}`);
  }
}

const CSP_RULES = [
  'DPK-DAST-021', 'DPK-DAST-022', 'DPK-DAST-061', 'DPK-DAST-070', 'DPK-DAST-075',
  'DPK-DAST-086', 'DPK-DAST-092', 'DPK-DAST-093', 'DPK-DAST-095',
  'DPK-DAST-098', 'DPK-DAST-099', 'DPK-DAST-102', 'DPK-DAST-103',
  'DPK-DAST-104', 'DPK-DAST-105', 'DPK-DAST-106', 'DPK-DAST-107', 'DPK-DAST-108',
  'DPK-DAST-115',
];

// --- A. Parser unit tests -----------------------------------------------------
{
  const empty = parseCspHeader('');
  assert(empty.policyCount === 0 && empty.policies.length === 0, 'parser: empty header yields no policies');
  const nonString = parseCspHeader(undefined);
  assert(nonString.policyCount === 0, 'parser: non-string input never throws');

  const single = parseCspHeader("default-src 'self'");
  assert(single.policyCount === 1, 'parser: one policy');
  assert(single.policies[0].directives.get('default-src').join(' ') === "'self'", 'parser: source list tokenised');

  const multi = parseCspHeader("default-src 'self'; script-src 'self' https://cdn.example");
  assert(multi.policyCount === 1 && multi.policies[0].directives.has('script-src'), 'parser: semicolon separates directives');

  const comma = parseCspHeader("default-src 'self', script-src 'self'");
  assert(comma.policyCount === 2, 'parser: comma separates policies');
  assert(comma.policies[1].directives.has('script-src'), 'parser: second policy parsed independently');

  const upper = parseCspHeader("DEFAULT-SRC 'self'; Script-Src 'self'");
  assert(upper.policies[0].directives.has('default-src') && upper.policies[0].directives.has('script-src'), 'parser: directive names are case-insensitive');

  const duplicate = parseCspHeader("script-src 'self'; script-src *");
  assert(duplicate.policies[0].directives.get('script-src').join(' ') === "'self'", 'parser: first duplicate directive wins');
  assert(duplicate.policies[0].directives.size === 1, 'parser: duplicate directive not stored twice');

  // An unknown-but-well-formed directive name is a directive the model simply
  // never consults; a segment that does not start with a token cannot be a
  // directive at all and is recorded as malformed.
  const unknown = parseCspHeader("script-src 'self'; future-directive x");
  assert(unknown.policies[0].malformed.length === 0 && unknown.policies[0].directives.has('future-directive'), 'parser: unknown directive name is kept, not treated as malformed');
  const junk = parseCspHeader("script-src 'self'; 'orphan-source'");
  assert(junk.policies[0].malformed.length === 1, 'parser: malformed segment recorded, not silently dropped');
  assert(junk.policies[0].directives.has('script-src'), 'parser: malformed segment does not discard valid ones');

  const spaced = parseCspHeader("  script-src    'self'   'none'  ;  ");
  assert(spaced.policies[0].directives.get('script-src').join('|') === "'self'|'none'", 'parser: whitespace runs collapse');

  const noSources = parseCspHeader('upgrade-insecure-requests');
  assert(noSources.policies[0].directives.get('upgrade-insecure-requests').length === 0, 'parser: flag directive has an empty source list');
}

// --- B. Semantic predicate unit tests ----------------------------------------
{
  const p = (v) => parseCspHeader(v).policies[0];

  assert(effectiveSources(p("default-src 'self'"), 'object-src').join(' ') === "'self'", 'semantics: object-src inherits default-src');
  assert(effectiveSources(p("default-src 'self'"), 'frame-ancestors') === null, 'semantics: frame-ancestors never inherits');
  assert(effectiveSources(p("default-src 'none'"), 'base-uri') === null, 'semantics: base-uri never inherits');
  assert(effectiveSources(p("script-src '*'"), 'script-src').length === 1, 'semantics: explicit directive wins over fallback');

  assert(hasBareWildcard(['*']) === true, 'semantics: bare wildcard detected');
  assert(hasBareWildcard(['https://*.example.com']) === false, 'semantics: host wildcard is not a bare wildcard');
  assert(hasBareWildcard(["'self'"]) === false, 'semantics: self is not a wildcard');

  assert(allowsScheme(['http:'], 'http') === true, 'semantics: scheme source matches its scheme');
  assert(allowsScheme(['http://cdn.example'], 'http') === true, 'semantics: host source matches its scheme');
  assert(allowsScheme(['https:'], 'http') === false, 'semantics: https does not grant http');

  assert(hasNonceOrHash(["'nonce-abc'"]) === true, 'semantics: nonce detected');
  assert(hasNonceOrHash(["'sha256-abc'"]) === true, 'semantics: hash detected');
  assert(hasNonceOrHash(["'self'"]) === false, 'semantics: self is not a nonce or hash');

  assert(hasUnsafeInline(["'unsafe-inline'"]) === true, 'semantics: quoted unsafe-inline detected');
  assert(hasUnsafeInline(["'self'"]) === false, 'semantics: self is not unsafe-inline');
  assert(hasUnsafeEval(["'unsafe-eval'"]) === true, 'semantics: unsafe-eval detected');

  assert(declaresDirective(p("script-src *"), 'script-src') === true, 'semantics: declared directive recognised');
  assert(declaresDirective(p("default-src 'self'"), 'script-src') === false, 'semantics: fallback is not a declaration');

  assert(headerAllowsInlineScripting(parseCspHeader("script-src 'unsafe-inline' 'nonce-x'")) === false, 'semantics: nonce neutralises unsafe-inline');
  assert(headerAllowsInlineScripting(parseCspHeader("style-src 'unsafe-inline'")) === true, 'semantics: style unsafe-inline counts');
  assert(headerObjectSrcUnconstrained(parseCspHeader("default-src 'none'")) === false, 'semantics: default-src constrains objects');
  assert(headerObjectSrcUnconstrained(parseCspHeader("script-src 'self'")) === true, 'semantics: no object-src and no default-src is unconstrained');
  assert(headerHasDefaultSrcWildcard(parseCspHeader("default-src 'self', default-src *")) === false, 'semantics: intersection of policies is not a wildcard');
}

// --- C. Curated differential matrix ------------------------------------------
// Every row is a single policy with no duplicate directive, so both the rule
// and the oracle must answer it exactly. The comment states the security fact
// that makes the expected answer non-negotiable.
const CURATED = [
  // default-src wildcard (022)
  ["default-src *", '022'],
  ["default-src 'self' *", '022'],
  ["default-src 'self'", '022'],
  ["default-src https://*.example.com", '022'],
  ["script-src *; default-src 'self'", '022'],
  // script-src wildcard (070)
  ["script-src *", '070'],
  ["script-src 'self' * 'unsafe-inline'", '070'],
  ["script-src https://*.cdn.example", '070'],
  ["default-src *; script-src 'self'", '070'],
  // connect-src wildcard (086)
  ["connect-src *", '086'],
  ["connect-src 'self' https://api.example", '086'],
  ["default-src *", '086'],
  // frame-ancestors wildcard (092)
  ["frame-ancestors *", '092'],
  ["frame-ancestors 'self'", '092'],
  ["default-src *; frame-ancestors 'self'", '092'],
  // script-src plaintext (093)
  ["script-src http:", '093'],
  ["script-src 'self' http://cdn.example", '093'],
  ["script-src https://cdn.example", '093'],
  ["default-src http:", '093'],
  // script-src data (095)
  ["script-src data:", '095'],
  ["script-src 'self' data: blob:", '095'],
  ["script-src 'self'", '095'],
  ["img-src data:", '095'],
  ["default-src data:", '095'],
  // object-src fallback (075)
  ["script-src 'self'", '075'],
  ["frame-ancestors 'self'; base-uri 'none'", '075'],
  ["default-src 'self'; script-src 'self'", '075'],
  ["default-src 'none'", '075'],
  ["object-src 'none'", '075'],
  ["object-src 'none'; default-src 'self'", '075'],
  // unsafe-inline (021)
  ["script-src 'unsafe-inline'", '021'],
  ["script-src 'unsafe-inline' 'nonce-abc'", '021'],
  ["script-src 'unsafe-inline' 'sha256-AAA'", '021'],
  ["style-src 'unsafe-inline'", '021'],
  ["style-src 'unsafe-inline' 'nonce-xyz'", '021'],
  ["script-src 'self'", '021'],
  ["script-src-attr 'unsafe-inline'", '021'],
  ["script-src 'unsafe-inline-x'", '021'],
  // A host that merely contains "nonce-" is not a nonce source expression.
  ["script-src https://nonce-cdn.example 'unsafe-inline'", '021'],
  ["script-src https://sha256-cdn.example 'unsafe-inline'", '021'],
  // Scheme-scoped wildcard hosts allow every origin of that scheme.
  ["default-src https://*", '022'],
  ["default-src http://*", '022'],
  ["default-src https://*.example.com", '022'],
  ["script-src https://*", '070'],
  ["script-src wss://*", '070'],
  ["connect-src https://*", '086'],
  ["connect-src https://*.api.example", '086'],
  ["frame-ancestors https://*", '092'],
  ["frame-ancestors https://*.example.com", '092'],
  // base-uri wildcard (098) - no default-src fallback for this directive
  ["base-uri *", '098'],
  ["base-uri 'self' *", '098'],
  ["base-uri https://*", '098'],
  ["base-uri 'self'", '098'],
  ["base-uri 'none'", '098'],
  ["default-src *", '098'],
  ["base-uri 'self'; base-uri *", '098'],
  // form-action wildcard (099)
  ["form-action *", '099'],
  ["form-action 'self' *", '099'],
  ["form-action http://*", '099'],
  ["form-action 'self'", '099'],
  ["form-action 'none'", '099'],
  ["default-src *", '099'],
  // connect-src / form-action plaintext (102, 103)
  ["connect-src http:", '102'],
  ["connect-src 'self' http://api.example", '102'],
  ["connect-src 'self' https://api.example", '102'],
  ["default-src http:", '102'],
  ["form-action http://pay.example", '103'],
  ["form-action 'self' https://pay.example", '103'],
  ["default-src http:", '103'],
  // frame-src / object-src / style-src / worker-src wildcards (104, 105, 107, 108)
  ["frame-src *", '104'],
  ["frame-src https://*", '104'],
  ["frame-src 'self'", '104'],
  ["object-src *", '105'],
  ["object-src 'none'", '105'],
  ["default-src *", '105'],
  ["style-src *", '107'],
  ["style-src 'self' https://*", '107'],
  ["style-src 'self'", '107'],
  ["worker-src *", '108'],
  ["worker-src https://*", '108'],
  ["worker-src 'self'", '108'],
  // CSP report-uri plaintext endpoint (115)
  ["report-uri http://collector.example/r", '115'],
  ["default-src 'self'; report-uri https://c.example/r http://backup.example/r", '115'],
  ["report-uri https://collector.example/r", '115'],
  ["report-uri /local-collector", '115'],
  ["report-to http://collector.example", '115'],
  ["report-uri https://a.example; report-uri http://b.example", '115'],
  // sandbox escape (106)
  ["sandbox allow-scripts allow-same-origin", '106'],
  ["sandbox allow-same-origin allow-scripts", '106'],
  ["sandbox allow-scripts", '106'],
  ["sandbox allow-same-origin", '106'],
  ["form-action 'self'; form-action *", '099'],
  // unsafe-eval (061)
  ["script-src 'unsafe-eval'", '061'],
  ["default-src 'unsafe-eval'", '061'],
  ["style-src 'unsafe-eval'", '061'],
  ["script-src 'self'", '061'],
];
for (const [policy, suffix] of CURATED) {
  const ruleId = `DPK-DAST-${suffix}`;
  const want = oracle(ruleId, policy);
  const got = evaluate(ruleId, policy);
  assert(got === want, `differential (curated): ${ruleId} on ${JSON.stringify(policy)}`, `oracle ${want}, rule ${got}`);
}

// Absent header is a distinct observation: 075 (and every CSP rule) must stay
// silent because DPK-DAST-002 owns "the header is missing".
for (const ruleId of CSP_RULES) {
  assert(evaluate(ruleId, null) === oracle(ruleId, null), `differential (curated): ${ruleId} on an absent header`, `oracle ${oracle(ruleId, null)}, rule ${evaluate(ruleId, null)}`);
}

// --- D. Generated differential corpus ---------------------------------------
// Deterministic LCG (Numerical Recipes constants). The pool is deliberately
// small so the product of possibilities is well covered; directives are drawn
// without repetition and no commas are emitted (multi-policy is suite E).
let seed = 0x5eed1234;
function nextInt(bound) {
  seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
  return seed % bound;
}

const DIRECTIVES = [
  'default-src', 'script-src', 'style-src', 'img-src', 'connect-src',
  'frame-src', 'frame-ancestors', 'object-src', 'base-uri', 'form-action',
  'worker-src', 'script-src-attr', 'media-src', 'sandbox', 'report-uri',
];
const SOURCES = [
  "'self'", "'none'", '*', 'https:', 'http:', 'data:', 'blob:',
  'https://cdn.example', 'http://cdn.example', 'https://*.example.com',
  'https://*', 'http://*', 'wss://*', 'https://nonce-cdn.example',
  "'unsafe-inline'", "'unsafe-eval'", "'nonce-abc123'", "'sha256-AAA111'",
  'allow-scripts', 'allow-same-origin',
];

function generatePolicy() {
  const count = 1 + nextInt(4);
  const used = new Set();
  const parts = [];
  for (let i = 0; i < count; i += 1) {
    let name = DIRECTIVES[nextInt(DIRECTIVES.length)];
    while (used.has(name)) name = DIRECTIVES[nextInt(DIRECTIVES.length)];
    used.add(name);
    const sources = [];
    const sourceCount = 1 + nextInt(3);
    for (let j = 0; j < sourceCount; j += 1) sources.push(SOURCES[nextInt(SOURCES.length)]);
    parts.push(`${name} ${sources.join(' ')}`);
  }
  return parts.join('; ');
}

const GENERATED = [];
for (let i = 0; i < 1200; i += 1) GENERATED.push(generatePolicy());

let generatedChecks = 0;
for (const policy of GENERATED) {
  for (const ruleId of CSP_RULES) {
    generatedChecks += 1;
    const want = oracle(ruleId, policy);
    const got = evaluate(ruleId, policy);
    assert(got === want, `differential (generated): ${ruleId}`, `${JSON.stringify(policy)} -> oracle ${want}, rule ${got}`);
  }
}

// The generator must actually produce both answers, otherwise the corpus would
// pass vacuously.
for (const ruleId of CSP_RULES) {
  const answers = new Set(GENERATED.map((policy) => oracle(ruleId, policy)));
  assert(answers.has(true) && answers.has(false), `generated corpus: ${ruleId} sees both true and false`, `saw ${JSON.stringify([...answers])}`);
}

// --- E. Characterisation: the one limitation a single-value regex cannot fix -
// CSP enforces every policy in a comma-separated list separately, so a resource
// is allowed only if *all* policies allow it. `default-src 'self', default-src *`
// therefore does not permit any origin. A regex that scans one header value has
// no way to say "and every policy agrees"; the oracle can. This suite pins the
// divergence so it is visible, quantified and impossible to forget — it is a
// known limitation, never a claim of correctness.
const MULTI_POLICY = [
  ["default-src 'self', default-src *", '022'],
  ["script-src 'self', script-src *", '070'],
  ["connect-src 'self', connect-src *", '086'],
  ["frame-ancestors 'self', frame-ancestors *", '092'],
];
for (const [policy, suffix] of MULTI_POLICY) {
  const ruleId = `DPK-DAST-${suffix}`;
  assert(oracle(ruleId, policy) === false, `known limitation: oracle treats ${JSON.stringify(policy)} as restricted (intersection)`);
  assert(evaluate(ruleId, policy) === true, `known limitation: ${ruleId} still reports the wildcard of a later policy`, 'if this changes, update the limitation ledger in docs/PACKS.md');
}

// E2. Keyword case. CSP source lists are case-sensitive: `'UNSAFE-INLINE'` is
// not the `'unsafe-inline'` keyword and grants nothing. The repository's
// `response-header-matches` check compiles its pattern with the `i` flag (header
// *names* and host names are case-insensitive, and one flag has to serve both),
// so the rule and the oracle both read the wrong-case token as the keyword.
// This is a property of the closed check-type vocabulary, not of the CSP model;
// it is pinned here so nobody mistakes the agreement for spec conformance.
assert(hasUnsafeInline(["'UNSAFE-INLINE'"]) === true, 'known limitation: keyword matching is case-insensitive in the model');
assert(evaluate('DPK-DAST-021', "script-src 'UNSAFE-INLINE'") === true, 'known limitation: 021 reports a wrong-case keyword', 'browsers ignore it; a case-sensitive check type is a vocabuary decision, not a rule fix');

// E3. Duplicate header values. A response may carry Content-Security-Policy more
// than once; the browser enforces all of them as an intersection. The evaluator
// tests each value independently (`some`), so a permissive value in one header
// is reported even when another header restricts the same directive. Expressing
// the intersection needs a check that receives the whole header list, which the
// seven-type vocabulary does not have (owner decision, docs/DAST_CHECK_TYPE_EXTENSION_PROPOSAL.md).
const duplicateHeaders = {
  url: 'https://app.example/',
  status: 200,
  headers: {
    'Content-Security-Policy': ["script-src 'self'", "script-src *"],
  },
};
assert(
  evalDastCheck(loadRule('DPK-DAST-070').check, duplicateHeaders) === true,
  'known limitation: a wildcard in one of two CSP headers is reported',
);

// --- summary -----------------------------------------------------------------
const generatedTotal = GENERATED.length * CSP_RULES.length;
process.stdout.write(
  `csp-semantics: ${failures.length === 0 ? 'PASS' : 'FAIL'} `
  + `(${passed}/${passed + failures.length} assertions; ${CURATED.length} curated, ${generatedTotal} generated rule/policy pairs)\n`,
);
for (const failure of failures) process.stdout.write(`  NOT OK - ${failure}\n`);
process.exitCode = failures.length === 0 ? 0 : 1;

export { generatedChecks };
