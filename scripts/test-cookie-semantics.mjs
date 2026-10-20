/**
 * DROBON Set-Cookie semantic differential gate (original, DROBON-authored).
 *
 * What it proves
 * --------------
 * The DAST cookie rules (DPK-DAST-004 / -006 / -008) are single-predicate rules:
 * they report a cookie that lacks Secure, HttpOnly or SameSite. This gate checks
 * the predicate layer — the DROBON Set-Cookie model in scripts/lib/set-cookie.mjs
 * — against an independent, declarative oracle built in two directions:
 *
 *   curated rows : header text -> expected model (hand-written expectation)
 *   generated rows: model -> rendered header text -> parsed model -> rule verdict
 *
 * The second direction matters. If the parser and the renderer shared an
 * assumption, a pure "parse then compare" test would pass while both were wrong.
 * Rendering is therefore driven by the model, and the rule is then run against
 * the produced text through the real evaluator (validate-packs.mjs), so each
 * generated case asserts the end-to-end verdict rather than a parser detail.
 *
 * Suites
 * ------
 * A. parser unit tests (shape, attribute identity, last-wins, quoting, discard)
 * B. flag predicates (Secure, HttpOnly, SameSite presence rules)
 * C. curated rule-vs-oracle rows for the three cookie rules
 * D. generated model -> text -> parse -> rule pairs (fixed LCG, fixed seed)
 * E. pinned limitations (never presented as correctness)
 *
 * Determinism: fixed LCG, no clock, no randomness, no network. Two runs print
 * identical output.
 */
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { evalDastCheck } from './validate-packs.mjs';
import {
  cookieDiscardReason,
  cookieHasFlag,
  cookieIsDiscarded,
  cookieStorageRejection,
  parseSetCookie,
} from './lib/set-cookie.mjs';

const ROOT = resolve(new URL('..', import.meta.url).pathname);
const RULES_DIR = join(ROOT, 'packs', 'dast', 'v1', 'rules');

const failures = [];
let passed = 0;

function check(label, actual, expected) {
  const same = JSON.stringify(actual) === JSON.stringify(expected);
  if (same) passed += 1;
  else failures.push(`${label}: got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`);
}

function rule(flag) {
  if (flag === 'Secure') return 'DPK-DAST-004';
  if (flag === 'HttpOnly') return 'DPK-DAST-006';
  return 'DPK-DAST-008';
}

function fires(ruleId, cookie) {
  const flags = { 'DPK-DAST-004': 'Secure', 'DPK-DAST-006': 'HttpOnly', 'DPK-DAST-008': 'SameSite' };
  return evalDastCheck(
    { type: 'cookie-missing-flag', flag: flags[ruleId] },
    { url: 'https://app.example/', status: 200, headers: { 'set-cookie': cookie } },
  );
}

// ---------------------------------------------------------------------------
// A. Parser unit tests
// ---------------------------------------------------------------------------
const parserRows = [
  // [raw, expected subset of the parsed model]
  ['sid=abc', { ok: true, name: 'sid', value: 'abc', secure: false, httpOnly: false, sameSite: 'absent' }],
  ['sid=abc; Secure; HttpOnly', { ok: true, name: 'sid', value: 'abc', secure: true, httpOnly: true, sameSite: 'absent' }],
  ['sid=abc; secure; httponly', { ok: true, secure: true, httpOnly: true }],
  ['sid=abc; Secure=0', { ok: true, secure: true, evidence: 'secure=0' }],
  ['sid=abc; HttpOnly=false', { ok: true, httpOnly: true, evidence: 'httponly=false' }],
  ['sid=abc; SameSite=Lax', { ok: true, sameSite: 'declared', effective: 'lax' }],
  ['sid=abc; samesite = STRICT', { ok: true, sameSite: 'declared', effective: 'strict' }],
  ['sid=abc; SameSite=None; Secure', { ok: true, sameSite: 'declared', effective: 'none', secure: true }],
  ['sid=abc; SameSite=', { ok: true, sameSite: 'unrecognised', effective: 'default' }],
  ['sid=abc; SameSite', { ok: true, sameSite: 'unrecognised' }],
  ['sid=abc; SameSite=Bogus', { ok: true, sameSite: 'unrecognised' }],
  ['sid=abc; SameSite=Lax; SameSite=None', { ok: true, sameSite: 'declared', effective: 'none' }],
  ['sid=abc; Path=/; Secure;', { ok: true, secure: true }],
  ['sid=abc; Secure ; HttpOnly', { ok: true, secure: true, httpOnly: true }],
  ['sid=abc; Secure=; HttpOnly', { ok: true, secure: true, httpOnly: true }],
  ['  sid = abc  ;  Secure  ', { ok: true, name: 'sid', value: 'abc', secure: true }],
  ['sid="a;b"; Secure', { ok: true, secure: true }],
  ['sid="a; Secure"', { ok: true, secure: false }],
  ['sid=abc; Unknown=x; Secure', { ok: true, secure: true, attributes: 2 }],
  ['sid=abc; Max-Age=0; Expires=Wed, 21 Oct 2015 07:28:00 GMT', { ok: true }],
  ['no-equals', { ok: false, reason: 'no-name-value-pair' }],
  ['=orphan', { ok: false, reason: 'no-name-value-pair' }],
  ['', { ok: false, reason: 'empty' }],
  ['sid=a\u0001b; Secure', { ok: false, reason: 'control-character' }],
];

for (const [raw, expected] of parserRows) {
  const parsed = parseSetCookie(raw);
  const view = { ok: parsed.ok };
  if (!parsed.ok) {
    view.reason = parsed.reason;
  } else {
    view.name = parsed.name;
    view.value = parsed.value;
    view.secure = parsed.flags.secure;
    view.httpOnly = parsed.flags.httpOnly;
    view.sameSite = parsed.sameSite.state;
    if (parsed.sameSite.state !== 'absent') view.effective = parsed.sameSite.effective;
    if (parsed.evidence.secure !== null) view.evidence = parsed.evidence.secure;
    if (parsed.evidence.httpOnly !== null) view.evidenceEvidence = parsed.evidence.httpOnly;
    view.attributes = parsed.attributes.length;
  }
  // Compare only the fields the row pins.
  const mismatched = Object.entries(expected).filter(([key, value]) => {
    const actual = key === 'evidence'
      ? (parsed.ok ? (parsed.evidence.secure ?? parsed.evidence.httpOnly) : null)
      : view[key];
    return JSON.stringify(actual) !== JSON.stringify(value);
  });
  if (mismatched.length === 0) passed += 1;
  else {
    failures.push(
      `A parser ${JSON.stringify(raw)}: ` +
      mismatched.map(([key, value]) => `${key} got ${JSON.stringify(view[key])} want ${JSON.stringify(value)}`).join('; '),
    );
  }
}

check('A discard reason is stable', cookieDiscardReason('no-equals'), 'no-name-value-pair');
check('A stored header is not discarded', cookieIsDiscarded('sid=1; Secure'), false);
check('A quoted semicolon does not create an attribute', parseSetCookie('sid="a; Secure"').attributes.length, 0);

// ---------------------------------------------------------------------------
// B. Flag predicates
// ---------------------------------------------------------------------------
const predicateRows = [
  ['sid=1; Secure', 'Secure', true],
  ['sid=1; Secure=0', 'Secure', true],
  ['sid=1; secure=0', 'Secure', true],
  ['sid=1', 'Secure', false],
  ['sid=1; Secure=0; Secure=1', 'Secure', true],
  ['sid=1; HttpOnly', 'HttpOnly', true],
  ['sid=1; HttpOnly=0', 'HttpOnly', true],
  ['sid=1; Secure', 'HttpOnly', false],
  ['sid=1; SameSite=Lax', 'SameSite', true],
  ['sid=1; SameSite=None', 'SameSite', true],
  ['sid=1; SameSite=', 'SameSite', false],
  ['sid=1; SameSite', 'SameSite', false],
  ['sid=1; SameSite=Bogus', 'SameSite', false],
  ['sid=1; Secure', 'SameSite', false],
  ['no-equals', 'Secure', false],
  ['sid=1; Path=/', 'unknown-flag', false],
];
for (const [raw, flag, expected] of predicateRows) {
  check(`B predicate ${JSON.stringify(raw)} ${flag}`, cookieHasFlag(raw, flag), expected);
}

// ---------------------------------------------------------------------------
// C. Curated rule-vs-oracle rows
// ---------------------------------------------------------------------------
const curated = [
  // DPK-DAST-004 Secure
  ['DPK-DAST-004', 'id=1; Path=/', true],
  ['DPK-DAST-004', 'id=1; Path=/; Secure; HttpOnly', false],
  ['DPK-DAST-004', 'id=1; Secure=0', false],
  ['DPK-DAST-004', 'id=1; secure; httponly', false],
  ['DPK-DAST-004', 'id=1; SameSite=Lax', true],
  ['DPK-DAST-004', 'no-equals-sign', false],
  // DPK-DAST-006 HttpOnly
  ['DPK-DAST-006', 'id=1; Path=/; Secure', true],
  ['DPK-DAST-006', 'id=1; Path=/; Secure; HttpOnly', false],
  ['DPK-DAST-006', 'id=1; HttpOnly=1', false],
  ['DPK-DAST-006', 'id=1; Path=/; Secure; HttpOnly ; SameSite=Lax', false],
  ['DPK-DAST-006', '=orphan-name', false],
  // DPK-DAST-008 SameSite
  ['DPK-DAST-008', 'id=1; Path=/', true],
  ['DPK-DAST-008', 'id=1; Path=/; Secure; HttpOnly; SameSite=Lax', false],
  ['DPK-DAST-008', 'id=1; Path=/; Secure; HttpOnly; SameSite = Strict', false],
  ['DPK-DAST-008', 'id=1; Secure; HttpOnly; SameSite=', true],
  ['DPK-DAST-008', 'id=1; Secure; HttpOnly; SameSite=none', false],
  ['DPK-DAST-008', 'no-equals-sign', false],
  // A SameSite=None cookie without Secure is refused by browsers, so no cookie
  // is stored and no storage flag can be missing. DPK-DAST-071 owns the defect.
  ['DPK-DAST-004', 'id=1; SameSite=None', false],
  ['DPK-DAST-006', 'id=1; SameSite=None', false],
  ['DPK-DAST-008', 'id=1; SameSite=None', false],
  ['DPK-DAST-004', 'id=1; SameSite=None; Secure', false],
  ['DPK-DAST-006', 'id=1; SameSite=None; Secure', true],
];
for (const [ruleId, cookie, expected] of curated) {
  check(`C ${ruleId} ${JSON.stringify(cookie)}`, fires(ruleId, cookie), expected);
}

// Every curated row must be a case the shipped rule file also asserts, so the
// gate cannot drift into testing an idea the rules do not implement.
const ruleTests = {
  'DPK-DAST-004': JSON.parse(readFileSync(join(RULES_DIR, 'DPK-DAST-004.json'), 'utf8')),
  'DPK-DAST-006': JSON.parse(readFileSync(join(RULES_DIR, 'DPK-DAST-006.json'), 'utf8')),
  'DPK-DAST-008': JSON.parse(readFileSync(join(RULES_DIR, 'DPK-DAST-008.json'), 'utf8')),
};
for (const [ruleId, cookie, expected] of curated) {
  const declared = ruleTests[ruleId].tests.some(
    (test) => test.observation.headers['set-cookie'] === cookie && test.match === expected,
  );
  check(`C ${ruleId} row is shipped in the rule file: ${JSON.stringify(cookie)}`, declared, true);
}

// ---------------------------------------------------------------------------
// D. Generated model -> text -> parse -> rule
// ---------------------------------------------------------------------------
// LCG parameters from Numerical Recipes; the same generator family is used by
// the CSP gate so the two gates do not need a random source.
const SEED = 0x5e7c00c1;
let state = SEED >>> 0;
function next() {
  state = (Math.imul(1664525, state) + 1013904223) >>> 0;
  return state / 0x100000000;
}
function pick(list) {
  return list[Math.floor(next() * list.length) % list.length];
}

const SAME_SITE_VALUES = ['Strict', 'Lax', 'None', 'strict', 'lax', 'none'];
const FLAG_FORMS = {
  secure: ['Secure', 'secure', 'SECURE', 'Secure=0', 'Secure=1', 'Secure=false', 'Secure='],
  httponly: ['HttpOnly', 'httponly', 'HTTPONLY', 'HttpOnly=0', 'HttpOnly=1', 'HttpOnly=true'],
};
const SAME_SITE_FORMS = {
  declared: SAME_SITE_VALUES,
  unrecognised: ['', 'Bogus', 'LAX2', 'NONE1'],
};

/**
 * Render one cookie from a declarative model. The model is the source of truth;
 * the renderer only chooses presentation (order, case, redundant attributes).
 */
function render(model) {
  if (model.discard === 'no-equals') return `${model.name}${model.value}`;
  if (model.discard === 'control') return `${model.name}=${model.value}\u0007`;
  const parts = [`${model.name}=${model.value}`];
  if (model.path) parts.push(`Path=${model.path}`);
  if (model.expires) parts.push('Expires=Wed, 21 Oct 2015 07:28:00 GMT');
  if (model.maxAge !== null) parts.push(`Max-Age=${model.maxAge}`);
  if (model.secure) parts.push(pick(FLAG_FORMS.secure));
  if (model.httpOnly) parts.push(pick(FLAG_FORMS.httponly));
  if (model.sameSite !== null) {
    parts.push(model.sameSiteValue.length === 0 ? 'SameSite=' : `SameSite=${model.sameSiteValue}`);
  }
  // Presentation noise: duplicated flags, empty segments, padding.
  if (model.secure && next() < 0.25) parts.push('Secure');
  if (model.httpOnly && next() < 0.25) parts.push('HttpOnly');
  if (next() < 0.2) parts.push('');
  return parts.join('; ');
}

const generated = [];
const RULES = ['DPK-DAST-004', 'DPK-DAST-006', 'DPK-DAST-008'];
for (let index = 0; index < 300; index += 1) {
  const model = {
    name: pick(['sid', 'token', 'prefs', 'a']),
    value: pick(['1', 'abc', 'x.y', '']),
    secure: next() < 0.55,
    httpOnly: next() < 0.5,
    sameSite: next() < 0.6 ? (next() < 0.75 ? 'declared' : 'unrecognised') : null,
    sameSiteValue: null,
    path: next() < 0.5 ? '/' : null,
    expires: next() < 0.2,
    maxAge: next() < 0.2 ? pick([0, 300, 86400]) : null,
    discard: next() < 0.08 ? pick(['no-equals', 'control']) : null,
  };
  if (model.sameSite !== null) {
    model.sameSiteValue = pick(SAME_SITE_FORMS[model.sameSite]);
  }
  const text = render(model);
  const ruleId = RULES[index % RULES.length];
  // The oracle applies the two storage rules first: a discarded header stores
  // nothing, and a SameSite=None cookie without Secure is refused by browsers
  // (DPK-DAST-071 owns that case, so the flag rules must stay silent).
  const refused = model.sameSite === 'declared'
    && model.sameSiteValue.toLowerCase() === 'none'
    && !model.secure;
  const expected = (model.discard !== null || refused)
    ? false
    : (() => {
        if (ruleId === 'DPK-DAST-004') return !model.secure;
        if (ruleId === 'DPK-DAST-006') return !model.httpOnly;
        if (model.sameSite === null) return true;
        if (model.sameSite === 'unrecognised') return true;
        return false;
      })();
  generated.push([ruleId, text, expected, model]);
}
for (const [ruleId, text, expected, model] of generated) {
  const actual = fires(ruleId, text);
  if (actual === expected) passed += 1;
  else failures.push(`D ${ruleId} ${JSON.stringify(text)} (model ${JSON.stringify(model)}): got ${actual}, want ${expected}`);
}

// Round-trip: the parser must recover the model the renderer was given.
for (const [, text, , model] of generated) {
  const parsed = parseSetCookie(text);
  const recovered = model.discard !== null
    ? { ok: false }
    : {
        ok: true,
        secure: parsed.flags.secure,
        httpOnly: parsed.flags.httpOnly,
        sameSite: parsed.sameSite.state,
      };
  const expected = model.discard !== null
    ? { ok: false }
    : {
        ok: true,
        secure: model.secure,
        httpOnly: model.httpOnly,
        sameSite: model.sameSite === null ? 'absent' : model.sameSite,
      };
  check(`D round-trip ${JSON.stringify(text)}`, recovered, expected);
}

// ---------------------------------------------------------------------------
// E. Pinned limitations (documentation of known behaviour, not correctness)
// ---------------------------------------------------------------------------
// E1: a folded multi-cookie single value is read as one cookie. The model says
// so; the rule cannot be better than the observation shape allows.
check('E1 folded header is read as one cookie', parseSetCookie('a=1; Secure, b=2').name, 'a');
// E2: the observation has no clock, so expiry is attribute identity only.
check('E2 Max-Age=0 does not remove the attributed flag', cookieHasFlag('sid=1; Max-Age=0', 'Secure'), false);
// E3: SameSite=None without Secure is rejected by browsers but is not this
// rule's question; the model reports what the response declared.
check('E3 SameSite=None is reported as declared without judging Secure', parseSetCookie('sid=1; SameSite=None').sameSite.effective, 'none');
// E4: a cookie-prefix violation (__Secure- without Secure) is browser policy and
// is deliberately not modelled.
check('E4 prefix rule is not modelled', parseSetCookie('__Secure-sid=1').flags.secure, false);

// ---------------------------------------------------------------------------
// F. Cross-rule duplicate findings
// ---------------------------------------------------------------------------
// Two rules must never report the same cookie for the same underlying reason.
// The one overlap this repository has is SameSite=None without Secure: browsers
// refuse the cookie, so the flag rules stay silent and DPK-DAST-071 reports it.
const crossChecks = {
  'DPK-DAST-004': ruleTests['DPK-DAST-004'].check,
  'DPK-DAST-006': ruleTests['DPK-DAST-006'].check,
  'DPK-DAST-008': ruleTests['DPK-DAST-008'].check,
  'DPK-DAST-071': JSON.parse(readFileSync(join(RULES_DIR, 'DPK-DAST-071.json'), 'utf8')).check,
};
function firesWith(ruleId, cookie) {
  return evalDastCheck(crossChecks[ruleId], {
    url: 'https://app.example/',
    status: 200,
    headers: { 'set-cookie': cookie },
  });
}
const crossCorpus = [
  ...curated.map(([, cookie]) => cookie),
  ...generated.map(([, text]) => text),
  'id=1; SameSite=None; Secure; HttpOnly',
  'id=1; SameSite=None; HttpOnly',
  'id=1; SameSite=none; Secure=0',
];
for (const cookie of crossCorpus) {
  const s071 = firesWith('DPK-DAST-071', cookie);
  const storage = ['DPK-DAST-004', 'DPK-DAST-006', 'DPK-DAST-008'].map((id) => firesWith(id, cookie));
  const duplicate = s071 && storage.some(Boolean);
  check(`F no duplicate finding for ${JSON.stringify(cookie)}`, duplicate, false);
  // 071 must also agree with the model: it reports exactly the refused cookie.
  const parsed = parseSetCookie(cookie);
  const modelRefused = parsed.ok
    && parsed.sameSite.state === 'declared'
    && parsed.sameSite.effective === 'none'
    && parsed.flags.secure === false;
  check(`F 071 agrees with the storage model for ${JSON.stringify(cookie)}`, s071, modelRefused);
}

// The storage predicate itself: refused exactly when the model says so.
for (const cookie of crossCorpus) {
  const parsed = parseSetCookie(cookie);
  const modelRefused = !parsed.ok
    || (parsed.sameSite.state === 'declared'
      && parsed.sameSite.effective === 'none'
      && parsed.flags.secure === false);
  check(`F storage predicate ${JSON.stringify(cookie)}`, cookieStorageRejection(cookie) !== null, modelRefused);
}

const generatedTotal = generated.length * 2;
process.stdout.write(
  `cookie-semantics: ${failures.length === 0 ? 'PASS' : 'FAIL'} `
  + `(${passed}/${passed + failures.length} assertions; ${curated.length} curated rule rows, `
  + `${generatedTotal} generated pairs, ${crossCorpus.length} cross-rule inputs)\n`,
);
for (const failure of failures) process.stdout.write(`  NOT OK - ${failure}\n`);
process.exitCode = failures.length === 0 ? 0 : 1;
