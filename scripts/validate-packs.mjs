#!/usr/bin/env node
/**
 * Zero-dependency validator for Drobon rule packs:
 *   drobon.pack.sast/v1, drobon.pack.secrets/v1, drobon.pack.dast/v1
 *
 * This is the EXECUTABLE SPEC for packs (see docs/PACKS.md). Beyond
 * closed shapes and bounds it EXECUTES every rule against its own
 * example tests: a SAST/secrets pattern must reproduce every declared
 * match/miss, and a DAST check must reproduce every declared
 * observation outcome. Patterns also pass a conservative static ReDoS
 * lint (no nested quantifiers, no repeated unbounded wildcards).
 *
 * Packs have NO sample concept: every shipped rule must be a genuine,
 * tested rule. Ids containing "-SAMPLE-" are rejected everywhere.
 *
 * Usage: node scripts/validate-packs.mjs [path...]  (default: packs)
 */
import { readdirSync, statSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { checkBoundedText, checkClosed, readJsonFile } from './validate.mjs';

export const PACK_SCHEMAS = {
  sast: 'drobon.pack.sast/v1',
  secrets: 'drobon.pack.secrets/v1',
  dast: 'drobon.pack.dast/v1',
};

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const CONFIDENCES = ['LOW', 'MEDIUM', 'HIGH'];
const COOKIE_FLAGS = ['Secure', 'HttpOnly', 'SameSite'];
const DAST_CHECK_TYPES = [
  'http-url',
  'missing-response-header',
  'response-header-missing-directive',
  'response-header-matches',
  'response-body-matches',
  'response-header-host-differs',
  'cookie-missing-flag',
];

const ID_PATTERNS = {
  sast: /^DPK-SAST-[0-9]{3,}$/,
  secrets: /^DPK-SEC-[0-9]{3,}$/,
  dast: /^DPK-DAST-[0-9]{3,}$/,
};
// Mirrors FINDING_CWE_PATTERN (Drobon app, packages/shared/src/scans.ts): no leading zeros.
const CWE_PATTERN = /^CWE-[1-9][0-9]{0,5}$/;
const CATEGORY_PATTERN = /^[a-z0-9-]{1,64}$/;
const LANGUAGE_PATTERN = /^[a-z][a-z0-9]{0,31}$/;
const HEADER_TOKEN = /^[A-Za-z0-9-]{1,64}$/;
const PACK_ID_PATTERN = /^[a-z0-9-]{1,64}$/;
const PACK_VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+$/;

const MAX_TITLE = 120;
const MAX_TEXT = 1000; // description, remediation, limitation
const MAX_PATTERN = 500;
const MAX_LINE = 1000;
const MAX_DENYLIST = 64;
const MAX_PATTERNS = 8;
const MAX_TESTS = 50;
const MAX_LANGUAGES = 10;
const MAX_DENYLIST_ENTRIES = 20;
const MAX_URL = 400;
const MAX_HEADERS = 30;
const MAX_HEADER_VALUE = 1000;
const MAX_BODY = 4000;
const MAX_CONTENT_TYPE = 200;
const MAX_PACK_DESCRIPTION = 400;

const BASE_REQUIRED = [
  'schemaVersion',
  'id',
  'title',
  'description',
  'severity',
  'category',
  'remediation',
  'limitation',
];
const SAST_ALLOWED = [...BASE_REQUIRED, 'cwe', 'languages', 'patterns', 'tests', 'patternRefs'];
const SAST_REQUIRED = [...BASE_REQUIRED, 'patterns', 'tests', 'patternRefs'];
const SECRETS_ALLOWED = [...BASE_REQUIRED, 'cwe', 'confidence', 'patterns', 'tests', 'denylist', 'matchOnlyEvidence', 'redact', 'patternRefs'];
const SECRETS_REQUIRED = [...BASE_REQUIRED, 'confidence', 'patterns', 'tests', 'redact', 'patternRefs'];
const DAST_ALLOWED = [...BASE_REQUIRED, 'cwe', 'check', 'tests', 'patternRefs'];
const DAST_REQUIRED = [...BASE_REQUIRED, 'check', 'tests', 'patternRefs'];
const MANIFEST_ALLOWED = ['schemaVersion', 'packId', 'version', 'description'];
const MANIFEST_REQUIRED = ['schemaVersion', 'packId', 'version'];

function kindOf(schemaVersion) {
  return Object.keys(PACK_SCHEMAS).find((kind) => PACK_SCHEMAS[kind] === schemaVersion) ?? null;
}

/**
 * Conservative static ReDoS lint. Returns a reason string, or null.
 * Rejects nested quantifiers — `(a*)*` — and repeated unbounded
 * wildcards — `.*.*`. Character classes are stripped first so `[.*]`
 * literals never trip the lint. This is necessary, not sufficient:
 * the app-side loader must also run bounded-time regression tests.
 */
export function lintRedos(source) {
  const noClasses = source.replace(/\[(?:\\.|[^\]\\])*\]/g, '');
  const noGroupSyntax = noClasses.replace(/\(\?([=:!])/g, '($1');
  if (/\([^()]*[+*?][^()]*\)[+*?]/.test(noGroupSyntax)) {
    return 'nested quantifier — rewrite without a quantified group containing a quantifier';
  }
  if (/(\.\*|\.\+).{0,12}(\.\*|\.\+)/.test(noClasses)) {
    return 'repeated unbounded wildcard — rewrite without adjacent .* / .+ runs';
  }
  return null;
}

function compilePattern(errors, path, source, flags) {
  if (flags !== undefined && flags !== 'i') {
    errors.push(`${path}.flags: only "i" is allowed (no g/y/m/s)`);
    return null;
  }
  let regex = null;
  try {
    // eslint-disable-next-line require-unicode-regexp
    regex = new RegExp(source, flags ?? '');
  } catch {
    errors.push(`${path}.source: invalid regex (${source.slice(0, 60)})`);
    return null;
  }
  const lint = lintRedos(source);
  if (lint !== null) {
    errors.push(`${path}.source: ReDoS lint failed (${lint})`);
    return null;
  }
  return regex;
}

function checkBase(errors, record, kind) {
  const idPattern = ID_PATTERNS[kind];
  if (record['id'] !== undefined) {
    if (typeof record['id'] !== 'string' || !idPattern.test(record['id'])) {
      errors.push(`id: must match ${idPattern} (packs have no -SAMPLE- ids)`);
    }
  }
  if (record['title'] !== undefined) {
    checkBoundedText(errors, 'title', record['title'], MAX_TITLE);
  }
  for (const field of ['description', 'remediation', 'limitation']) {
    if (record[field] !== undefined) {
      checkBoundedText(errors, field, record[field], MAX_TEXT);
    }
  }
  if (record['severity'] !== undefined && !SEVERITIES.includes(record['severity'])) {
    errors.push(`severity: must be one of ${SEVERITIES.join(', ')}`);
  }
  if (record['category'] !== undefined) {
    if (typeof record['category'] !== 'string' || !CATEGORY_PATTERN.test(record['category'])) {
      errors.push('category: must match ^[a-z0-9-]{1,64}$');
    }
  }
  if (record['cwe'] !== undefined) {
    if (typeof record['cwe'] !== 'string' || !CWE_PATTERN.test(record['cwe'])) {
      errors.push('cwe: must match ^CWE-[1-9][0-9]{0,5}$ (omit when uncertain)');
    }
  }
  checkPatternRefs(errors, record);
}

const PATTERN_REF_PATTERN = /^DPK-PAT-[0-9]{4,}$/;

function checkPatternRefs(errors, record) {
  if (record['patternRefs'] === undefined) {
    return; // presence is enforced by the REQUIRED lists
  }
  if (!Array.isArray(record['patternRefs']) || record['patternRefs'].length < 1) {
    errors.push('patternRefs: must be a non-empty array of pattern ids');
    return;
  }
  const seen = new Set();
  record['patternRefs'].forEach((entry, index) => {
    if (typeof entry !== 'string' || !PATTERN_REF_PATTERN.test(entry)) {
      errors.push(`patternRefs[${index}]: must match ${PATTERN_REF_PATTERN}`);
    } else if (seen.has(entry)) {
      errors.push(`patternRefs[${index}]: duplicate pattern ref "${entry}"`);
    } else {
      seen.add(entry);
    }
  });
}

function checkPatterns(errors, record) {
  const compiled = [];
  if (record['patterns'] === undefined) {
    return compiled;
  }
  if (!Array.isArray(record['patterns'])) {
    errors.push('patterns: must be an array');
    return compiled;
  }
  if (record['patterns'].length < 1 || record['patterns'].length > MAX_PATTERNS) {
    errors.push(`patterns: must have 1..${MAX_PATTERNS} entries`);
    return compiled;
  }
  record['patterns'].forEach((entry, index) => {
    const path = `patterns[${index}]`;
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      errors.push(`${path}: must be an object`);
      return;
    }
    checkClosed(errors, path, entry, ['source', 'flags'], ['source']);
    if (entry['source'] !== undefined) {
      checkBoundedText(errors, `${path}.source`, entry['source'], MAX_PATTERN);
      if (typeof entry['source'] === 'string' && entry['source'].length > 0) {
        const regex = compilePattern(errors, path, entry['source'], entry['flags']);
        if (regex !== null) {
          compiled.push(regex);
        }
      }
    }
  });
  return compiled;
}

function checkLineTests(errors, record, compiled, denylist) {
  if (record['tests'] === undefined) {
    return;
  }
  if (!Array.isArray(record['tests'])) {
    errors.push('tests: must be an array');
    return;
  }
  if (record['tests'].length < 2 || record['tests'].length > MAX_TESTS) {
    errors.push(`tests: must have 2..${MAX_TESTS} entries`);
    return;
  }
  let positives = 0;
  let negatives = 0;
  record['tests'].forEach((entry, index) => {
    const path = `tests[#${index}]`;
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      errors.push(`${path}: must be an object`);
      return;
    }
    checkClosed(errors, path, entry, ['line', 'match'], ['line', 'match']);
    if (entry['line'] !== undefined) {
      checkBoundedText(errors, `${path}.line`, entry['line'], MAX_LINE);
    }
    if (entry['match'] !== undefined && typeof entry['match'] !== 'boolean') {
      errors.push(`${path}.match: must be a boolean`);
      return;
    }
    if (typeof entry['line'] !== 'string' || typeof entry['match'] !== 'boolean') {
      return;
    }
    if (entry['match']) {
      positives += 1;
    } else {
      negatives += 1;
    }
    if (compiled.length === 0) {
      return; // pattern errors already reported; cannot execute
    }
    let hit = compiled.some((regex) => {
      regex.lastIndex = 0;
      return regex.test(entry['line']);
    });
    if (hit && denylist.length > 0) {
      const lowered = entry['line'].toLowerCase();
      if (denylist.some((deny) => lowered.includes(deny.toLowerCase()))) {
        hit = false;
      }
    }
    if (hit !== entry['match']) {
      errors.push(
        `${path}: expected match=${String(entry['match'])} but patterns say ${String(hit)} for line "${entry['line'].slice(0, 80)}"`,
      );
    }
  });
  if (positives < 1 || negatives < 1) {
    errors.push('tests: must include at least one positive and one negative example');
  }
}

function checkDenylist(errors, record) {
  if (record['denylist'] === undefined) {
    return [];
  }
  if (!Array.isArray(record['denylist'])) {
    errors.push('denylist: must be an array');
    return [];
  }
  if (record['denylist'].length > MAX_DENYLIST_ENTRIES) {
    errors.push(`denylist: at most ${MAX_DENYLIST_ENTRIES} entries`);
    return [];
  }
  const out = [];
  record['denylist'].forEach((entry, index) => {
    checkBoundedText(errors, `denylist[${index}]`, entry, MAX_DENYLIST);
    if (typeof entry === 'string' && entry.length > 0) {
      out.push(entry);
    }
  });
  return out;
}

function normalizeHeaders(headers) {
  const normalized = {};
  for (const [name, value] of Object.entries(headers)) {
    normalized[name.toLowerCase()] = Array.isArray(value) ? value : [value];
  }
  return normalized;
}

function headerHasDirective(values, directive) {
  const want = directive.toLowerCase();
  // RFC list headers (e.g. Cache-Control) separate directives with commas; CSP
  // separates directives with ';' and policies with ','. Split on both.
  return values.some((value) =>
    value.split(/[;,]/).some((part) => {
      const name = part.trim().split(/[=\s]/, 1)[0]?.toLowerCase();
      return name === want;
    }),
  );
}

function cookieHasFlag(cookie, flag) {
  if (flag === 'SameSite') {
    return /(?:^|;)\s*SameSite\s*=/i.test(cookie);
  }
  return new RegExp(`(?:^|;)\\s*${flag}(?:;|$)`, 'i').test(cookie);
}

/**
 * Evaluate one DAST check against one normalized observation.
 * Pure function — the same semantics the app-side loader must implement.
 */
export function evalDastCheck(check, observation) {
  const headers = normalizeHeaders(observation.headers);
  switch (check.type) {
    case 'http-url':
      return new URL(observation.url).protocol === 'http:';
    case 'missing-response-header':
      return headers[check.header.toLowerCase()] === undefined;
    case 'response-header-missing-directive': {
      const values = headers[check.header.toLowerCase()];
      return values === undefined || !headerHasDirective(values, check.directive);
    }
    case 'response-header-matches': {
      const values = headers[check.header.toLowerCase()];
      if (values === undefined) {
        return false; // header absent: nothing discloses
      }
      // eslint-disable-next-line require-unicode-regexp
      const valueRe = new RegExp(check.valuePattern, 'i');
      return values.some((value) => valueRe.test(value));
    }
    case 'cookie-missing-flag': {
      const cookies = headers['set-cookie'];
      if (cookies === undefined) {
        return false; // no cookies: nothing to flag
      }
      return cookies.some((cookie) => !cookieHasFlag(cookie, check.flag));
    }
    case 'response-body-matches': {
      if (check.requireScheme !== undefined) {
        // Scope check: only observations fetched over the required scheme are judged.
        if (new URL(observation.url).protocol !== `${check.requireScheme}:`) {
          return false;
        }
      }
      if (typeof observation.body !== 'string') {
        return false; // no body captured: nothing to match
      }
      // eslint-disable-next-line require-unicode-regexp
      return new RegExp(check.valuePattern, 'i').test(observation.body);
    }
    case 'response-header-host-differs': {
      const values = headers[check.header.toLowerCase()];
      if (values === undefined || observation.status < 300 || observation.status > 399) {
        return false; // not a redirect carrying this header
      }
      let target;
      try {
        target = new URL(values[0], observation.url);
      } catch {
        return false; // unparseable target: unknown, never a match
      }
      if (target.protocol !== 'http:' && target.protocol !== 'https:') {
        return false; // non-web schemes are out of this check's scope
      }
      return target.hostname !== new URL(observation.url).hostname;
    }
    default:
      throw new Error(`unknown check type "${check.type}"`);
  }
}

function checkDastCheck(errors, record) {
  if (record['check'] === undefined) {
    return null;
  }
  const check = record['check'];
  if (typeof check !== 'object' || check === null || Array.isArray(check)) {
    errors.push('check: must be an object');
    return null;
  }
  if (typeof check['type'] !== 'string' || !DAST_CHECK_TYPES.includes(check['type'])) {
    errors.push(`check.type: must be one of ${DAST_CHECK_TYPES.join(', ')}`);
    return null;
  }
  const specs = {
    'http-url': { allowed: ['type'], required: ['type'] },
    'missing-response-header': { allowed: ['type', 'header'], required: ['type', 'header'] },
    'response-header-missing-directive': {
      allowed: ['type', 'header', 'directive'],
      required: ['type', 'header', 'directive'],
    },
    'cookie-missing-flag': { allowed: ['type', 'flag'], required: ['type', 'flag'] },
    'response-header-matches': {
      allowed: ['type', 'header', 'valuePattern'],
      required: ['type', 'header', 'valuePattern'],
    },
    'response-body-matches': {
      allowed: ['type', 'valuePattern', 'requireScheme'],
      required: ['type', 'valuePattern'],
    },
    'response-header-host-differs': {
      allowed: ['type', 'header'],
      required: ['type', 'header'],
    },
  };
  const spec = specs[check['type']];
  checkClosed(errors, 'check', check, spec.allowed, spec.required);
  if (check['header'] !== undefined) {
    if (typeof check['header'] !== 'string' || !HEADER_TOKEN.test(check['header'])) {
      errors.push('check.header: must be an HTTP token (1..64 chars)');
    }
  }
  if (check['directive'] !== undefined) {
    if (typeof check['directive'] !== 'string' || !HEADER_TOKEN.test(check['directive'])) {
      errors.push('check.directive: must be an HTTP token (1..64 chars)');
    }
  }
  if (check['flag'] !== undefined && !COOKIE_FLAGS.includes(check['flag'])) {
    errors.push(`check.flag: must be one of ${COOKIE_FLAGS.join(', ')}`);
  }
  if (check['requireScheme'] !== undefined && check['requireScheme'] !== 'http' && check['requireScheme'] !== 'https') {
    errors.push('check.requireScheme: must be http or https');
  }
  if (check['valuePattern'] !== undefined) {
    checkBoundedText(errors, 'check.valuePattern', check['valuePattern'], MAX_PATTERN);
    if (typeof check['valuePattern'] === 'string' && check['valuePattern'].length > 0) {
      try {
        // eslint-disable-next-line require-unicode-regexp
        new RegExp(check['valuePattern'], 'i');
      } catch {
        errors.push('check.valuePattern: invalid regex');
      }
      const lint = lintRedos(check['valuePattern']);
      if (lint !== null) {
        errors.push(`check.valuePattern: ReDoS lint failed (${lint})`);
      }
    }
  }
  return check;
}

function checkObservation(errors, path, value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    errors.push(`${path}: must be an object`);
    return null;
  }
  checkClosed(errors, path, value, ['url', 'status', 'headers', 'body', 'contentType'], ['url', 'status', 'headers']);
  checkBoundedText(errors, `${path}.url`, value['url'], MAX_URL);
  let urlOk = false;
  if (typeof value['url'] === 'string') {
    try {
      const protocol = new URL(value['url']).protocol;
      urlOk = protocol === 'http:' || protocol === 'https:';
    } catch {
      urlOk = false;
    }
    if (!urlOk) {
      errors.push(`${path}.url: must be a valid http(s) URL`);
    }
  }
  if (
    typeof value['status'] !== 'number' ||
    !Number.isInteger(value['status']) ||
    value['status'] < 100 ||
    value['status'] > 599
  ) {
    errors.push(`${path}.status: must be an integer 100..599`);
  }
  if (typeof value['headers'] !== 'object' || value['headers'] === null || Array.isArray(value['headers'])) {
    errors.push(`${path}.headers: must be an object`);
  } else {
    const names = Object.keys(value['headers']);
    if (names.length > MAX_HEADERS) {
      errors.push(`${path}.headers: at most ${MAX_HEADERS} headers`);
    }
    for (const name of names) {
      if (!HEADER_TOKEN.test(name)) {
        errors.push(`${path}.headers: bad header name "${name.slice(0, 40)}"`);
        continue;
      }
      const headerValue = value['headers'][name];
      const values = Array.isArray(headerValue) ? headerValue : [headerValue];
      for (const single of values) {
        if (typeof single !== 'string' || single.length > MAX_HEADER_VALUE) {
          errors.push(`${path}.headers.${name}: values must be strings ≤${MAX_HEADER_VALUE} chars`);
        }
      }
    }
  }
  if (value['body'] !== undefined) {
    if (typeof value['body'] !== 'string' || value['body'].length > MAX_BODY) {
      errors.push(`${path}.body: must be a string ≤${MAX_BODY} chars`);
    }
  }
  if (value['contentType'] !== undefined) {
    checkBoundedText(errors, `${path}.contentType`, value['contentType'], MAX_CONTENT_TYPE);
  }
  const clean = errors.length === 0;
  return clean && urlOk ? value : clean ? value : null;
}

function checkDastTests(errors, record, check) {
  if (record['tests'] === undefined) {
    return;
  }
  if (!Array.isArray(record['tests'])) {
    errors.push('tests: must be an array');
    return;
  }
  if (record['tests'].length < 2 || record['tests'].length > MAX_TESTS) {
    errors.push(`tests: must have 2..${MAX_TESTS} entries`);
    return;
  }
  let positives = 0;
  let negatives = 0;
  record['tests'].forEach((entry, index) => {
    const path = `tests[#${index}]`;
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      errors.push(`${path}: must be an object`);
      return;
    }
    checkClosed(errors, path, entry, ['observation', 'match'], ['observation', 'match']);
    const before = errors.length;
    const observation = entry['observation'] === undefined ? null : checkObservation(errors, `${path}.observation`, entry['observation']);
    if (entry['match'] !== undefined && typeof entry['match'] !== 'boolean') {
      errors.push(`${path}.match: must be a boolean`);
      return;
    }
    if (typeof entry['match'] !== 'boolean') {
      return;
    }
    if (entry['match']) {
      positives += 1;
    } else {
      negatives += 1;
    }
    if (observation === null || check === null || errors.length !== before) {
      return; // structural errors already reported; cannot execute
    }
    let hit;
    try {
      hit = evalDastCheck(check, observation);
    } catch (err) {
      errors.push(`${path}: cannot evaluate check (${err.message})`);
      return;
    }
    if (hit !== entry['match']) {
      errors.push(`${path}: expected match=${String(entry['match'])} but check says ${String(hit)}`);
    }
  });
  if (positives < 1 || negatives < 1) {
    errors.push('tests: must include at least one positive and one negative example');
  }
}

function validateSastRule(record) {
  const errors = [];
  checkClosed(errors, 'record', record, SAST_ALLOWED, SAST_REQUIRED);
  checkBase(errors, record, 'sast');
  if (record['languages'] !== undefined) {
    if (!Array.isArray(record['languages'])) {
      errors.push('languages: must be an array');
    } else if (record['languages'].length < 1 || record['languages'].length > MAX_LANGUAGES) {
      errors.push(`languages: must have 1..${MAX_LANGUAGES} entries (omit for universal rules)`);
    } else {
      record['languages'].forEach((entry, index) => {
        if (typeof entry !== 'string' || !LANGUAGE_PATTERN.test(entry)) {
          errors.push(`languages[${index}]: must match ^[a-z][a-z0-9]{0,31}$ and exist in the app language catalog`);
        }
      });
    }
  }
  const compiled = checkPatterns(errors, record);
  checkLineTests(errors, record, compiled, []);
  return errors;
}

function validateSecretsRule(record) {
  const errors = [];
  checkClosed(errors, 'record', record, SECRETS_ALLOWED, SECRETS_REQUIRED);
  checkBase(errors, record, 'secrets');
  if (record['confidence'] !== undefined && !CONFIDENCES.includes(record['confidence'])) {
    errors.push(`confidence: must be one of ${CONFIDENCES.join(', ')} (detection confidence, never "credential is live")`);
  }
  if (record['redact'] !== undefined && record['redact'] !== true) {
    errors.push('redact: must be true (pack rules must promise evidence redaction)');
  }
  if (record['matchOnlyEvidence'] !== undefined && typeof record['matchOnlyEvidence'] !== 'boolean') {
    errors.push('matchOnlyEvidence: must be a boolean');
  }
  const compiled = checkPatterns(errors, record);
  const denylist = checkDenylist(errors, record);
  checkLineTests(errors, record, compiled, denylist);
  return errors;
}

function validateDastRule(record) {
  const errors = [];
  checkClosed(errors, 'record', record, DAST_ALLOWED, DAST_REQUIRED);
  checkBase(errors, record, 'dast');
  const check = checkDastCheck(errors, record);
  checkDastTests(errors, record, check);
  return errors;
}

/** Validate one parsed pack rule file. Routes on schemaVersion. */
export function validatePackFile(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return ['record: must be an object'];
  }
  const kind = kindOf(value['schemaVersion']);
  if (kind === 'sast') {
    return validateSastRule(value);
  }
  if (kind === 'secrets') {
    return validateSecretsRule(value);
  }
  if (kind === 'dast') {
    return validateDastRule(value);
  }
  return [`schemaVersion: must be one of ${Object.values(PACK_SCHEMAS).join(', ')}`];
}

/** Validate one parsed pack.json manifest. */
export function validatePackManifest(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return ['manifest: must be an object'];
  }
  const errors = [];
  checkClosed(errors, 'manifest', value, MANIFEST_ALLOWED, MANIFEST_REQUIRED);
  if (value['schemaVersion'] !== undefined && kindOf(value['schemaVersion']) === null) {
    errors.push(`manifest.schemaVersion: must be one of ${Object.values(PACK_SCHEMAS).join(', ')}`);
  }
  if (value['packId'] !== undefined) {
    if (typeof value['packId'] !== 'string' || !PACK_ID_PATTERN.test(value['packId'])) {
      errors.push('manifest.packId: must match ^[a-z0-9-]{1,64}$');
    }
  }
  if (value['version'] !== undefined) {
    if (typeof value['version'] !== 'string' || !PACK_VERSION_PATTERN.test(value['version'])) {
      errors.push('manifest.version: must match ^N.N.N$');
    }
  }
  if (value['description'] !== undefined) {
    checkBoundedText(errors, 'manifest.description', value['description'], MAX_PACK_DESCRIPTION);
  }
  return errors;
}

export function validatePackPath(filePath) {
  const loaded = readJsonFile(filePath);
  if (loaded.errors !== undefined) return loaded.errors;
  const errors =
    basename(filePath) === 'pack.json' ? validatePackManifest(loaded.value) : validatePackFile(loaded.value);
  return errors.map((error) => `${filePath}: ${error}`);
}

function collectJsonFiles(target) {
  const stat = statSync(target);
  if (stat.isFile()) {
    return target.endsWith('.json') ? [target] : [];
  }
  const found = [];
  const walk = (dir) => {
    const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && entry.name.endsWith('.json')) {
        found.push(full);
      }
    }
  };
  walk(target);
  return found;
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (invokedAsScript) {
  const targets = process.argv.slice(2);
  const roots = (targets.length > 0 ? targets : ['packs']).map((target) =>
    resolve(process.cwd(), target),
  );
  const failures = [];
  let fileCount = 0;
  for (const root of roots) {
    let files;
    try {
      files = collectJsonFiles(root);
    } catch (err) {
      failures.push(`${root}: cannot read: ${err.message}`);
      continue;
    }
    fileCount += files.length;
    for (const file of files) {
      failures.push(...validatePackPath(file));
    }
  }
  if (fileCount === 0 && failures.length === 0) {
    failures.push('no JSON files found (refusing to pass on empty input)');
  }
  for (const failure of failures) {
    process.stdout.write(`${failure}\n`);
  }
  if (failures.length > 0) {
    process.stdout.write(`validate-packs: FAIL (${fileCount} files, ${failures.length} errors)\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`validate-packs: PASS (${fileCount} files, 0 errors)\n`);
  }
}
