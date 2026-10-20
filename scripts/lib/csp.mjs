/**
 * DROBON AEGIS — Content-Security-Policy semantic model (original implementation).
 *
 * Why this file exists
 * --------------------
 * The DAST evaluator is deliberately tiny: seven closed check types, each
 * reading one header value with a regular expression. That is a fine transport
 * for single-token checks, but a CSP header is not a bag of tokens — it is a
 * small grammar with a fallback chain, duplicate-directive resolution and a
 * multi-policy intersection rule. Writing more regex rules against that grammar
 * keeps producing local fixes for global questions.
 *
 * This module is the missing analysis layer for CSP: a parser plus the small
 * set of semantic predicates the DAST rules actually ask. It is **not** a new
 * check type, not a second evaluator and not a parallel catalogue. The rule
 * files keep their existing `response-header-matches` /
 * `response-header-missing-directive` checks; this model is used as an
 * independent oracle so those checks can be differentially tested against real
 * grammar semantics (scripts/test-csp-semantics.mjs).
 *
 * Design decisions that belong to DROBON (not to any spec)
 * -------------------------------------------------------
 * 1. A *header-level* predicate is true only when **every** policy carried by
 *    the header independently satisfies it. CSP enforces each policy in a
 *    comma-separated list separately, so a resource is allowed only if all
 *    policies allow it; a wildcard in one policy cannot widen the intersection.
 * 2. A malformed policy is parsed leniently (tokens that are not directives are
 *    ignored) and never throws: a broken policy must not masquerade as a
 *    finding, and an observation must never crash the evaluator.
 * 3. Only the directives this repository has rules for are given predicates.
 *    The parser knows the fetch/non-fetch split because that split changes what
 *    "the directive is missing" means.
 *
 * What this model deliberately does NOT do
 * ----------------------------------------
 * - It does not decide whether a URL is actually blocked by a policy. The DAST
 *   engine observes one static response and never sees the resource list.
 * - It does not evaluate `report-uri`, `report-to`, `require-trusted-types-for`
 *   or Trusted Types semantics.
 * - It does not model the `strict-dynamic` cascade, because that would require
 *   knowing which scripts are nonce'd at runtime.
 *
 * Grammar facts encoded here are drawn from the CSP Level 3 specification
 * (W3C): comma separates policies, semicolon separates directives, the directive
 * name is the first whitespace-delimited token, source expressions are the
 * remaining tokens, and a repeated directive name inside one policy is ignored
 * after its first occurrence. No third-party implementation or rule text was
 * consulted or copied; the predicates below are written for this repository.
 */

/** Directives that fall back to `default-src` when absent (CSP3 § 6.1). */
export const FETCH_DIRECTIVES = new Set([
  'child-src',
  'connect-src',
  'default-src',
  'font-src',
  'frame-src',
  'img-src',
  'manifest-src',
  'media-src',
  'object-src',
  'prefetch-src',
  'script-src',
  'script-src-attr',
  'script-src-elem',
  'style-src',
  'style-src-attr',
  'style-src-elem',
  'worker-src',
]);

/** Directives that never inherit from `default-src`. */
export const NON_FALLBACK_DIRECTIVES = new Set([
  'base-uri',
  'block-all-mixed-content',
  'form-action',
  'frame-ancestors',
  'plugin-types',
  'report-to',
  'report-uri',
  'require-sri-for',
  'require-trusted-types-for',
  'sandbox',
  'trusted-types',
  'upgrade-insecure-requests',
]);

const DIRECTIVE_NAME = /^[a-z][a-z0-9-]*$/;

/**
 * Split a header value into policies. CSP has no comma inside a source
 * expression (nonces and hashes are base64url/base64, neither uses ','), so a
 * plain split is correct here and cheap.
 */
function splitPolicies(raw) {
  return String(raw).split(',');
}

/**
 * Parse one policy string into an ordered directive list.
 * First occurrence of a directive name wins; later ones are dropped, which is
 * what a browser does and what a naive token scan gets wrong.
 */
function parsePolicy(policyText) {
  const directives = new Map();
  const malformed = [];
  for (const segment of policyText.split(';')) {
    const trimmed = segment.trim();
    if (trimmed === '') continue;
    const parts = trimmed.split(/\s+/);
    const name = parts[0].toLowerCase();
    if (!DIRECTIVE_NAME.test(name)) {
      // A segment whose first token is not a directive name (for example a
      // stray source expression) cannot be interpreted; record it and move on.
      malformed.push(trimmed.slice(0, 60));
      continue;
    }
    if (directives.has(name)) continue; // first occurrence wins
    directives.set(name, parts.slice(1));
  }
  return { directives, malformed };
}

/**
 * Parse a full Content-Security-Policy header value.
 * @returns {{policies: Array<{directives: Map<string,string[]>, malformed: string[]}>, policyCount: number}}
 */
export function parseCspHeader(raw) {
  if (typeof raw !== 'string' || raw.trim() === '') {
    return { policies: [], policyCount: 0 };
  }
  const policies = splitPolicies(raw).map(parsePolicy);
  return { policies, policyCount: policies.length };
}

/**
 * The source list that actually governs `directive` in one policy.
 * Returns null when neither the directive nor a fallback is declared, which
 * means "no restriction stated" and is a distinct answer from "restricted to
 * nothing" (`'none'`).
 */
export function effectiveSources(policy, directive) {
  const name = directive.toLowerCase();
  if (policy.directives.has(name)) return policy.directives.get(name);
  if (FETCH_DIRECTIVES.has(name) && policy.directives.has('default-src')) {
    return policy.directives.get('default-src');
  }
  return null;
}

/** True when the policy declares the directive explicitly. */
export function declaresDirective(policy, directive) {
  return policy.directives.has(directive.toLowerCase());
}

/** True when the source list contains the bare wildcard token (not `*.host`). */
export function hasBareWildcard(sources) {
  return Array.isArray(sources) && sources.includes('*');
}

/**
 * A source expression that permits every origin of a scheme.
 *
 * `*` is the obvious spelling. `https://*`, `http://*`, `ws://*` and `wss://*`
 * are host-source expressions whose host is the wildcard, so they allow every
 * host reachable over that scheme — the same permission for that scheme, and
 * the form a rule that only looks for a standalone `*` misses. A scoped host
 * wildcard (`https://*.example.com`) is a *different* expression and is not
 * matched here; it is limited to one registrable domain's subdomains.
 */
export function hasSchemeWildcardHost(sources) {
  if (!Array.isArray(sources)) return false;
  return sources.some((source) => /^(?:https?|wss?):\/\/\*$/i.test(source));
}

/** Every-origin permission: the bare `*` or a scheme-scoped wildcard host. */
export function hasAllOriginsWildcard(sources) {
  return hasBareWildcard(sources) || hasSchemeWildcardHost(sources);
}

/**
 * True when the list carries a scheme source or a host source using that
 * scheme. `http:` and `http://host` are different spellings of the same
 * permission for the plaintext scheme.
 */
export function allowsScheme(sources, scheme) {
  if (!Array.isArray(sources)) return false;
  const want = scheme.toLowerCase();
  const prefix = `${want}:`;
  return sources.some((source) => {
    const value = source.toLowerCase();
    return value === prefix || value.startsWith(prefix);
  });
}

/**
 * True when a nonce or hash source is present in the list. CSP3 ignores
 * `'unsafe-inline'` inside a directive that also carries a nonce or hash, so
 * this is the predicate that decides whether an `unsafe-inline` finding is real.
 */
export function hasNonceOrHash(sources) {
  if (!Array.isArray(sources)) return false;
  // Only a complete, quoted nonce-source or hash-source neutralises
  // `'unsafe-inline'` (CSP3 6.7.3.3). A substring match is not good enough:
  // `https://nonce-cdn.example` contains "nonce-" but grants no nonce, and an
  // unquoted `nonce-abc` is not a source expression at all. Anchoring the whole
  // token is what keeps that host from hiding a real unsafe-inline finding.
  return sources.some((source) => /^'(?:nonce-[^'\s]+|sha(?:256|384|512)-[^'\s]+)'$/.test(source));
}

/** True when the list states `'unsafe-inline'` (quoted; unquoted is accepted leniently). */
export function hasUnsafeInline(sources) {
  if (!Array.isArray(sources)) return false;
  return sources.some((source) => source.toLowerCase().replace(/^'+|'+$/g, '') === 'unsafe-inline');
}

/** True when the list states `'unsafe-eval'`. */
export function hasUnsafeEval(sources) {
  if (!Array.isArray(sources)) return false;
  return sources.some((source) => source.toLowerCase().replace(/^'+|'+$/g, '') === 'unsafe-eval');
}

/** True when every policy in the set satisfies `predicate(policy)`. */
function everyPolicy(parsed, predicate) {
  if (parsed.policies.length === 0) return false;
  return parsed.policies.every((policy) => predicate(policy));
}

// --- Header-level predicates used by the differential oracle ----------------

/** `default-src` exists and allows every origin. */
export function headerHasDefaultSrcWildcard(parsed) {
  return everyPolicy(parsed, (policy) => hasAllOriginsWildcard(effectiveSources(policy, 'default-src')));
}

/** `script-src` exists and allows every origin. */
export function headerHasScriptSrcWildcard(parsed) {
  return everyPolicy(parsed, (policy) => {
    const sources = effectiveSources(policy, 'script-src');
    return declaresDirective(policy, 'script-src') && hasAllOriginsWildcard(sources);
  });
}

/** Any fetch directive declared with an every-origin source list. */
export function headerHasDirectiveWildcard(parsed, directive) {
  const name = directive.toLowerCase();
  return everyPolicy(parsed, (policy) => declaresDirective(policy, name)
    && hasAllOriginsWildcard(effectiveSources(policy, name)));
}

/** A declared directive that permits a plaintext `http:` source. */
export function headerDirectiveAllowsPlaintext(parsed, directive) {
  const name = directive.toLowerCase();
  return everyPolicy(parsed, (policy) => declaresDirective(policy, name)
    && allowsScheme(effectiveSources(policy, name), 'http'));
}

/**
 * The first `report-uri` declaration contains a plaintext endpoint. `report-to`
 * is deliberately not handled here: its value is a group name, not a URL, so
 * the cleartext question belongs to the Report-To header instead.
 */
export function headerReportUriAllowsPlaintext(parsed) {
  return everyPolicy(parsed, (policy) => {
    const tokens = policy.directives.get('report-uri');
    return Array.isArray(tokens) && tokens.some((token) => /^http:\/\//i.test(token));
  });
}

/**
 * `sandbox` with both allow-scripts and allow-same-origin. Either token alone is
 * defensible; together the framed document can reach its own sandbox attribute
 * and remove it, so the directive stops being a boundary.
 */
export function headerSandboxEscapable(parsed) {
  return everyPolicy(parsed, (policy) => {
    const tokens = policy.directives.get('sandbox');
    return Array.isArray(tokens)
      && tokens.includes('allow-scripts')
      && tokens.includes('allow-same-origin');
  });
}

/** `base-uri` is declared and matches every origin (it has no `default-src` fallback). */
export function headerHasBaseUriWildcard(parsed) {
  return everyPolicy(parsed, (policy) => declaresDirective(policy, 'base-uri')
    && hasAllOriginsWildcard(effectiveSources(policy, 'base-uri')));
}

/** `form-action` is declared and matches every origin (it has no `default-src` fallback). */
export function headerHasFormActionWildcard(parsed) {
  return everyPolicy(parsed, (policy) => declaresDirective(policy, 'form-action')
    && hasAllOriginsWildcard(effectiveSources(policy, 'form-action')));
}

/** `connect-src` exists and allows every origin. */
export function headerHasConnectSrcWildcard(parsed) {
  return everyPolicy(parsed, (policy) => {
    const sources = effectiveSources(policy, 'connect-src');
    return declaresDirective(policy, 'connect-src') && hasAllOriginsWildcard(sources);
  });
}

/** `frame-ancestors` exists and allows every origin. */
export function headerHasFrameAncestorsWildcard(parsed) {
  return everyPolicy(parsed, (policy) => {
    const sources = effectiveSources(policy, 'frame-ancestors');
    return declaresDirective(policy, 'frame-ancestors') && hasAllOriginsWildcard(sources);
  });
}

/** `script-src` exists and permits the plaintext http scheme. */
export function headerScriptAllowsPlaintext(parsed) {
  return everyPolicy(parsed, (policy) => {
    const sources = effectiveSources(policy, 'script-src');
    return declaresDirective(policy, 'script-src') && allowsScheme(sources, 'http');
  });
}

/** `script-src` exists and permits the data: scheme. */
export function headerScriptAllowsData(parsed) {
  return everyPolicy(parsed, (policy) => {
    const sources = effectiveSources(policy, 'script-src');
    return declaresDirective(policy, 'script-src') && allowsScheme(sources, 'data');
  });
}

/**
 * Object loading is unconstrained: no policy sets `object-src`, and none sets
 * `default-src` either. When `default-src` is present it *is* the object-src
 * fallback, so the directive is not missing.
 */
export function headerObjectSrcUnconstrained(parsed) {
  return everyPolicy(parsed, (policy) => !declaresDirective(policy, 'object-src')
    && !declaresDirective(policy, 'default-src'));
}

/**
 * Directives in which `'unsafe-inline'` actually grants something. The keyword
 * has no meaning in img-src, connect-src, media-src or any other fetch
 * directive: those requests are never inline. Only script and style execution
 * can be inline, and `default-src` supplies their fallback.
 */
export const INLINE_CAPABLE_DIRECTIVES = new Set([
  'default-src',
  'script-src',
  'script-src-attr',
  'script-src-elem',
  'style-src',
  'style-src-attr',
  'style-src-elem',
]);

/** A real `unsafe-inline` permission: stated in a directive that carries no nonce or hash. */
export function headerAllowsInlineScripting(parsed) {
  return everyPolicy(parsed, (policy) => [...policy.directives.entries()].some(([name, sources]) => (
    INLINE_CAPABLE_DIRECTIVES.has(name)
      && hasUnsafeInline(sources)
      && !hasNonceOrHash(sources)
  )));
}

/** `unsafe-eval` stated in an effective script source list. */
export function headerAllowsEval(parsed) {
  return everyPolicy(parsed, (policy) => hasUnsafeEval(effectiveSources(policy, 'script-src')));
}

/** The header is delivered in report-only mode (a policy exists on that header). */
export function headerIsReportOnly(reportOnlyValue) {
  if (typeof reportOnlyValue !== 'string') return false;
  return reportOnlyValue.trim() !== '';
}
