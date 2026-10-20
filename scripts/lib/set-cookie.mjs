/**
 * DROBON Set-Cookie semantic model (original, DROBON-authored).
 *
 * Why this exists
 * ---------------
 * A Set-Cookie header is not a keyword soup: the first ';'-separated segment is
 * the cookie pair, every later segment is an attribute, and each attribute has
 * its own value semantics. DAST cookie checks that search the raw header for a
 * keyword therefore mis-read two shapes that occur in real traffic:
 *
 *   1. `Secure=0` / `HttpOnly=1` — the flag attributes are defined to ignore
 *      their value. A browser treats both as "flag enabled", so reporting the
 *      cookie as unprotected is a false positive.
 *   2. `Set-Cookie: no-equals-sign` — a header the user agent discards entirely.
 *      No cookie is stored, so there is nothing that can lack a flag.
 *
 * Scope and provenance
 * --------------------
 * The behaviour encoded here is derived from the public HTTP state-management
 * specification (RFC 6265 sections 5.2 and 5.3) and from the observable
 * behaviour those sections require of user agents. No third-party parser,
 * rule set, test corpus or source code was copied or consulted; the parsing
 * strategy, the predicate names, the failure model and the tests written
 * against it are DROBON's own. The specification text itself is not
 * redistributed here.
 *
 * Deliberate limits (pinned by scripts/test-cookie-semantics.mjs)
 * --------------------------------------------------------------
 * - One string is one cookie. Folding several cookies into one header value is
 *   not un-folded: RFC 6265 forbids it, but a lenient intermediary may still do
 *   it, and a single-string API cannot tell the two apart. This is stated as a
 *   limitation on every cookie rule instead of guessed at.
 * - Cookie-prefix enforcement (`__Secure-`, `__Host-`) is browser behaviour, not
 *   header syntax. It is NOT applied here and no rule claims it.
 * - The parser does not rank `SameSite` value validity as a finding: an
 *   unrecognised value falls back to the user agent default. It records the
 *   value so a caller can reason about it, and reports `effective` only as
 *   "declared" / "unrecognised" / "absent".
 * - Expiry (`Max-Age` / `Expires`) is parsed for attribute identity only; the
 *   model never decides whether a cookie is still live, because the observation
 *   has no clock.
 */

/** Attribute names defined by RFC 6265 plus the modern SameSite attribute. */
const KNOWN_ATTRIBUTES = new Set([
  'expires',
  'max-age',
  'domain',
  'path',
  'secure',
  'httponly',
  'samesite',
]);

/** Flag attributes: the specification says their value is ignored. */
const FLAG_ATTRIBUTES = new Set(['secure', 'httponly']);

/** Control characters that make a user agent discard the whole header. */
const CTL = /[\u0000-\u0008\u000A-\u001F\u007F]/;

const SAMESITE_VALUES = new Set(['strict', 'lax', 'none']);

/**
 * Split an attribute list on ';' while respecting double-quoted spans.
 *
 * RFC 6265 cookie-value is not allowed to contain ';', so a quoted span with a
 * ';' inside it is already non-conforming input. Treating the quote as opaque
 * is still the least surprising reading of such a header, and it keeps the
 * parser from inventing a `Secure` attribute out of cookie data.
 */
function splitAttributes(text) {
  const parts = [];
  let current = '';
  let quoted = false;
  for (const character of text) {
    if (character === '"') quoted = !quoted;
    if (character === ';' && !quoted) {
      parts.push(current);
      current = '';
      continue;
    }
    current += character;
  }
  parts.push(current);
  return parts;
}

/**
 * Parse one Set-Cookie header value.
 *
 * Returns `{ ok: false, reason }` when a user agent would discard the header,
 * otherwise `{ ok: true, name, value, attributes, flags, sameSite }`.
 * Attributes are returned in header order with lower-cased names; the caller
 * can read `flags` / `sameSite` for the resolved semantics.
 */
export function parseSetCookie(raw) {
  if (typeof raw !== 'string') {
    return { ok: false, reason: 'not-a-string' };
  }
  if (raw.length === 0) {
    return { ok: false, reason: 'empty' };
  }
  if (CTL.test(raw)) {
    return { ok: false, reason: 'control-character' };
  }

  const segments = splitAttributes(raw);
  const pair = segments[0].trim();
  const equals = pair.indexOf('=');
  // RFC 6265 5.2 step 2: without '=' the whole header is ignored.
  if (equals <= 0) {
    return { ok: false, reason: 'no-name-value-pair' };
  }

  const name = pair.slice(0, equals).trim();
  const value = pair.slice(equals + 1).trim();
  if (name.length === 0) {
    return { ok: false, reason: 'empty-name' };
  }

  const attributes = [];
  for (const segment of segments.slice(1)) {
    const text = segment.trim();
    if (text.length === 0) continue; // trailing ';' or empty segment
    const index = text.indexOf('=');
    const attributeName = (index === -1 ? text : text.slice(0, index)).trim().toLowerCase();
    if (attributeName.length === 0) continue;
    const attributeValue = index === -1 ? '' : text.slice(index + 1).trim();
    attributes.push({
      name: attributeName,
      value: attributeValue,
      known: KNOWN_ATTRIBUTES.has(attributeName),
      flag: FLAG_ATTRIBUTES.has(attributeName),
    });
  }

  // RFC 6265 5.3: when an attribute appears more than once, the last one is
  // the one the user agent uses. Resolve to that same view so the reported
  // evidence matches what the browser would store.
  const last = (attributeName) => {
    for (let index = attributes.length - 1; index >= 0; index -= 1) {
      if (attributes[index].name === attributeName) return attributes[index];
    }
    return null;
  };

  const secure = last('secure');
  const httpOnly = last('httponly');
  const sameSiteAttribute = last('samesite');

  let sameSiteState = 'absent';
  let sameSiteValue = null;
  let sameSiteEffective = null;
  if (sameSiteAttribute !== null) {
    sameSiteValue = sameSiteAttribute.value;
    const normalized = sameSiteValue.toLowerCase();
    if (normalized.length === 0) {
      sameSiteState = 'unrecognised';
      sameSiteEffective = 'default';
    } else if (SAMESITE_VALUES.has(normalized)) {
      sameSiteState = 'declared';
      sameSiteEffective = normalized;
    } else {
      sameSiteState = 'unrecognised';
      sameSiteEffective = 'default';
    }
  }

  return {
    ok: true,
    name,
    value,
    attributes,
    flags: {
      secure: secure !== null,
      httpOnly: httpOnly !== null,
    },
    sameSite: {
      state: sameSiteState,
      value: sameSiteValue,
      effective: sameSiteEffective,
    },
    // Evidence-only view: the exact attribute tokens that established a flag.
    evidence: {
      secure: secure === null ? null : (secure.value === '' ? secure.name : `${secure.name}=${secure.value}`),
      httpOnly: httpOnly === null ? null : (httpOnly.value === '' ? httpOnly.name : `${httpOnly.name}=${httpOnly.value}`),
      sameSite: sameSiteAttribute === null ? null : (sameSiteAttribute.value === ''
        ? sameSiteAttribute.name
        : `${sameSiteAttribute.name}=${sameSiteAttribute.value}`),
    },
  };
}

/**
 * Does this header value establish the named cookie flag?
 *
 * `flag` is `Secure`, `HttpOnly` or `SameSite` (case-insensitive). A discarded
 * header establishes nothing, so every flag is reported absent — callers that
 * need to distinguish "discarded" from "stored without the flag" must call
 * `parseSetCookie` themselves, and the DAST rules intentionally do not: a
 * discarded header sets no cookie and therefore supports no finding.
 */
export function cookieHasFlag(raw, flag) {
  const parsed = parseSetCookie(raw);
  if (!parsed.ok) return false;
  const name = String(flag).toLowerCase();
  if (name === 'secure') return parsed.flags.secure;
  if (name === 'httponly') return parsed.flags.httpOnly;
  // A SameSite attribute with an empty or unrecognised value is ignored by user
  // agents, which then apply their own default. That default is browser policy,
  // not evidence carried by this response, so only a recognised Strict/Lax/None
  // value counts as the attribute being present.
  if (name === 'samesite') return parsed.sameSite.state === 'declared';
  return false;
}

/**
 * Why a user agent would refuse to store this cookie, or null when it stores it.
 *
 * Two distinct reasons exist and they are not interchangeable:
 *  - a syntactically discarded header (RFC 6265 5.2) stores nothing;
 *  - a `SameSite=None` cookie without `Secure` is refused by every shipping
 *    browser (the SameSite=None value is only accepted on a secure cookie), so
 *    the response declares a cookie that will never be sent.
 *
 * The second case is owned by DPK-DAST-071. Keeping it out of the flag rules
 * avoids reporting "missing HttpOnly" on a cookie that does not exist, and
 * avoids two findings for one underlying defect.
 */
export function cookieStorageRejection(raw) {
  const parsed = parseSetCookie(raw);
  if (!parsed.ok) return `discarded:${parsed.reason}`;
  if (parsed.sameSite.state === 'declared'
    && parsed.sameSite.effective === 'none'
    && parsed.flags.secure === false) {
    return 'samesite-none-without-secure';
  }
  return null;
}

/** True when the response actually establishes this cookie. */
export function cookieWillBeStored(raw) {
  return cookieStorageRejection(raw) === null;
}

/** True when a user agent would discard this header value. */
export function cookieIsDiscarded(raw) {
  return !parseSetCookie(raw).ok;
}

/** Human-readable reason a header value is discarded, or null. */
export function cookieDiscardReason(raw) {
  const parsed = parseSetCookie(raw);
  return parsed.ok ? null : parsed.reason;
}

export { KNOWN_ATTRIBUTES, FLAG_ATTRIBUTES, SAMESITE_VALUES };
