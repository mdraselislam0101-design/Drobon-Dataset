/**
 * app-evaluator-profile.mjs — faithful JavaScript mirror of the Main App's
 * DAST pack evaluator, used only to MEASURE parity against this repository's
 * executable semantics.
 *
 * Source of truth (read-only, verified 2026-10-21):
 *   mdraselislam0101-design/Drobon @ 9360dd1abdf940cc1bffd942aab0702703aaaaef
 *   apps/api/src/external/evaluator.ts   (`evaluatePackDastCheck`)
 *   apps/api/src/external/packProvider.ts (`convertSastPackToRule`,
 *     `convertSecretsPackToRule`, `convertDastPackToRule`)
 *
 * Why a mirror: this repository must be able to state, and machine-check, exactly
 * where the App's implementation and the declared pack tests disagree — without
 * importing App code (the App is a separate repository and the dataset lock
 * forbids coupling). The mirror is deliberately dumb: it is a transcription, not
 * a re-design. When the App changes, bump `APP_PROFILE.commit` here and re-run
 * `node scripts/gen-app-conformance.mjs --write`; the gate fails until then.
 *
 * This module is NOT used by any dataset validator to judge our own rules. Our
 * own semantics live in scripts/validate-packs.mjs + scripts/lib/*, and the pack
 * files' declared tests are the ground truth this profile is measured against.
 */

export const APP_PROFILE = Object.freeze({
  repo: 'mdraselislam0101-design/Drobon',
  commit: '9360dd1abdf940cc1bffd942aab0702703aaaaef',
  verifiedAt: '2026-10-21',
  sources: Object.freeze([
    'apps/api/src/external/evaluator.ts',
    'apps/api/src/external/packProvider.ts',
  ]),
});

/** App `header()` helper: lowercased lookup, arrays joined with ", ", value trimmed. */
function header(obs, name) {
  const v = obs.headers[name.toLowerCase()];
  const sel = Array.isArray(v) ? v.join(', ') : v;
  return typeof sel === 'string' ? sel.trim() : undefined;
}

/** App `evaluatePackDastCheck()` — transcribed branch for branch. */
export function appEvaluateDast(check, obs) {
  const t = check.type;
  if (t === 'http-url') {
    try {
      return new URL(obs.url).protocol === 'http:';
    } catch {
      return false;
    }
  }
  if (t === 'missing-response-header') {
    const h = check.header;
    if (typeof h !== 'string') return false;
    const v = header(obs, h);
    return v === undefined || v.trim() === '';
  }
  if (t === 'response-header-missing-directive') {
    const h = check.header;
    const d = check.directive;
    if (typeof h !== 'string' || typeof d !== 'string') return false;
    const v = header(obs, h);
    if (v === undefined) return true;
    const parts = v.split(/[;,]/).map((s) => s.trim());
    return !parts.some((p) => p.split(/[=\s]/)[0]?.toLowerCase() === d.toLowerCase());
  }
  if (t === 'cookie-missing-flag') {
    const flag = check.flag;
    const raw = obs.headers['set-cookie'];
    const cookies = typeof raw === 'string' ? [raw] : Array.isArray(raw) ? raw : [];
    if (cookies.length === 0) return false;
    for (const c of cookies.slice(0, 5)) {
      const parts = c.split(';').slice(1).map((p) => p.trim().toLowerCase());
      const has = flag === 'Secure'
        ? parts.some((p) => p === 'secure')
        : flag === 'HttpOnly'
          ? parts.some((p) => p === 'httponly')
          : parts.some((p) => p.startsWith('samesite='));
      if (!has) return true;
    }
    return false;
  }
  if (t === 'response-header-matches') {
    const h = check.header;
    const pat = check.valuePattern;
    if (typeof h !== 'string' || typeof pat !== 'string') return false;
    const v = header(obs, h);
    if (v === undefined) return false;
    try {
      return new RegExp(pat, 'i').test(v);
    } catch {
      return false;
    }
  }
  if (t === 'response-body-matches') {
    const pat = check.valuePattern;
    if (typeof pat !== 'string' || !obs.body) return false;
    if (check.requireScheme) {
      try {
        if (new URL(obs.url).protocol.slice(0, -1) !== check.requireScheme) return false;
      } catch {
        return false;
      }
    }
    try {
      return new RegExp(pat, 'i').test(obs.body);
    } catch {
      return false;
    }
  }
  if (t === 'response-header-host-differs') {
    const h = check.header;
    if (typeof h !== 'string') return false;
    if (obs.status < 300 || obs.status > 399) return false;
    const v = header(obs, h);
    if (!v) return false;
    try {
      const base = new URL(obs.url);
      const target = new URL(v, base);
      if (target.protocol !== 'http:' && target.protocol !== 'https:') return false;
      return target.hostname.toLowerCase() !== base.hostname.toLowerCase();
    } catch {
      return false;
    }
  }
  return false;
}

/** App `compilePattern()`: only no-flags or the `i` flag survive; g/y rejected. */
export function appCompilePattern(source, flags) {
  try {
    const f = flags === 'i' ? 'i' : flags === undefined ? '' : '';
    if (f !== '' && f !== 'i') return undefined;
    return new RegExp(source, f);
  } catch {
    return undefined;
  }
}

/** App `convertSastPackToRule()` acceptance + matcher, reduced to what a test needs. */
export function appSastMatches(raw, line) {
  if (raw?.schemaVersion !== 'drobon.pack.sast/v1') return { accepted: false, fires: false };
  if (typeof raw.id !== 'string' || !/^DPK-SAST-\d+$/.test(raw.id)) return { accepted: false, fires: false };
  if (typeof raw.title !== 'string' || typeof raw.severity !== 'string') return { accepted: false, fires: false };
  if (!Array.isArray(raw.patterns)) return { accepted: false, fires: false };
  const compiled = [];
  for (const p of raw.patterns) {
    if (typeof p.source !== 'string') return { accepted: false, fires: false };
    const re = appCompilePattern(p.source, p.flags);
    if (!re) return { accepted: false, fires: false };
    if (re.global || re.sticky) return { accepted: false, fires: false };
    compiled.push(re);
  }
  if (compiled.length === 0) return { accepted: false, fires: false };
  return { accepted: true, fires: compiled.some((re) => re.test(line)) };
}

/** App `convertSecretsPackToRule()` acceptance + denylist veto, reduced to a line test. */
export function appSecretsMatches(raw, line) {
  if (raw?.schemaVersion !== 'drobon.pack.secrets/v1') return { accepted: false, fires: false };
  if (typeof raw.id !== 'string' || !/^DPK-SEC-\d+$/.test(raw.id)) return { accepted: false, fires: false };
  if (!Array.isArray(raw.patterns)) return { accepted: false, fires: false };
  const compiled = [];
  for (const p of raw.patterns) {
    if (typeof p.source !== 'string') return { accepted: false, fires: false };
    const re = appCompilePattern(p.source, p.flags);
    if (!re) return { accepted: false, fires: false };
    if (re.global || re.sticky) return { accepted: false, fires: false };
    compiled.push(re);
  }
  if (compiled.length === 0) return { accepted: false, fires: false };
  const matchOnlyEvidence = raw.matchOnlyEvidence === true;
  const denylist = Array.isArray(raw.denylist) ? raw.denylist.filter((x) => typeof x === 'string') : [];
  const hit = compiled.some((re) => re.test(line));
  if (!hit) return { accepted: true, fires: false };
  if (matchOnlyEvidence || denylist.length === 0) return { accepted: true, fires: true };
  const vetoed = denylist.some((d) => line.toLowerCase().includes(d.toLowerCase()));
  return { accepted: true, fires: !vetoed };
}

/** App `convertDastPackToRule()` acceptance (schema + id + check.type). */
export function appAcceptsDast(raw) {
  if (raw?.schemaVersion !== 'drobon.pack.dast/v1') return false;
  if (typeof raw.id !== 'string' || !/^DPK-DAST-\d+$/.test(raw.id)) return false;
  if (!raw.check || typeof raw.check.type !== 'string') return false;
  return true;
}
