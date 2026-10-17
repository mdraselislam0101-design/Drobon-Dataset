/**
 * secret-candidates.mjs — evidence-gated secret CANDIDATE evaluation
 * (Phase 8, Work B). Pure, deterministic, throw-free, no I/O.
 *
 * What this is NOT:
 *   - NOT a confirmed-secret detector. The strongest state a candidate can
 *     reach is `CANDIDATE`. Nothing here asserts that a string IS a live
 *     credential, and nothing verifies or revokes credentials.
 *   - NOT production intelligence. All callers must pass synthetic test-only
 *     values (schema-enforced); these never enter corpus counts.
 *   - NOT auto-fix. This module never modifies source.
 *
 * What this is:
 *   - A small deterministic signal evaluator (Shannon entropy, length,
 *     charset classes, placeholder/hash/identifier vetoes) plus a context
 *     gate: without assignment-like contextual evidence a value stays
 *     UNASSESSED, never CANDIDATE.
 *   - Redaction-first reporting: output carries a short fingerprint
 *     (prefix + length), never the raw value.
 *
 * Entropy alone NEVER asserts a credential. High-entropy non-secrets (hash
 * digests, UUIDs, public identifiers) are explicit rejection classes.
 */
export const SECRET_CANDIDATE_SCHEMA = 'drobon.secret.candidate/v1';
export const CANDIDATE_STATES = Object.freeze(['CANDIDATE', 'REJECTED', 'UNASSESSED']);

/** Placeholder/vocabulary vetoes (case-insensitive, substring on the value). */
const PLACEHOLDER_VETO = Object.freeze([
  'example', 'changeme', 'change-me', 'placeholder', 'dummy', 'sample',
  'not-a-real', 'notareal', 'redacted', 'xxxxxxxx', 'todo', 'fixme',
  'your-', 'insert-', 'test-only', 'synthetic', 'lorem', 'password', 'secret',
]);
/** Values that are structurally identifiers, not credentials. */
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const HEX_DIGEST_RE = /^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$/;
const SEMVER_RE = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}(T[0-9:.]+Z?)?$/;
const TEMPLATE_REF_RE = /^[<{$%][^>}]*/; // <...>, ${...}, %{...}, %s...

function safeText(value, cap = 512) {
  if (typeof value !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f]/g, '?').slice(0, cap);
}

/** Shannon entropy in bits/character (deterministic, standard formula). */
export function shannonEntropy(text) {
  if (typeof text !== 'string' || text.length === 0) return 0;
  const freq = new Map();
  for (const ch of text) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const count of freq.values()) {
    const p = count / text.length;
    bits -= p * Math.log2(p);
  }
  return Number(bits.toFixed(4));
}

/** Redacted fingerprint: first 4 chars + length. The raw value never leaves. */
export function fingerprint(value) {
  const text = typeof value === 'string' ? value : '';
  return `${text.slice(0, 4)}…(len=${text.length})`;
}

/**
 * Validate a candidate record against the schema. Returns error strings.
 */
export function validateCandidate(value) {
  const errors = [];
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return ['candidate: must be an object'];
  }
  const allowed = [
    'schemaVersion', 'id', 'synthetic', 'testOnly', 'text', 'contextKind',
    'contextEvidence', 'provenance',
  ];
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) errors.push(`candidate: unknown property "${key}"`);
  }
  if (value.schemaVersion !== SECRET_CANDIDATE_SCHEMA) {
    errors.push(`candidate.schemaVersion: unsupported schema (want "${SECRET_CANDIDATE_SCHEMA}")`);
  }
  if (typeof value.id !== 'string' || !/^SYN-CAND-[0-9]{3}$/.test(value.id)) {
    errors.push('candidate.id: must match ^SYN-CAND-[0-9]{3}$');
  }
  if (value.synthetic !== true) errors.push('candidate.synthetic: must be true (test-only)');
  if (value.testOnly !== true) errors.push('candidate.testOnly: must be true (test-only)');
  if (typeof value.text !== 'string' || value.text.length === 0 || value.text.length > 256) {
    errors.push('candidate.text: required string of 1..256 chars');
  }
  if (!['assignment', 'url-userinfo', 'header', 'config', 'other'].includes(value.contextKind)) {
    errors.push('candidate.contextKind: must be assignment|url-userinfo|header|config|other');
  }
  if (value.contextKind !== 'other' && (typeof value.contextEvidence !== 'string' || value.contextEvidence.length < 8)) {
    errors.push('candidate.contextEvidence: required string (>=8 chars) for contextual kinds');
  }
  const prov = value.provenance;
  if (prov === null || typeof prov !== 'object' || prov.origin !== 'original-authored'
    || prov.expectationAuthoredBeforeFirstRun !== true) {
    errors.push("candidate.provenance: required object with origin='original-authored' and expectationAuthoredBeforeFirstRun=true");
  }
  return errors;
}

/**
 * Evaluate one candidate. Pure; never throws; never echoes the raw value.
 *
 * States:
 *   REJECTED  — structural non-secret (hash/UUID/semver/date/template ref),
 *               placeholder vocabulary, or too short for meaningful entropy.
 *   UNASSESSED— entropy/shape look interesting but contextual evidence is
 *               absent (`contextKind: 'other'`). Not scored as a detection.
 *   CANDIDATE — high-entropy value WITH assignment-like contextual evidence.
 *               This is a triage lead, NOT a confirmed secret finding.
 */
export function evaluateSecretCandidate(candidate) {
  const errors = validateCandidate(candidate);
  if (errors.length > 0) {
    return { state: 'UNASSESSED', reason: 'invalid-candidate', notes: errors.slice(0, 8), fingerprint: null };
  }
  const text = candidate.text;
  const lower = text.toLowerCase();
  const notes = [];
  const entropy = shannonEntropy(text);
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(text)).length;

  const fingerprintValue = fingerprint(text);
  const signals = { entropyBitsPerChar: entropy, length: text.length, charClasses: classes };

  // Structural rejections — high-entropy non-secrets.
  if (HEX_DIGEST_RE.test(text)) {
    return { state: 'REJECTED', reason: 'hex-digest-shape', signals, notes, fingerprint: fingerprintValue };
  }
  if (UUID_RE.test(text)) {
    return { state: 'REJECTED', reason: 'uuid-shape', signals, notes, fingerprint: fingerprintValue };
  }
  if (SEMVER_RE.test(text) || ISO_DATE_RE.test(text)) {
    return { state: 'REJECTED', reason: 'ordinary-identifier-shape', signals, notes, fingerprint: fingerprintValue };
  }
  if (TEMPLATE_REF_RE.test(text) || text.includes('%s') || text.includes('${')) {
    return { state: 'REJECTED', reason: 'template-or-placeholder-ref', signals, notes, fingerprint: fingerprintValue };
  }
  for (const veto of PLACEHOLDER_VETO) {
    if (lower.includes(veto)) {
      return { state: 'REJECTED', reason: `placeholder-veto:${veto}`, signals, notes, fingerprint: fingerprintValue };
    }
  }
  if (text.length < 12) {
    return { state: 'REJECTED', reason: 'too-short-for-entropy-signal', signals, notes, fingerprint: fingerprintValue };
  }
  if (entropy < 3.2) {
    return { state: 'REJECTED', reason: 'low-entropy', signals, notes, fingerprint: fingerprintValue };
  }

  // Context gate: without assignment-like evidence there is no escalation.
  const contextOk = candidate.contextKind !== 'other'
    && typeof candidate.contextEvidence === 'string'
    && candidate.contextEvidence.length >= 8;
  if (!contextOk) {
    notes.push('entropy/shape alone is NOT a credential claim; context evidence missing');
    return { state: 'UNASSESSED', reason: 'no-contextual-evidence', signals, notes, fingerprint: fingerprintValue };
  }
  const confidence = entropy >= 3.8 && classes >= 3 ? 'MEDIUM' : 'LOW';
  notes.push('CANDIDATE is a triage lead only; never a confirmed secret');
  return {
    state: 'CANDIDATE',
    reason: 'entropy-with-contextual-evidence',
    confidence,
    signals,
    notes,
    fingerprint: fingerprintValue,
  };
}
