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

// ---------------------------------------------------------------------------
// Candidate -> evidence-gated FINDING promotion contract (Phase 9).
//
// State mapping to `drobon.finding.evidence/v1` verification.state (documented
// in docs/FINDING_EVIDENCE_CONTRACT.md — one vocabulary, no duplicate system):
//   CANDIDATE (here)  -> 'UNVERIFIED' (triage lead)
//   UNRESOLVED        -> 'UNRESOLVED'
//   VERIFIED (below)  -> 'CONFIRMED'
//   REJECTED          -> 'REJECTED'
//
// A candidate NEVER becomes VERIFIED because of entropy, charset, length, a
// regex hit, a synthetic test label, or an agent/model assertion. The only
// implemented path to VERIFIED requires `verification.method =
// 'independent-rule-evidence'`: a DIFFERENT detector family (pattern rule)
// than the entropy/shape heuristic, with exact source-span evidence
// (matchedText must appear in the evidence excerpt). Re-running the
// candidate heuristic is explicitly NOT independent verification.
//
// Liveness/revocation/rotation verification is NOT IMPLEMENTED in Dataset
// scope — the contract boundary is implemented and tested; actual live
// credential verification remains an external engine capability.
// ---------------------------------------------------------------------------
export const PROMOTION_METHODS = Object.freeze([
  'independent-rule-evidence', 're-run-heuristic', 'entropy', 'model-assertion',
  'test-label', 'liveness',
]);

/**
 * Promote a candidate evaluation using separately supplied verification
 * evidence. Pure; never throws; never echoes raw values.
 *
 * Returns { findingState, reason, verification, notes, fingerprint }.
 * findingState is one of VERIFIED | UNRESOLVED | REJECTED.
 */
export function promoteCandidate(candidate, evaluation, verification) {
  const fingerprintValue = typeof candidate?.text === 'string' ? fingerprint(candidate.text) : null;
  const notes = [];
  if (evaluation === null || typeof evaluation !== 'object' || !CANDIDATE_STATES.includes(evaluation.state)) {
    return { findingState: 'UNRESOLVED', reason: 'invalid-evaluation', verification: null, notes, fingerprint: fingerprintValue };
  }
  if (evaluation.state === 'REJECTED') {
    return { findingState: 'REJECTED', reason: evaluation.reason ?? 'rejected-by-evaluation', verification: null, notes, fingerprint: fingerprintValue };
  }
  if (evaluation.state === 'UNASSESSED') {
    notes.push('candidate was never assessed (context/provenance missing) — verification cannot bootstrap an assessment');
    return { findingState: 'UNRESOLVED', reason: 'evaluation-unassessed', verification: null, notes, fingerprint: fingerprintValue };
  }
  if (verification === null || typeof verification !== 'object' || Array.isArray(verification)) {
    return { findingState: 'UNRESOLVED', reason: 'verification-absent', verification: null, notes, fingerprint: fingerprintValue };
  }
  const method = verification.method;
  if (method === 'liveness') {
    notes.push('liveness/revocation verification is NOT IMPLEMENTED in Dataset scope');
    return { findingState: 'UNRESOLVED', reason: 'verification-not-implemented', verification: { method }, notes, fingerprint: fingerprintValue };
  }
  if (['re-run-heuristic', 'entropy', 'model-assertion', 'test-label'].includes(method)) {
    notes.push(`${method} is not independent verification of a secret finding`);
    return { findingState: 'UNRESOLVED', reason: 'not-independent-verification', verification: { method }, notes, fingerprint: fingerprintValue };
  }
  if (method !== 'independent-rule-evidence') {
    return { findingState: 'UNRESOLVED', reason: 'unknown-verification-method', verification: { method: safeText(method, 64) }, notes, fingerprint: fingerprintValue };
  }
  // Independent rule-evidence path: require rule identity + exact span.
  const ruleId = verification.ruleId;
  const pathOk = typeof verification.evidencePath === 'string' && verification.evidencePath.length > 0;
  const lineOk = Number.isInteger(verification.evidenceLineNo) && verification.evidenceLineNo > 0;
  const excerpt = typeof verification.evidenceExcerpt === 'string' ? verification.evidenceExcerpt : null;
  const matchedText = typeof verification.matchedText === 'string' ? verification.matchedText : null;
  const spanOk = excerpt !== null && matchedText !== null && excerpt.includes(matchedText);
  if (typeof ruleId !== 'string' || !/^DPK-[A-Z]+-[0-9]+$/.test(ruleId) || !pathOk || !lineOk || !spanOk) {
    notes.push('independent verification requires ruleId + evidencePath + evidenceLineNo + matchedText inside evidenceExcerpt');
    return {
      findingState: 'UNRESOLVED',
      reason: 'independent-evidence-incomplete',
      verification: { method, ruleId: safeText(ruleId, 32) ?? null },
      notes,
      fingerprint: fingerprintValue,
    };
  }
  if (typeof candidate?.text === 'string' && excerpt.includes(candidate.text)) {
    notes.push('evidence excerpt must stay redacted; raw candidate value found in excerpt');
    return { findingState: 'UNRESOLVED', reason: 'evidence-not-redacted', verification: { method, ruleId }, notes, fingerprint: fingerprintValue };
  }
  notes.push('VERIFIED = contract-gated synthetic evidence check (independent rule + exact span); live-credential verification NOT IMPLEMENTED');
  return {
    findingState: 'VERIFIED',
    reason: 'independent-rule-evidence-exact-span',
    verification: {
      method,
      ruleId,
      ruleVersion: Number.isInteger(verification.ruleVersion) && verification.ruleVersion > 0 ? verification.ruleVersion : null,
      evidencePath: safeText(verification.evidencePath, 256),
      evidenceLineNo: verification.evidenceLineNo,
    },
    notes,
    fingerprint: fingerprintValue,
  };
}
