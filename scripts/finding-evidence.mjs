/**
 * finding-evidence.mjs — finding evidence contract + scan-to-scan tracking
 * (Phase 6, Work C small milestone + Work D).
 *
 * Part 1 — evidence extraction (the one small semantic-analysis improvement
 * implemented this phase): given actual source text and an exact matched span,
 * compute (never invent) the finding's file/line-range/excerpt/context record.
 * Line numbers are derived from the text; a span that cannot be located yields
 * an explicit error result, never a guessed position. This is source mapping,
 * not AST/CFG/taint analysis (see docs/SEMANTIC_ANALYSIS_ASSESSMENT.md).
 *
 * Part 2 — remediation-tracking transitions across scans:
 *   FIXED_VERIFIED | PARTIALLY_FIXED | STILL_PRESENT |
 *   CHANGED_REQUIRES_REVIEW | NOT_OBSERVED_UNVERIFIED
 * Finding disappearance alone is NEVER proof of remediation: absence without
 * covering re-scan + explicit fix evidence is NOT_OBSERVED_UNVERIFIED.
 * Identity is stable across line shifts (rule + path + normalized span hash).
 *
 * Pure, deterministic, throw-free, no I/O, no network. Severity/CWE are only
 * carried from a declared rule; CVSS is never invented (absent by design under
 * the production lock). Synthetic-test safe: no real targets or credentials.
 */
import { createHash } from 'node:crypto';

export const FINDING_EVIDENCE_SCHEMA = 'drobon.finding.evidence/v1';
export const TRANSITION_STATUSES = Object.freeze([
  'FIXED_VERIFIED',
  'PARTIALLY_FIXED',
  'STILL_PRESENT',
  'CHANGED_REQUIRES_REVIEW',
  'NOT_OBSERVED_UNVERIFIED',
]);

const MAX_EXCERPT = 4096;
const MAX_ID = 512;

function safeText(value, cap) {
  if (typeof value !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f]/g, '?').slice(0, cap);
}

function langFromPath(path) {
  const ext = typeof path === 'string' && path.includes('.') ? path.slice(path.lastIndexOf('.') + 1) : '';
  const map = {
    py: 'python', js: 'javascript', ts: 'typescript', java: 'java', go: 'go',
    rb: 'ruby', php: 'php', cs: 'csharp', sh: 'shell', ps1: 'powershell',
    sql: 'sql', yaml: 'yaml', yml: 'yaml', json: 'json', env: 'env', tf: 'hcl',
  };
  return map[ext] ?? null;
}

/**
 * Stable finding identity: rule + path + hash of the normalized matched span.
 * Line numbers deliberately do NOT participate — identity survives line shifts
 * when the evidence content is unchanged.
 */
export function identityOf(ruleId, path, matchedText) {
  const normalized = String(matchedText).replace(/\s+/g, ' ').trim();
  const digest = createHash('sha256').update(`${ruleId}\u0000${path}\u0000${normalized}`, 'utf8').digest('hex');
  return `FIND-${digest.slice(0, 16)}`;
}

/**
 * Extract exact finding evidence from real source text.
 * @param {string} sourceText  the actual scanned file content (single string)
 * @param {{ruleId: string, path: string, matchedText: string, occurrence?: number,
 *          snapshotId: string, commitId?: string, method: string,
 *          cwe?: string, severity?: string, framework?: string|null}} spec
 * @returns {{ok: true, evidence: object} | {ok: false, reason: string}}
 */
export function extractEvidence(sourceText, spec) {
  if (typeof sourceText !== 'string' || spec === null || typeof spec !== 'object') {
    return { ok: false, reason: 'malformed-input' };
  }
  const ruleId = safeText(spec.ruleId, MAX_ID);
  const path = safeText(spec.path, MAX_ID);
  const matchedText = safeText(spec.matchedText, 256);
  const snapshotId = safeText(spec.snapshotId, MAX_ID);
  const method = safeText(spec.method, 128);
  if (ruleId === null || path === null || matchedText === null || matchedText.length === 0
    || snapshotId === null || method === null) {
    return { ok: false, reason: 'incomplete-spec' };
  }
  const occurrence = Number.isInteger(spec.occurrence) && spec.occurrence >= 0 ? spec.occurrence : 0;
  // Locate every occurrence of the exact span; pick the declared occurrence.
  const hits = [];
  let from = 0;
  for (;;) {
    const at = sourceText.indexOf(matchedText, from);
    if (at < 0) break;
    hits.push(at);
    from = at + Math.max(1, matchedText.length);
  }
  if (hits.length === 0) {
    return { ok: false, reason: 'span-not-found-in-source' };
  }
  if (occurrence >= hits.length) {
    return { ok: false, reason: 'occurrence-out-of-range' };
  }
  const startOffset = hits[occurrence];
  const endOffset = startOffset + matchedText.length;
  // Compute line numbers from the actual text — never invented.
  const before = sourceText.slice(0, startOffset);
  const lineNo = before.split('\n').length;
  const lines = sourceText.split('\n');
  const matchedLine = lines[lineNo - 1];
  const endLineNo = sourceText.slice(0, endOffset).split('\n').length;
  const contextFrom = Math.max(1, lineNo - 2);
  const contextTo = Math.min(lines.length, endLineNo + 2);
  const evidence = {
    schemaVersion: FINDING_EVIDENCE_SCHEMA,
    findingId: identityOf(ruleId, path, matchedText),
    snapshot: {
      snapshotId,
      ...(typeof spec.commitId === 'string' && /^[0-9a-f]{7,40}$/.test(spec.commitId) ? { commitId: spec.commitId } : {}),
    },
    location: {
      path,
      lineFrom: lineNo,
      lineTo: endLineNo,
      startOffset,
      endOffset,
    },
    source: {
      excerpt: matchedLine.slice(0, MAX_EXCERPT),
      matchedText,
      context: lines.slice(contextFrom - 1, contextTo).map((l) => l.slice(0, MAX_EXCERPT)),
      contextFrom,
      contextTo,
    },
    analysis: {
      language: langFromPath(path),
      framework: safeText(spec.framework, 128) ?? null,
      method,
      ...(Number.isInteger(spec.ruleVersion) && spec.ruleVersion > 0 ? { ruleVersion: spec.ruleVersion } : {}),
    },
    // Evaluation/verification status: never upgraded without evidence.
    verification: {
      state: ['CONFIRMED', 'REJECTED', 'UNRESOLVED', 'UNASSESSED', 'UNVERIFIED'].includes(spec.verificationState)
        ? spec.verificationState
        : 'UNVERIFIED',
    },
    dataFlowEvidence: { state: 'NOT_ASSESSED', note: 'no taint/data-flow analysis exists in this workstream' },
    callChainEvidence: { state: 'NOT_ASSESSED', note: 'no call-graph analysis exists in this workstream' },
    confidence: {
      level: 'SHAPE_MATCH',
      uncertainty: 'Lexical/observation shape match only; exploitability is not established by this record.',
    },
    // Severity/CWE are carried ONLY when a declared rule supplies them.
    ...(typeof spec.cwe === 'string' && /^CWE-[1-9][0-9]{0,5}$/.test(spec.cwe) ? { cwe: spec.cwe } : {}),
    ...(typeof spec.severity === 'string' && ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(spec.severity) ? { severity: spec.severity } : {}),
    // CVSS is absent by design: never invented under the production lock.
    whyItMatters: safeText(spec.whyItMatters ?? 'Shape matches a declared rule; review the cited source excerpt.', MAX_EXCERPT),
    remediation: null, // filled from knowledge/remediation — always a separate field, never mixed into source
  };
  return { ok: true, evidence };
}

/**
 * Classify a single finding's scan-to-scan transition.
 *
 * @param {{findingId: string, ruleId: string, path: string, evidenceSpans: Array<{excerpt: string}>}} prev
 *        prior finding (spans = the exact source lines it cited)
 * @param {{files: Object<string, string[]>, snapshotId: string}} currScan
 *        current scan snapshot (file -> lines); files NOT listed were not
 *        covered by this scan.
 * @param {{fixEvidence?: {note: string, snapshotId: string}, currentMatch?: {excerpt: string}}} [opts]
 * @returns {{status: string, perSpan: Array<{spanIndex: number, status: string, reason: string}>}}
 */
export function classifyTransition(prev, currScan, opts = {}) {
  const fail = (status, reason) => ({ status, perSpan: [{ spanIndex: -1, status, reason }] });
  if (prev === null || typeof prev !== 'object' || !Array.isArray(prev.evidenceSpans) || prev.evidenceSpans.length === 0) {
    return fail('NOT_OBSERVED_UNVERIFIED', 'malformed-prev-finding');
  }
  if (currScan === null || typeof currScan !== 'object' || typeof currScan.files !== 'object' || currScan.files === null) {
    return fail('NOT_OBSERVED_UNVERIFIED', 'malformed-current-scan');
  }
  const path = safeText(prev.path, MAX_ID);
  const lines = path !== null && Object.hasOwn(currScan.files, path) && Array.isArray(currScan.files[path])
    ? currScan.files[path]
    : null;
  const fixEvidence = Object.hasOwn(opts, 'fixEvidence') && opts.fixEvidence !== null && typeof opts.fixEvidence === 'object'
    ? opts.fixEvidence
    : null;
  const fixOk = fixEvidence !== null
    && typeof fixEvidence.note === 'string' && fixEvidence.note.length >= 8
    && typeof fixEvidence.snapshotId === 'string' && fixEvidence.snapshotId.length > 0;

  const perSpan = prev.evidenceSpans.map((span, spanIndex) => {
    const excerpt = span !== null && typeof span === 'object' && Object.hasOwn(span, 'excerpt') ? safeText(span.excerpt, MAX_EXCERPT) : null;
    if (excerpt === null) {
      return { spanIndex, status: 'NOT_OBSERVED_UNVERIFIED', reason: 'malformed-span' };
    }
    if (lines === null) {
      return { spanIndex, status: 'NOT_OBSERVED_UNVERIFIED', reason: 'file-not-covered-by-current-scan' };
    }
    const present = lines.some((l) => typeof l === 'string' && l.includes(excerpt.trim()));
    if (present) {
      // Content unchanged (possibly at a new line number) => still present.
      // A different current match for the same rule/path is a change signal.
      const currentMatch = Object.hasOwn(opts, 'currentMatch') && opts.currentMatch !== null && typeof opts.currentMatch === 'object'
        ? safeText(opts.currentMatch.excerpt, MAX_EXCERPT)
        : null;
      if (currentMatch !== null && currentMatch !== excerpt) {
        return { spanIndex, status: 'CHANGED_REQUIRES_REVIEW', reason: 'same-site-span-changed' };
      }
      return { spanIndex, status: 'STILL_PRESENT', reason: 'span-observed-identical' };
    }
    if (lines.some((l) => typeof l === 'string' && l.trim().length > 0) && lines.length > 0) {
      // Absence — proof only with explicit fix evidence.
      if (fixOk) {
        return { spanIndex, status: 'FIXED_VERIFIED', reason: 'absent-in-covering-rescan-with-fix-evidence' };
      }
      return { spanIndex, status: 'NOT_OBSERVED_UNVERIFIED', reason: 'absent-without-fix-evidence' };
    }
    return { spanIndex, status: 'NOT_OBSERVED_UNVERIFIED', reason: 'empty-file-coverage' };
  });

  const statuses = perSpan.map((s) => s.status);
  let status;
  if (statuses.includes('CHANGED_REQUIRES_REVIEW')) status = 'CHANGED_REQUIRES_REVIEW';
  else if (statuses.every((s) => s === 'STILL_PRESENT')) status = 'STILL_PRESENT';
  else if (statuses.every((s) => s === 'FIXED_VERIFIED')) status = 'FIXED_VERIFIED';
  else if (statuses.every((s) => s === 'NOT_OBSERVED_UNVERIFIED')) status = 'NOT_OBSERVED_UNVERIFIED';
  else if (statuses.includes('STILL_PRESENT') && statuses.includes('FIXED_VERIFIED')) status = 'PARTIALLY_FIXED';
  else status = 'NOT_OBSERVED_UNVERIFIED';
  return { status, perSpan };
}
