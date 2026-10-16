/**
 * agent-policy.mjs — deterministic agent-governance policy core (Phase 4).
 *
 * Pure functions, no I/O, no network. Any future AI-agent runtime in the
 * DROBON analysis pipeline MUST route tool permissions, budgets, and untrusted
 * repository content through this module. Design and acceptance criteria:
 * docs/AGENT_ARCHITECTURE.md (W1/W2/W3, §4–§6).
 *
 * Threat model: repository files, comments, documentation, dependency
 * metadata, commit messages, and scan artifacts are attacker-controllable and
 * may contain prompt-injection attempts. The instruction hierarchy is
 * `system policy > task brief > tool contracts > untrusted content`; nothing
 * carried by untrusted content can grant a tool, a permission, or budget.
 *
 * Fail-closed contract:
 *   - unknown origin            -> untrusted
 *   - unknown tool / no policy  -> denied
 *   - untrusted caller          -> denied (even for allowlisted tools)
 *   - missing/NaN/negative budget or spend -> denied
 *
 * Limits (stated honestly): `detectEmbeddedInstructions` is a hardening
 * heuristic over known instruction shapes, not a proof that content is safe.
 * The load-bearing controls remain deny-by-default permissions, least
 * privilege, and independent finding verification.
 */

/** Origins whose text is policy-grade (never content-attacker-controlled). */
export const TRUSTED_ORIGINS = ['system-policy', 'task-brief', 'tool-contract'];

/** Origins that are attacker-controllable by default. */
export const UNTRUSTED_SOURCES = [
  'repo-file',
  'repo-comment',
  'repo-doc',
  'dependency-metadata',
  'commit-message',
  'scan-artifact',
  'web-content',
  'unknown',
];

/** Instruction hierarchy, highest authority first. */
export const INSTRUCTION_HIERARCHY = [
  'system-policy',
  'task-brief',
  'tool-contract',
  'untrusted-content',
];

/**
 * Default tool permission map (docs/AGENT_ARCHITECTURE.md §4).
 * Deny-by-default: only entries listed here exist at all, and `allowed: false`
 * entries are explicit denials. `net.fetch` is denied while the Production
 * Intelligence Lock is active.
 */
export const DEFAULT_TOOL_POLICY = Object.freeze({
  tools: {
    'read.file': { allowed: true, scope: 'scan' },
    'exec.validator': { allowed: true, scope: 'validators' },
    'exec.tests': { allowed: true, scope: 'tests' },
    'write.scratch': { allowed: true, scope: 'scratch' },
    'net.fetch': { allowed: false, scope: 'net' },
  },
});

/** Instruction-shape heuristics for content that tries to act like policy. */
const EMBEDDED_INSTRUCTION_PATTERNS = Object.freeze([
  { id: 'ignore-previous', re: /\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|above|system|these)\s+(?:instructions?|rules?|prompts?|guidelines?)\b/i },
  { id: 'disregard', re: /\bdisregard\s+(?:the\s+)?(?:previous|prior|earlier|above|system|all)\b/i },
  { id: 'you-must-now', re: /\byou\s+(?:must|shall|should|will|have\s+to)\s+now\b/i },
  { id: 'from-now-on', re: /\bfrom\s+now\s+on\b/i },
  { id: 'new-instructions', re: /\bnew\s+(?:system\s+)?instructions?\b/i },
  { id: 'system-prompt', re: /\bsystem\s+prompt\b/i },
  { id: 'role-reassign', re: /\b(?:you\s+are\s+now|act\s+as\s+(?:an?\s+)?(?:unrestricted|jailbroken|different)|pretend\s+(?:to\s+be|you))\b/i },
  { id: 'tool-smuggling', re: /\b(?:invoke|call|execute|run)\s+(?:the\s+)?(?:tool|command|function)\b/i },
  { id: 'tag-injection', re: /<\/?(?:assistant|system|tool|function)>/i },
  { id: 'exfiltration', re: /\b(?:send|post|exfiltrate|upload|leak|print)\b[^.]{0,48}\b(?:secret|secrets|token|credential|credentials|password|passwords|api\s*key)s?\b/i },
  { id: 'override-policy', re: /\boverrides?\b[^.]{0,32}\b(?:policy|permission|permissions|rules?|restrictions?|model)\b/i },
  { id: 'hide-from-user', re: /\b(?:do\s+not|never|don't)\s+(?:tell|inform|show|alert|notify)\s+the\s+user\b/i },
]);

/**
 * Classify an input origin. Unknown origins are untrusted (fail-closed).
 * @param {string} origin
 * @returns {{origin: string, trusted: boolean, reason: string}}
 */
export function classifyUntrusted(origin) {
  if (typeof origin !== 'string' || origin.length === 0) {
    return { origin: String(origin), trusted: false, reason: 'unknown-origin' };
  }
  if (TRUSTED_ORIGINS.includes(origin)) {
    return { origin, trusted: true, reason: 'policy-grade-origin' };
  }
  return { origin, trusted: false, reason: UNTRUSTED_SOURCES.includes(origin) ? 'listed-untrusted-source' : 'unknown-origin' };
}

/**
 * Heuristically flag text that carries embedded instructions (prompt
 * injection shapes). Detection is advisory hardening only.
 * @param {string} text
 * @returns {Array<{id: string, match: string}>}
 */
export function detectEmbeddedInstructions(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const findings = [];
  for (const { id, re } of EMBEDDED_INSTRUCTION_PATTERNS) {
    const m = re.exec(text);
    if (m) findings.push({ id, match: m[0] });
  }
  return findings;
}

/**
 * Deny-by-default tool permission check.
 * @param {{tools?: Record<string, {allowed?: boolean, scope?: string}>}|null|undefined} policy
 * @param {string} toolId
 * @param {{scope?: string, requestedBy?: string}} [ctx]
 * @returns {{allowed: boolean, reason: string}}
 */
export function checkToolPermission(policy, toolId, ctx = {}) {
  // Fail-closed requester check: the requester must be an explicitly named
  // policy-grade actor. Missing/null/unknown requesters are untrusted.
  const requestedBy = ctx?.requestedBy;
  const POLICY_GRADE_REQUESTERS = ['system-policy', 'task-brief', 'tool-contract'];
  if (typeof requestedBy !== 'string' || !POLICY_GRADE_REQUESTERS.includes(requestedBy)) {
    return { allowed: false, reason: `untrusted-requester:${String(requestedBy)}` };
  }
  if (policy === null || typeof policy !== 'object' || typeof policy.tools !== 'object' || policy.tools === null) {
    return { allowed: false, reason: 'no-policy' };
  }
  if (typeof toolId !== 'string' || toolId.length === 0) {
    return { allowed: false, reason: 'unknown-tool' };
  }
  const entry = policy.tools[toolId];
  if (entry === undefined || entry === null || typeof entry !== 'object') {
    return { allowed: false, reason: 'unknown-tool' };
  }
  if (entry.allowed !== true) {
    return { allowed: false, reason: 'denied-by-policy' };
  }
  if (typeof entry.scope === 'string' && entry.scope !== '*' && typeof ctx?.scope === 'string') {
    if (ctx.scope !== entry.scope) {
      return { allowed: false, reason: `scope-escape:${ctx.scope}` };
    }
  }
  return { allowed: true, reason: 'ok' };
}

const BUDGET_FIELDS = ['wallClockMs', 'maxToolCalls', 'maxTokens', 'maxWriteBytes'];

/**
 * Fail-closed budget check. Missing fields are simply not constrained, but a
 * budget object with no numeric fields at all is rejected (fail-closed), as is
 * any NaN/negative/overspent value.
 * @param {Record<string, number>|null|undefined} budget
 * @param {Record<string, number>|null|undefined} spent
 * @returns {{allowed: boolean, reason: string}}
 */
export function checkBudget(budget, spent = {}) {
  if (budget === null || typeof budget !== 'object') {
    return { allowed: false, reason: 'no-budget' };
  }
  const constrained = [];
  for (const field of BUDGET_FIELDS) {
    if (!(field in budget)) continue;
    const limit = budget[field];
    const used = spent?.[field] ?? 0;
    if (typeof limit !== 'number' || !Number.isFinite(limit) || limit < 0) {
      return { allowed: false, reason: `invalid-budget:${field}` };
    }
    if (typeof used !== 'number' || !Number.isFinite(used) || used < 0) {
      return { allowed: false, reason: `invalid-spend:${field}` };
    }
    if (used > limit) {
      return { allowed: false, reason: `exhausted:${field}` };
    }
    constrained.push(field);
  }
  if (constrained.length === 0) {
    return { allowed: false, reason: 'no-budget-fields' };
  }
  return { allowed: true, reason: 'ok' };
}

/**
 * Evaluate untrusted content: classify it, flag embedded instructions, and
 * prove-by-construction that the effective policy is byte-identical to the
 * input policy (content can never widen permissions).
 * @param {object} policy
 * @param {string} origin
 * @param {string} text
 * @returns {{classification: {origin: string, trusted: boolean, reason: string}, findings: Array<{id: string, match: string}>, effectivePolicy: object}}
 */
export function evaluateUntrustedContent(policy, origin, text) {
  const classification = classifyUntrusted(origin);
  const findings = classification.trusted ? [] : detectEmbeddedInstructions(text);
  // The effective policy is the input policy, unchanged. Callers/tests assert
  // identity or deep equality to pin that content cannot mutate permissions.
  return { classification, findings, effectivePolicy: policy };
}
