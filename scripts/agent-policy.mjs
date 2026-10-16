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
export const TRUSTED_ORIGINS = Object.freeze(['system-policy', 'task-brief', 'tool-contract']);

/** Origins that are attacker-controllable by default. */
export const UNTRUSTED_SOURCES = Object.freeze([
  'repo-file',
  'repo-comment',
  'repo-doc',
  'dependency-metadata',
  'commit-message',
  'scan-artifact',
  'web-content',
  'unknown',
]);

/** Instruction hierarchy, highest authority first. */
export const INSTRUCTION_HIERARCHY = Object.freeze([
  'system-policy',
  'task-brief',
  'tool-contract',
  'untrusted-content',
]);

/**
 * Default tool permission map (docs/AGENT_ARCHITECTURE.md §4).
 * Deny-by-default: only entries listed here exist at all, and `allowed: false`
 * entries are explicit denials. `net.fetch` is denied while the Production
 * Intelligence Lock is active. Deeply frozen: neither the map nor any entry can
 * be mutated after import (a shallow freeze left entries writable).
 */
export const DEFAULT_TOOL_POLICY = Object.freeze({
  tools: Object.freeze({
    'read.file': Object.freeze({ allowed: true, scope: 'scan' }),
    'exec.validator': Object.freeze({ allowed: true, scope: 'validators' }),
    'exec.tests': Object.freeze({ allowed: true, scope: 'tests' }),
    'write.scratch': Object.freeze({ allowed: true, scope: 'scratch' }),
    'net.fetch': Object.freeze({ allowed: false, scope: 'net' }),
  }),
});

/** Instruction-shape heuristics for content that tries to act like policy. */
const EMBEDDED_INSTRUCTION_PATTERNS = Object.freeze([
  Object.freeze({ id: 'ignore-previous', re: /\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|above|system|these)\s+(?:instructions?|rules?|prompts?|guidelines?)\b/i }),
  Object.freeze({ id: 'disregard', re: /\bdisregard\s+(?:the\s+)?(?:previous|prior|earlier|above|system|all)\b/i }),
  Object.freeze({ id: 'you-must-now', re: /\byou\s+(?:must|shall|should|will|have\s+to)\s+now\b/i }),
  Object.freeze({ id: 'from-now-on', re: /\bfrom\s+now\s+on\b/i }),
  Object.freeze({ id: 'new-instructions', re: /\bnew\s+(?:system\s+)?instructions?\b/i }),
  Object.freeze({ id: 'system-prompt', re: /\bsystem\s+prompt\b/i }),
  Object.freeze({ id: 'role-reassign', re: /\b(?:you\s+are\s+now|act\s+as\s+(?:an?\s+)?(?:unrestricted|jailbroken|different)|pretend\s+(?:to\s+be|you))\b/i }),
  Object.freeze({ id: 'tool-smuggling', re: /\b(?:invoke|call|execute|run)\s+(?:the\s+)?(?:tool|command|function)\b/i }),
  Object.freeze({ id: 'tag-injection', re: /<\/?(?:assistant|system|tool|function)>/i }),
  Object.freeze({ id: 'exfiltration', re: /\b(?:send|post|exfiltrate|upload|leak|print)\b[^.]{0,48}\b(?:secret|secrets|token|credential|credentials|password|passwords|api\s*key)s?\b/i }),
  Object.freeze({ id: 'override-policy', re: /\boverrides?\b[^.]{0,32}\b(?:policy|permission|permissions|rules?|restrictions?|model)\b/i }),
  Object.freeze({ id: 'hide-from-user', re: /\b(?:do\s+not|never|don't)\s+(?:tell|inform|show|alert|notify)\s+the\s+user\b/i }),
]);

/**
 * Echo an untrusted value into a reason/origin string without letting it crash
 * the module (hostile `toString`/`Symbol.toPrimitive`), forge log lines
 * (control characters), or flood logs (length cap). Never returns the raw
 * attacker object.
 * @param {unknown} value
 * @returns {string}
 */
function safeEcho(value) {
  let text;
  if (typeof value === 'string') {
    text = value;
  } else if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    text = String(value);
  } else if (value === null) {
    text = 'null';
  } else if (value === undefined) {
    text = 'undefined';
  } else {
    text = `[${typeof value}]`;
  }
  // Strip C0/C1 control characters (log-injection hardening) and cap length.
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\u0000-\u001f\u007f-\u009f]/g, '?').slice(0, 64);
}

/**
 * Classify an input origin. Unknown origins are untrusted (fail-closed).
 * @param {string} origin
 * @returns {{origin: string, trusted: boolean, reason: string}}
 */
export function classifyUntrusted(origin) {
  if (typeof origin !== 'string' || origin.length === 0) {
    return { origin: safeEcho(origin), trusted: false, reason: 'unknown-origin' };
  }
  if (TRUSTED_ORIGINS.includes(origin)) {
    return { origin: safeEcho(origin), trusted: true, reason: 'policy-grade-origin' };
  }
  return {
    origin: safeEcho(origin),
    trusted: false,
    reason: UNTRUSTED_SOURCES.includes(origin) ? 'listed-untrusted-source' : 'unknown-origin',
  };
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
    if (m) findings.push({ id, match: safeEcho(m[0]) });
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
  // policy-grade actor, carried as the call context's OWN property (a
  // prototype-inherited `requestedBy` is not evidence of who is asking).
  // Missing/null/unknown requesters are untrusted.
  const ctxIsObject = ctx !== null && typeof ctx === 'object';
  const requestedBy = ctxIsObject && Object.hasOwn(ctx, 'requestedBy') ? ctx.requestedBy : undefined;
  const POLICY_GRADE_REQUESTERS = ['system-policy', 'task-brief', 'tool-contract'];
  if (typeof requestedBy !== 'string' || !POLICY_GRADE_REQUESTERS.includes(requestedBy)) {
    return { allowed: false, reason: `untrusted-requester:${safeEcho(requestedBy)}` };
  }
  if (policy === null || typeof policy !== 'object' || typeof policy.tools !== 'object' || policy.tools === null) {
    return { allowed: false, reason: 'no-policy' };
  }
  if (typeof toolId !== 'string' || toolId.length === 0) {
    return { allowed: false, reason: 'unknown-tool' };
  }
  // The tool entry must be an OWN property of the policy's tool map:
  // prototype lookups (`__proto__`, `constructor`, `toString`, ...) never
  // authorize anything.
  const entry = Object.hasOwn(policy.tools, toolId) ? policy.tools[toolId] : undefined;
  if (entry === undefined || entry === null || typeof entry !== 'object') {
    return { allowed: false, reason: 'unknown-tool' };
  }
  if (entry.allowed !== true) {
    return { allowed: false, reason: 'denied-by-policy' };
  }
  if (typeof entry.scope === 'string' && entry.scope !== '*') {
    // Fail-closed scope binding: a concrete scope entry requires the call to
    // DECLARE a matching scope. A missing/non-string scope is not a wildcard.
    if (typeof ctx?.scope !== 'string') {
      return { allowed: false, reason: 'scope-missing' };
    }
    if (ctx.scope !== entry.scope) {
      return { allowed: false, reason: `scope-escape:${safeEcho(ctx.scope)}` };
    }
  }
  return { allowed: true, reason: 'ok' };
}

const BUDGET_FIELDS = ['wallClockMs', 'maxToolCalls', 'maxTokens', 'maxWriteBytes'];

/**
 * Fail-closed budget check. Missing fields are simply not constrained, but a
 * budget object with no numeric fields at all is rejected (fail-closed), as is
 * any NaN/negative/overspent value. Limits must be OWN properties: a
 * prototype-inherited `wallClockMs` is not a granted budget.
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
    if (!Object.hasOwn(budget, field)) continue;
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
