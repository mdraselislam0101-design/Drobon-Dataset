/**
 * agent-workflows.mjs — bounded agent orchestration contracts (Phase 6, Work B).
 *
 * Implementation-ready execution contracts for the three W3-architecture
 * workflows (docs/AGENT_ARCHITECTURE.md §3), plus the small pure functions
 * that machine-check their load-bearing boundaries. There is NO agent runtime
 * and NO model connection in this repository: these contracts and functions
 * are what a future runtime must call through, and they are tested today as
 * deterministic code (scripts/test-agent-workflows.mjs).
 *
 * Security model (all fail-closed, all tested):
 *   - every tool use goes through checkToolPermission/checkBudget from
 *     agent-policy.mjs (default-deny, own-property identity, immutable policy);
 *   - repository metadata, candidates, explanations and any other caller text
 *     are untrusted data: they can never widen tools, scopes or budgets;
 *   - a candidate finding is UNRESOLVED until exact source evidence resolves
 *     in the scanned snapshot and re-checks mechanically; explanations are
 *     never proof;
 *   - malformed inputs return explicit failure results — never throw;
 *   - outputs are bounded (task counts, string lengths).
 *
 * Workflows:
 *   W1 scan planning        — planFromMetadata + validatePlan
 *   W2 finding verification — proposeCandidate + verifyCandidate
 *   W3 synthetic evaluation — delegate to scripts/eval-foundation.mjs
 */
import {
  checkBudget,
  checkToolPermission,
  detectEmbeddedInstructions,
} from './agent-policy.mjs';

/** Bounded-output caps (workflows never emit unbounded structures). */
export const LIMITS = Object.freeze({
  maxPlannedTasks: 32,
  maxEvidenceRefs: 16,
  maxText: 4096,
  maxNotes: 32,
});

const FROZEN_REQUESTER = 'task-brief';

/**
 * Machine-verifiable execution contracts. Frozen: no caller can relax one.
 * `deniedTools` names the tools that must stay unusable in this workstream
 * even if some policy object later allows them (defense in depth).
 */
export const WORKFLOW_CONTRACTS = Object.freeze({
  W1: Object.freeze({
    id: 'W1',
    name: 'scan planning',
    inputs: Object.freeze({
      metadata: 'project metadata object (untrusted): languages[], frameworks[], manifestHints[]',
      policy: 'frozen tool policy',
      budget: 'budget object with >=1 numeric BUDGET_FIELDS entry',
    }),
    outputs: Object.freeze({
      plan: 'bounded task list [{taskIndex, toolId, target, budget}] + notAssessed[] regions',
      invariant: 'W1 emits NO findings of any kind',
    }),
    permittedTools: Object.freeze(['read.file', 'exec.validator', 'exec.tests', 'write.scratch']),
    deniedTools: Object.freeze(['net.fetch', 'git.push', 'git.commit', 'fs.write-source', 'model.call']),
    budgets: Object.freeze({ maxToolCalls: 16, wallClockMs: 60000, maxWriteBytes: 65536 }),
    failure: 'on timeout/budget exhaustion emit plan with partial:true and unvisited regions; never guess languages (NOT_ASSESSED)',
    uncertainty: 'unknown language/framework => notAssessed entry, never a planned analysis claim',
    trust: 'metadata is untrusted content; instruction shapes inside it are flagged and ignored for planning authority',
    acceptance: '100% of planned calls pass checkToolPermission+checkBudget; injection in metadata causes zero tool expansions',
  }),
  W2: Object.freeze({
    id: 'W2',
    name: 'evidence-grounded finding verification',
    inputs: Object.freeze({
      candidate: 'candidate object (untrusted): {ruleId, path, lineNo, matchedText, hypothesis?, explanation?, evidenceRefs[]}',
      bundle: 'scanned snapshot: {snapshotId, commitId?, files: {path: lines[]}, fixtureOnlyPaths?: string[]}',
      policy: 'frozen tool policy',
      budget: 'budget object',
    }),
    outputs: Object.freeze({
      verdict: 'CONFIRMED | REJECTED | UNRESOLVED (advisory to humans; never auto-published)',
      record: '{verdict, reason, evidenceRefs (resolved), notes[]}',
      invariant: 'CONFIRMED requires exact source evidence re-checked mechanically; explanation alone never confirms',
    }),
    permittedTools: Object.freeze(['read.file']),
    deniedTools: Object.freeze(['net.fetch', 'git.push', 'git.commit', 'fs.write-source', 'model.call', 'exec.tests']),
    budgets: Object.freeze({ maxToolCalls: 8, wallClockMs: 30000, maxWriteBytes: 0 }),
    failure: 'malformed candidate/bundle => UNRESOLVED; timeout => UNRESOLVED; missing/unresolved evidence => UNRESOLVED; never CONFIRMED by silence',
    uncertainty: 'UNRESOLVED is the honest state for incomplete evidence; REJECTED requires positive counter-evidence (decoy marker, failed re-check)',
    trust: 'candidates and explanations are untrusted data; embedded instructions in them are flagged and cannot alter verdicts',
    acceptance: 'planted synthetic issue with exact evidence => CONFIRMED; decoy with fixture marker => REJECTED; explanation-only candidate => UNRESOLVED',
  }),
  W3: Object.freeze({
    id: 'W3',
    name: 'synthetic evaluation and regression',
    inputs: Object.freeze({
      cases: 'read-only case manifests (data/eval-cases, drobon.eval.case/v1)',
      policy: 'frozen tool policy',
    }),
    outputs: Object.freeze({
      report: 'drobon.eval.report/v1 JSON (deterministic; see scripts/eval-foundation.mjs)',
      invariant: 'expected outcomes are never rewritten; UNASSESSED never scores',
    }),
    permittedTools: Object.freeze(['read.file', 'exec.tests', 'write.scratch']),
    deniedTools: Object.freeze(['net.fetch', 'git.push', 'git.commit', 'fs.write-source', 'model.call']),
    budgets: Object.freeze({ maxToolCalls: 32, wallClockMs: 120000, maxWriteBytes: 262144 }),
    failure: 'invalid case manifests => fail-closed, no report; never silently reduced sample sizes',
    uncertainty: 'cases with UNASSESSED ground truth stay unscored',
    trust: 'cases are synthetic test-only fixtures — never vulnerability intelligence, never promoted to packs/',
    acceptance: 'byte-identical reports across runs; ground-truth hashes unchanged after execution (scripts/test-eval.mjs)',
  }),
});

/** Small pure helper: bounded, throw-free text normalization for record fields. */
function safeText(value, cap = LIMITS.maxText) {
  if (typeof value !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f]/g, '?').slice(0, cap);
}

/**
 * W1 — deterministic planner. Pure: same metadata => same plan. Never emits
 * findings. Unknown languages become explicit notAssessed entries.
 * @returns {{tasks: Array, notAssessed: Array, partial: boolean, injectionFlags: Array}}
 */
export function planFromMetadata(metadata) {
  const result = { tasks: [], notAssessed: [], partial: false, injectionFlags: [] };
  if (metadata === null || typeof metadata !== 'object' || Array.isArray(metadata)) {
    result.partial = true;
    return result;
  }
  const contract = WORKFLOW_CONTRACTS.W1;
  // Untrusted metadata text fields are scanned for instruction shapes (advisory
  // flag only) and NEVER grant tools.
  for (const key of ['readme', 'notes', 'description', 'manifestHints']) {
    const value = metadata[key];
    const texts = Array.isArray(value) ? value : [value];
    for (const text of texts) {
      for (const finding of detectEmbeddedInstructions(typeof text === 'string' ? text : '')) {
        result.injectionFlags.push(finding.id);
      }
    }
  }
  const languages = Object.hasOwn(metadata, 'languages') && Array.isArray(metadata.languages) ? metadata.languages : [];
  const known = new Set(['python', 'javascript', 'typescript', 'java', 'go', 'ruby', 'php', 'csharp']);
  let taskIndex = 0;
  for (const language of [...languages].map((l) => (typeof l === 'string' ? l : '')).sort()) {
    if (language.length === 0) continue;
    if (!known.has(language)) {
      result.notAssessed.push({ region: `language:${safeText(language, 64)}`, reason: 'unknown-language' });
      continue;
    }
    if (taskIndex >= LIMITS.maxPlannedTasks) {
      result.partial = true;
      break;
    }
    result.tasks.push({
      taskIndex,
      toolId: 'exec.tests',
      target: safeText(language, 64),
      budget: { maxToolCalls: 2, wallClockMs: 5000 },
    });
    taskIndex += 1;
    if (taskIndex >= LIMITS.maxPlannedTasks) {
      result.partial = true;
      break;
    }
    result.tasks.push({
      taskIndex,
      toolId: 'read.file',
      target: safeText(language, 64),
      budget: { maxToolCalls: 4, wallClockMs: 5000 },
    });
    taskIndex += 1;
  }
  if (result.tasks.length === 0 && result.notAssessed.length === 0) {
    result.partial = true;
    result.notAssessed.push({ region: 'repository', reason: 'no-metadata' });
  }
  // Every planned tool must be inside the contract's permitted set.
  result.tasks = result.tasks.filter((t) => contract.permittedTools.includes(t.toolId));
  return result;
}

/**
 * W1 — machine-check a plan against the contract and the policy. Any task
 * that fails permission or budget checks fails the whole plan (fail-closed).
 * @returns {{ok: boolean, reason: string, checked: number}}
 */
export function validatePlan(plan, policy, requester = FROZEN_REQUESTER) {
  if (plan === null || typeof plan !== 'object' || !Object.hasOwn(plan, 'tasks') || !Array.isArray(plan.tasks)) {
    return { ok: false, reason: 'malformed-plan', checked: 0 };
  }
  if (plan.tasks.length > LIMITS.maxPlannedTasks) {
    return { ok: false, reason: 'plan-exceeds-task-limit', checked: 0 };
  }
  const contract = WORKFLOW_CONTRACTS.W1;
  let checked = 0;
  for (const task of plan.tasks) {
    if (task === null || typeof task !== 'object') return { ok: false, reason: 'malformed-task', checked };
    if (!contract.permittedTools.includes(task.toolId)) {
      return { ok: false, reason: `tool-not-permitted:${safeText(String(task.toolId), 64)}`, checked };
    }
    const perm = checkToolPermission(policy, task.toolId, { scope: scopeFor(task.toolId), requestedBy: requester });
    if (!perm.allowed) return { ok: false, reason: `permission-denied:${perm.reason}`, checked };
    const budget = checkBudget({ ...contract.budgets, ...(task.budget ?? {}) }, {});
    if (!budget.allowed) return { ok: false, reason: `budget-invalid:${budget.reason}`, checked };
    checked += 1;
  }
  return { ok: true, reason: 'ok', checked };
}

function scopeFor(toolId) {
  if (toolId === 'read.file') return 'scan';
  if (toolId === 'exec.validator') return 'validators';
  if (toolId === 'exec.tests') return 'tests';
  if (toolId === 'write.scratch') return 'scratch';
  return '';
}

/**
 * W2 — finder side (deterministic): propose a candidate record from an exact
 * detection (ruleId + line evidence). Pure; bounded; never attaches verdicts.
 */
export function proposeCandidate(detection, sourceLines) {
  if (detection === null || typeof detection !== 'object' || !Array.isArray(sourceLines)) {
    return { ok: false, reason: 'malformed-input' };
  }
  const lineNo = detection.lineNo;
  const line = Number.isInteger(lineNo) && lineNo >= 1 && lineNo <= sourceLines.length ? sourceLines[lineNo - 1] : null;
  const matchedText = Object.hasOwn(detection, 'matchedText') ? safeText(detection.matchedText, 256) : null;
  if (line === null || matchedText === null || !line.includes(matchedText)) {
    return { ok: false, reason: 'evidence-not-in-source' };
  }
  return {
    ok: true,
    candidate: {
      ruleId: safeText(detection.ruleId, 64),
      path: safeText(detection.path, 512),
      lineNo,
      matchedText,
      hypothesis: safeText(detection.hypothesis, LIMITS.maxText) ?? 'shape matches rule; exploitability not established',
      explanation: null,
      evidenceRefs: [{ path: safeText(detection.path, 512), lineNo, excerpt: line.slice(0, LIMITS.maxText) }],
    },
  };
}

/**
 * W2 — verifier side (independent, fail-closed). Re-checks every mechanical
 * claim against the scanned snapshot. Explanations are never proof. Returns an
 * explicit result object and NEVER throws on malformed input.
 * @returns {{verdict: 'CONFIRMED'|'REJECTED'|'UNRESOLVED', reason: string, notes: string[]}}
 */
export function verifyCandidate(candidate, bundle, opts = {}) {
  const notes = [];
  const unresolved = (reason) => ({ verdict: 'UNRESOLVED', reason, notes });
  if (candidate === null || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return unresolved('malformed-candidate');
  }
  if (bundle === null || typeof bundle !== 'object' || typeof bundle.files !== 'object' || bundle.files === null) {
    return unresolved('malformed-bundle');
  }
  // Timeout / budget boundary: explicit unverified result, never CONFIRMED.
  if (typeof opts.elapsedMs === 'number' && typeof opts.budgetMs === 'number' && opts.elapsedMs > opts.budgetMs) {
    return unresolved('timeout');
  }
  // Untrusted candidate text is scanned; instruction shapes are recorded and
  // can never influence the verdict.
  for (const key of ['hypothesis', 'explanation', 'matchedText']) {
    for (const finding of detectEmbeddedInstructions(typeof candidate[key] === 'string' ? candidate[key] : '')) {
      notes.push(`injection-flag:${finding.id}`);
    }
  }
  const refs = Object.hasOwn(candidate, 'evidenceRefs') && Array.isArray(candidate.evidenceRefs) ? candidate.evidenceRefs : [];
  if (refs.length === 0) {
    return unresolved('evidence-insufficient');
  }
  if (refs.length > LIMITS.maxEvidenceRefs) {
    return unresolved('evidence-refs-unbounded');
  }
  const resolved = [];
  for (const ref of refs) {
    if (ref === null || typeof ref !== 'object' || !Object.hasOwn(ref, 'path') || !Object.hasOwn(ref, 'lineNo') || !Object.hasOwn(ref, 'excerpt')) {
      return unresolved('incomplete-evidence');
    }
    const path = safeText(ref.path, 512);
    const excerpt = safeText(ref.excerpt, LIMITS.maxText);
    if (path === null || excerpt === null || !Number.isInteger(ref.lineNo)) {
      return unresolved('incomplete-evidence');
    }
    const lines = bundle.files[path];
    if (!Array.isArray(lines) || ref.lineNo < 1 || ref.lineNo > lines.length) {
      return unresolved('evidence-unresolved');
    }
    if (lines[ref.lineNo - 1] !== excerpt) {
      return unresolved('evidence-mismatch');
    }
    // Mechanical re-check: the candidate's matched text must appear in the
    // exact source line the evidence points at.
    const matchedText = Object.hasOwn(candidate, 'matchedText') ? safeText(candidate.matchedText, 256) : null;
    if (matchedText === null || !excerpt.includes(matchedText)) {
      return unresolved('claim-not-in-evidence');
    }
    resolved.push({ path, lineNo: ref.lineNo, excerpt });
  }
  // Fixture-only paths are decoys: a finding there is REJECTED with evidence.
  const fixtureOnly = Object.hasOwn(bundle, 'fixtureOnlyPaths') && Array.isArray(bundle.fixtureOnlyPaths) ? bundle.fixtureOnlyPaths : [];
  if (resolved.every((r) => fixtureOnly.includes(r.path))) {
    return { verdict: 'REJECTED', reason: 'fixture-only-scope', notes, resolvedEvidence: resolved };
  }
  return {
    verdict: 'CONFIRMED',
    reason: 'evidence-resolved-and-rechecked',
    notes,
    resolvedEvidence: resolved.slice(0, LIMITS.maxEvidenceRefs),
  };
}

/**
 * Workflow conformance probe used by tests and by any future runtime at
 * startup: every contract's tool lists must stay inside deny-by-default
 * semantics (denied ∩ permitted = ∅, and the hard-denied tools stay denied).
 */
export function auditContracts(policy) {
  const problems = [];
  for (const contract of Object.values(WORKFLOW_CONTRACTS)) {
    for (const toolId of contract.permittedTools) {
      if (contract.deniedTools.includes(toolId)) {
        problems.push(`${contract.id}: ${toolId} listed as both permitted and denied`);
      }
      const check = checkToolPermission(policy, toolId, { scope: scopeFor(toolId), requestedBy: FROZEN_REQUESTER });
      if (!check.allowed && toolId !== 'net.fetch') {
        problems.push(`${contract.id}: permitted tool ${toolId} fails policy check (${check.reason})`);
      }
    }
    for (const toolId of contract.deniedTools) {
      const check = checkToolPermission(policy, toolId, { scope: '*', requestedBy: FROZEN_REQUESTER });
      if (check.allowed) {
        problems.push(`${contract.id}: denied tool ${toolId} is allowed by policy`);
      }
    }
  }
  return problems;
}
