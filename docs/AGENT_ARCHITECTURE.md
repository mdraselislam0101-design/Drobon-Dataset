# AGENT_ARCHITECTURE.md — AI-agent-native analysis design (Phase 4, 2026-10-17)

Purpose: define how AI agents will (future) improve DROBON analysis **without**
fabricating capability, findings, or authority. Current state, stated once and
plainly: **no agent/model runtime is configured in this workstream.** No agent
was executed during Phase 4. What *is* implemented and tested now is the
deterministic policy core that any future agent must be governed by
(`scripts/agent-policy.mjs` + `scripts/test-agent-policy.mjs`). Everything else
below is a design with acceptance criteria — status-labelled, never implied to
be running.

Design principles (evidence over hype):

1. **Small coherent architecture, not ten services.** The brief's ten agent
   capabilities collapse into **three workflows + two shared cores**. Agents
   orchestrate; they do not reimplement engines.
2. **Deterministic engines stay authoritative.** Range matching, validators,
   dedup, leak-scan, and ingestion gates are pure code and keep the final say
   on mechanical claims. An agent may *hypothesize*; it may never *certify*.
3. **Untrusted-by-default content.** Repository files, comments, docs,
   dependency metadata, commit messages, and scan artifacts are attacker-
   controllable. Instruction hierarchy:
   `system policy (this file + agent-policy.mjs) > task brief > tool contracts
   > untrusted content`. Nothing in untrusted content can grant tools,
   permissions, budget, or the right to skip verification.
4. **Fail closed.** Unknown tool = denied. Missing budget = denied. Missing
   evidence reference = finding rejected. Timeout = cancelled, not retried
   into unbounded loops.
5. **Least privilege.** Read-only tools for analysis; write tools limited to
   designated scratch/report paths; no network tools in analysis loops (the
   Production Intelligence Lock makes live fetching out of scope anyway).

---

## 1. Integration seam (where agents would attach)

```
                 ┌────────────────────────────────────────────┐
                 │ shared deterministic cores (exist + tested) │
                 │ range.mjs · validate*.mjs · dedup-report   │
                 │ ingestion-gates.mjs (fail-closed)          │
                 │ agent-policy.mjs (Phase 4: policy checks)  │
                 │ rehearse.mjs (synthetic corpora, pure)     │
                 └───────────────▲────────────────────────────┘
                                 │ tool calls (allowlisted)
   repo content ──► W1 planner ──► W2 finder/verifier ──► W3 regression
   (untrusted)     (bounded)        (evidence-bound)       (benchmark)
                                 │
                                 ▼
                     report draft + evidence refs (advisory only;
                     never auto-applied — code-mutation ban)
```

The Main App has exactly one adjacent seam: `AssistantProvider.generate`
(`apps/api/src/assistant/provider.ts`, production default `NONE` —
`docs/SCOPE.md` row 2). Dataset-side agents do not touch it. Any future app
assistant work is app-repo scope (GATE-4 workstream).

## 2. Capability evaluation (brief §8 ten items)

| # | Capability | Fit | Decision (Phase 4) |
|---|---|---|---|
| 1 | Repository understanding & planning | W1 | adopt as workflow (design only) |
| 2 | Specialized analysis agents | W2 roles | adopt **roles within W2**, not separate services |
| 3 | Shared deterministic engines agents can invoke | cores | adopt — engines already exist; tool table below |
| 4 | Evidence-grounded candidate generation | W2 | adopt — evidence refs mandatory |
| 5 | Independent verification & counter-evidence | W2 verifier | adopt — separate context/tools from the finder |
| 6 | Safe bounded follow-up analysis | W2 budgets | adopt — `checkBudget` enforced |
| 7 | Confidence/uncertainty calibration | labels | adopt minimal labels first; calibration needs data |
| 8 | Dedup & cross-engine correlation | core (exists) | keep deterministic (`dedup-report.mjs`, TRUE_DUPLICATE) |
| 9 | Scan-to-scan remediation verification | W3 | deferred — needs a scan store (app workstream, CGM-G4) |
| 10 | Continuous synthetic benchmark generation | W3 | adopt — `rehearse.mjs`-style purity is the model |

## 3. Workflow specifications

### W1 — Repository understanding & analysis planning
- **Responsibility:** map the repository (languages, frameworks, manifests,
  entry points), propose an analysis plan (ordered engine invocations), and
  estimate budget. Produces hypotheses only.
- **Allowed inputs/tools:** read-only file listing + sampling tools; language
  detection is delegated to deterministic taggers where possible; the
  deterministic catalog snapshot (`docs/PACKS.md` block) informs reachability.
- **Outputs:** `plan.json` (tasks, tool ids, budgets) conforming to the
  permission map; evidence refs to sampled files.
- **Evidence requirements:** every plan claim cites file paths; unknown
  language ⇒ `NOT_ASSESSED`, never guessed.
- **Permission boundaries:** read-only + scratch write; no network; cannot
  expand its own toolset (agent-policy enforces).
- **Failure/timeout:** hard budget (default: wall-clock + token caps from the
  run config); on timeout the plan is emitted with `partial: true` and
  unvisited regions listed.
- **Validation:** plan entries must reference allowlisted tool ids;
  `checkToolPermission` run on every planned call before execution.
- **Prevention of unsupported findings:** W1 emits no findings at all.
- **Acceptance criteria:** 100% of planned tool calls pass permission checks
  on a synthetic repo fixture; instruction-injection fixture (README with
  "ignore previous instructions…") causes zero permission expansions (tested
  in `test-agent-policy.mjs`).

### W2 — Evidence-grounded finding candidates + independent verification
- **Responsibility:** two roles in one workflow: (a) *finder* proposes
  candidate findings citing exact file/line evidence and a rule/pattern
  reference; (b) *verifier* — separate context, no finder's conclusions —
  searches for counter-evidence (safe explanations, existing sanitization,
  fixture-only code) and returns CONFIRMED / REJECTED / UNRESOLVED.
- **Allowed inputs/tools:** deterministic engine invocations (validate,
  range, pack tests), file reads within scan scope; no network; no writes
  outside report scratch.
- **Outputs:** candidate records with `{evidenceRefs, engineRefs, verifierVerdict,
  confidence}`. Verdict is advisory to humans, never auto-published.
- **Evidence requirements:** candidate without ≥1 concrete evidence ref is
  dropped by policy; verifier must name its counter-evidence or confirm path.
- **Permission boundaries:** finder and verifier get disjoint scratch; neither
  can write to the dataset; both fail-closed through agent-policy.
- **Failure/timeout:** per-candidate budget; timeout ⇒ UNRESOLVED (never
  CONFIRMED by silence).
- **Validation:** deterministic re-check of every mechanical claim (rule
  exists? pattern matches the quoted line? CWE resolves?) before the record is
  emitted.
- **Prevention of unsupported findings:** CONFIRMED requires (1) evidence ref,
  (2) engine agreement or an explicit deviation note, (3) independent verifier
  verdict. Hypothesis language is preserved in the record (`hypothesis` field).
- **Acceptance criteria:** on a synthetic fixture repo with N planted issues
  and M decoys, W2 must find all N (recall on the synthetic set) and must not
  CONFIRM any decoy; the run trace is reproducible under fixed model params or
  the variance is recorded.

### W3 — Continuous synthetic benchmark & regression comparison
- **Responsibility:** generate or select synthetic corpora (pure, seeded —
  `rehearse.mjs` pattern), run candidate detectors **after expected results
  are declared**, measure TP/FP/FN against that ground truth, and compare with
  the previous run.
- **Allowed inputs/tools:** `rehearse.mjs` generators, test runners, dedup
  report; no network; corpus generation writes only to tmp/scratch.
- **Outputs:** benchmark report (counts, deltas, corpus id, seed) labelled
  **synthetic**; regression verdicts.
- **Evidence requirements:** expected results committed alongside corpus
  seeds; any metric names its corpus (never "real-world precision").
- **Permission boundaries:** cannot touch `packs/`, `knowledge/`, `vuln-intel/`
  (promotion only via the established review/release process).
- **Failure/timeout:** benchmark failure = report failure; never silently
  reduced sample sizes.
- **Validation:** determinism (same seed ⇒ same corpus — already tested);
  metric recomputation by an independent script.
- **Prevention of unsupported findings:** research agents cannot add rules to
  the production Dataset (policy + permission map; promotion requires the
  release process — brief §9.11).
- **Acceptance criteria:** benchmark artifacts reproducible byte-identical
  from seed; every published number carries corpus + seed + date.

## 4. Tool permission map (initial — enforced by `scripts/agent-policy.mjs`)

| Tool id | Scope | Notes |
|---|---|---|
| `read.file` | scan scope | read-only |
| `exec.validator` | `scripts/validate*.mjs`, `check-vectors.mjs` | allowlisted commands only |
| `exec.tests` | `scripts/test-*.mjs` | allowlisted commands only |
| `write.scratch` | run scratch dir | reports, traces |
| `net.fetch` | **denied by default** | Production Intelligence Lock; enable only under owner-authorized workflows |

Unknown tool ids are denied (fail-closed). Any future tool must be added to
this table **and** tested before use.

## 5. Evidence, traces, budgets (spec for future runs)

- **Trace record (per run):** `runId`, model id, prompt hashes, tool calls with
  args hash + duration, budget ledger, verdicts, evidence refs. Stored under
  scratch; promoted to reports only with human acceptance.
- **Budgets:** `wallClockMs`, `maxToolCalls`, `maxTokens` (if applicable),
  `maxWriteBytes`. All validated by `checkBudget` (NaN/negative ⇒ deny).
- **Timeout/retry/cancellation:** importer-style primitives (`retry.mjs`,
  `checkpoint.mjs`) set the pattern — bounded retries with checkpoints;
  cancellation must leave checkpoints consistent and never partially promote.
- **Reproducibility:** temperature 0 where the runtime supports it; residual
  nondeterminism recorded in the trace (never hidden).

## 6. Deterministic policy core — what was implemented in Phase 4

`scripts/agent-policy.mjs` (pure functions, no I/O):

| Export | Behavior |
|---|---|
| `UNTRUSTED_SOURCES` / `INSTRUCTION_HIERARCHY` | fixed policy constants (system > task > tools > untrusted) |
| `classifyUntrusted(origin)` | repo-file/comment/metadata/scan-artifact inputs ⇒ `untrusted`; system/task literals ⇒ `trusted`; unknown ⇒ `untrusted` (fail-closed) |
| `detectEmbeddedInstructions(text)` | heuristics for imperative instruction shapes in untrusted text ("ignore previous…", "you must now…", tool-call smuggling, role reassignment, secret exfiltration requests). Returns findings list; **detection is advisory hardening, not a proof of safety** |
| `checkToolPermission(policy, toolId, ctx)` | deny-by-default; unknown tool/policy/scope ⇒ deny with reason |
| `checkBudget(budget, spent)` | deny on NaN/negative/overshoot; allow otherwise |
| `evaluateUntrustedContent(policy, origin, text)` | aggregate: classification + instruction findings + asserts that permissions/budget cannot be modified by content (returns derived state only) |

`scripts/test-agent-policy.mjs` — synthetic injection corpus (original),
positive detection cases + safe-text negatives, permission/budget fail-closed
cases. Wired into `npm test`.

**Limitations, stated:** heuristics catch known instruction shapes, not all
future injection forms; the module is inert until a runtime enforces it; it
cannot protect a runtime that bypasses it. These are the same limits any
prompt-filter has — the load-bearing controls remain least privilege +
fail-closed tools + independent verification.

## 7. Research pipeline (brief §9) — current state & improvements

Existing pipeline (kept, reused): hypothesis → cell class (original) →
generator (`generate-assets.mjs`) → declared tests (pos/neg/edge in the cell) →
executed suites → dedup/consistency checks → determinism gate → release
process. `rehearse.mjs` already provides step 3–8 for *ingestion* research

(deterministic corpora with expected duplicate/shard/alias scenarios).

Phase 4 assessment: the pipeline already satisfies steps 1–10 for rule
authoring **except** (a) explicit expected-results declaration before first
run is implicit in cell `tests` (acceptable — tests are authored with the
rule), and (b) no real-world benchmark step exists (correct — no authorized
corpora; synthetic labels mandatory). No change required to the pipeline
itself; W3 codifies it for agent-assisted research.

## 8. Validation addendum (Phase 4 run, 2026-10-17)

`scripts/test-agent-policy.mjs` executed as part of `npm test`: **72 passed,
0 failed** (12 injection-shape positives, 8 safe-text negatives, origin
classification fail-closed, permission deny-by-default incl. untrusted
requester + scope escape + missing policy, budget fail-closed incl.
NaN/negative/overspend/missing, and the policy-immutability property). Two
real defects were found by the suite and fixed at root cause in the module
(the plural `overrides` was missed by the override-policy regex; a `null`
requester nullish-coalesced to trusted) — the tests were not weakened. The
repo leak scanner (`test-consistency` §13) also caught a credential-shaped
example inside this suite's own safe-text corpus; the example was reworded
(root cause in the fixture text, not the scanner). Full suite after all
Phase 4 changes: 15,496 assertions across 10 runners, exit 0; all 9
validators exit 0; ingestion gates stay fail-closed.

## 9. Validation addendum (Phase 5 run, 2026-10-17)

`scripts/test-agent-policy.mjs` executed as part of `npm test`: **91 passed,
0 failed** (the Phase 4 suite of 72 plus 19 focused hardening asserts). The
Phase 5 audit treated the policy core as a security boundary and fixed five
defect classes at root cause in `scripts/agent-policy.mjs` (tests were not
weakened):

1. **Mutable trust state** — `TRUSTED_ORIGINS`/`UNTRUSTED_SOURCES`/
   `INSTRUCTION_HIERARCHY` were unfrozen arrays and `DEFAULT_TOOL_POLICY` was
   only shallow-frozen (entries writable). All exported constants are now
   frozen deeply; mutation attempts are impossible and asserted.
2. **Prototype-assisted confusion/aliasing** — `ctx.requestedBy`,
   `policy.tools[toolId]`, and budget limits could be satisfied through the
   prototype chain (`Object.create({requestedBy: ...})`, `toolId =
   '__proto__'`, inherited `wallClockMs`). All identity-bearing lookups now
   require own properties.
3. **Hostile-value crashes (fail-open class)** — reason strings called
   `String(value)`, which throws on an attacker-supplied `toString`. A
   `safeEcho` helper now type-tags non-primitives without invoking user code,
   strips control characters (log-injection hardening), and caps echoes at 64
   characters.
4. **Scope fail-open** — a missing or non-string `ctx.scope` skipped the scope
   check entirely. Concrete-scope tools now deny undeclared scopes
   (`scope-missing`); only an explicit `scope: '*'` policy entry opts out.
5. **Alternate field names** — `requested_by`/`requester`, `toolPolicy`, and
   `wall_clock_ms` were already ignored (fail-closed); tests now pin that
   behavior so a future refactor cannot silently widen it.

Stated limits (unchanged): `detectEmbeddedInstructions` is an advisory
hardening heuristic, not a proof that content is safe; the load-bearing
controls remain deny-by-default permissions, own-property identity,
fail-closed budgets, and independent finding verification. The module remains
deterministic and side-effect-free (asserted), and nothing here claims an
agent runtime, a model, `net.fetch`, or any external service exists or was
exercised — no runtime is configured. Full suite after all Phase 5 changes:
15,553 assertions across 10 runners, exit 0; all validators exit 0;
ingestion gates stay fail-closed.
