# SEMANTIC_ANALYSIS_ASSESSMENT.md — Phase 6 Work C (2026-10-17)

Scope: honest assessment of semantic-analysis capabilities for the DROBON
Dataset workstream. Inventory row counts refreshed 2026-10-18; the capability
verdicts (no parser/AST/flow engine) are unchanged. This document is an assessment plus a dependency
specification — it is **not** a claim that semantic analysis exists. All
statements are backed by the current repository tree and its test suites.

## 0. What exists today (inventory, verified)

| Layer | State | Evidence |
|---|---|---|
| Lexical detectors | **Implemented + verified** | 2171 rules (`packs/*/v1/rules`) with executable pos/neg tests; `test-packs` 5,962/5,594 (2026-10-21) |
| Line/observation evaluation | **Implemented + verified** (Phase 6; breadth extended 2026-10-19) | `scripts/eval-foundation.mjs` + `data/eval-cases` (1,390 synthetic cases, 1,192 distinct rules in positive detections: 942 SAST / 97 secrets / 153 DAST); `test-eval` 43/43; breadth report `npm run eval:coverage` |
| Evidence source-mapping | **Implemented + verified** (Phase 6, small milestone) | `scripts/finding-evidence.mjs` `extractEvidence` (line-range/excerpt/context computed from actual text); `test-finding-evidence` 31/31 |
| Parser / AST | **NOT IMPLEMENTED** | no parser, grammar, or AST code anywhere in `scripts/`; no tests |
| Header semantic models | **Implemented + verified** (2026-10-19) | `scripts/lib/csp.mjs` (policies/directives/source lists, fallback chain, first-wins duplicates) and `scripts/lib/set-cookie.mjs` (RFC 6265 attribute model, flag and SameSite resolution, and a storage decision that excludes refused cookies); differential gates `scripts/test-csp-semantics.mjs` 4,538/4,538 (incl. the multi-policy, keyword-case and duplicate-header limitation pins) and `scripts/test-cookie-semantics.mjs` 2,104/2,104 (incl. a cross-rule duplicate-finding suite) |
| Control-flow graph | **NOT IMPLEMENTED** | no CFG code or tests |
| Data-flow / taint tracking | **NOT IMPLEMENTED** | no taint code or tests; eval case EVAL-SAST-004 is explicitly `UNASSESSED` because of this |
| Source/sink/sanitizer models | **NOT IMPLEMENTED** | rule pack is shape-level; sanitizers are not modelled (see FP/FN boundaries per rule `limitation` fields) |
| Call-graph construction | **NOT IMPLEMENTED** | no call-graph code or tests; `finding-evidence` records `callChainEvidence.state = NOT_ASSESSED` |
| Framework-specific semantics | **Shape level only** | framework rules (e.g. DPK-SAST-114..146 family) match framework API shapes lexically; no semantic models |
| Evidence location / source mapping | **Implemented + verified** (Phase 6) | `extractEvidence`: offsets/line-range/context computed, never invented; failure = explicit error |
| Independent finding verification | **Contract implemented + verified** (Phase 6) | `agent-workflows.mjs` `verifyCandidate` (evidence re-check, explanation ≠ proof); `test-agent-workflows` 40/40 — no live verifier agent exists |

## 1. Per-capability assessment

### 1.1 Parsing and AST construction — NOT IMPLEMENTED
- **Existing code/tests:** none (verified by repository inventory).
- **Smallest useful milestone (for a future workstream):** a single-language
  expression parser sufficient to classify `execute(...)` argument shapes
  (concatenation vs placeholder binding) for Python only.
- **Approach comparison on reproducible synthetic cases:**
  - (a) Full parser (tree-sitter-class): high fidelity, large dependency +
    maintenance surface. Rejected for this workstream (mandate: no large new
    parser framework here; licensing review needed first — D-1/D-2 open).
  - (b) Targeted argument-shape classifier (balanced-paren slice + operator
    scan around the sink): small, original, testable against the existing
    eval cases (EVAL-SAST-001/002/003 distinguish `+`/`%`/placeholder).
    Feasible, but it is NOT an AST and must never be labelled one.
  - (c) Status quo (lexical regex): already shipped; documented FP classes
    (docstring/comment matches — EVAL-SAST-008 pins this honestly).
- **Language coverage:** none beyond lexical matching today. Unsupported
  constructs: every structural question (scope, aliasing, interpolation
  provenance) is **UNASSESSED**.
- **Decision this phase:** no parser is implemented here. Approach (b) is
  specified below as the Main App workstream's smallest milestone because
  sink semantics must eventually join the engine's language pipeline
  (GATE-4 co-design); a Dataset-side second implementation would duplicate
  the engine seam and is rejected (no competing implementations).

### 1.2 Control-flow representation — NOT IMPLEMENTED
Smallest milestone: per-function linear statement order + reachability flag
for a single language. Requires a parser first (1.1). Explicitly out of scope
for the Dataset workstream.

### 1.3 Data-flow and taint tracking — NOT IMPLEMENTED
- **Existing code/tests:** none. Eval case EVAL-SAST-004 (`cursor.execute(sql)`
  with unknown `sql` provenance) is the standing reproducible demonstration
  that this gap is real: ground truth is `UNASSESSED`, and it is never scored.
- **Smallest useful milestone:** intraprocedural source→sink for one language
  (request parameter → SQL string) with an explicit sanitizer allowlist.
- **Confidence limitation:** without taint, every "review required" rule is a
  shape match only; the rules' `limitation` fields already say so.

### 1.4 Source, sink and sanitizer models — SHAPES ONLY
Sink vocabulary exists as rule titles/patterns (1200 rules). Sanitizers are
not modeled; parameterized-query use is a documented negative fixture family
(EVAL-SAST-002). Smallest milestone: a sanitizer declaration schema
(`knowledge/sanitizers/`) + engine wiring — specified for the App workstream.

### 1.5 Call-graph construction — NOT IMPLEMENTED
Smallest milestone: same-file direct-call edges for one language. Blocked on
1.1. `finding-evidence.mjs` marks call-chain evidence `NOT_ASSESSED` rather
than empty, so absence is explicit.

### 1.6 Framework-specific semantics — LEXICAL ONLY
Framework rules match framework API call shapes (documented capability in
`docs/CAPABILITY_GAP_MATRIX.md` CGM-B2). No framework data-flow semantics
exist. Limitations are per-rule `limitation` text.

### 1.7 Evidence location and source mapping — IMPLEMENTED (Phase 6 milestone)
- **Code:** `scripts/finding-evidence.mjs` (`extractEvidence`).
- **Tests:** `scripts/test-finding-evidence.mjs` (24 assertions): exact
  line-range computed from text (never invented), ±2-line context, occurrence
  selection, explicit errors for unlocatable spans, determinism, CVSS/severity
  carried only from declared rules, remediation kept separate from source.
- **Limitations:** text-offset mapping only; multi-line match spans supported
  via `lineFrom..lineTo`; no symbol resolution.

### 1.8 Independent finding verification — CONTRACT + PURE CORE (Phase 6)
`verifyCandidate` (W2 verifier side) mechanically re-checks evidence against a
scanned snapshot and returns CONFIRMED / REJECTED / UNRESOLVED. Tested
fail-closed behaviors: explanation-only ⇒ UNRESOLVED; fabricated excerpts ⇒
REJECTED path (`evidence-mismatch`); fixture-only decoys ⇒ REJECTED;
timeouts ⇒ UNRESOLVED. **No live agent verifier exists**; this is the
deterministic contract a future runtime must call (AGENT_ARCHITECTURE §3 W2).

## 2. Decision for this workstream

The Dataset workstream **cannot responsibly implement semantic analysis**
without duplicating the Main App engine seam or importing an external parser
framework (blocked on D-1/D-2 licensing and GATE-4 co-design). Phase 6
therefore ships only the two genuinely Dataset-side pieces: evidence
source-mapping (1.7) and the verification contract (1.8), and produces the
dependency specification below.

## 3. Dependency & acceptance specification — Main App workstream (not implemented here)

| ID | Milestone | Acceptance (all required) | Depends on |
|---|---|---|---|
| SEM-A1 | Python argument-shape classifier at `execute`/`os.system` sinks | On EVAL-SAST-001/002/003/005/006 fixtures: concatenation/`%`/`.format` classified `built-from-parts`; placeholder+tuple classified `bound`; zero misclassifications on those fixtures; explicitly lexical-adjacent (no AST claim) | engine language pipeline (GATE-4) |
| SEM-A2 | Balanced-paren/call extraction utility | Extracts exact call argument text for nested parens/strings; 100% on a 20-case synthetic suite authored with expected outputs first | SEM-A1 |
| SEM-B1 | Intraprocedural taint (request→SQL) with sanitizer declarations | EVAL-SAST-004 becomes assessable: with `sql` tainted ⇒ issue, with `sql` from a constant ⇒ clean; sanitizer allowlist blocks known-safe APIs; every sanitizer carries pos+neg tests | SEM-A1/A2 |
| SEM-B2 | Sanitizer schema `knowledge/sanitizers/` v1 | Schema + validators + ≥3 original sanitizer entries, each with pos+neg fixtures and scope limits | SEM-B1 |
| SEM-C1 | Call-graph (same-file direct edges, one language) | Edges reproducible on a synthetic fixture; every edge cites file/line evidence via `finding-evidence.mjs` | SEM-A2 |
| SEM-D1 | Framework semantics (one framework, one flow) | Django `raw()`/`extra()` request→SQL flow cases with expected outcomes authored first; FP/FN reported only over that synthetic set | SEM-B1 |

Ground rules inherited from this workstream (non-negotiable): expected
outcomes authored before execution; UNASSESSED where ground truth is unknown;
no copied detection logic; no external datasets to inflate benchmarks; never
label lexical output as semantic analysis; evidence records never invent
locations/scores.

## 3.1 Phase 7 semantic-boundary test coverage (2026-10-17)

The mandatory boundary scenarios now have executed regression tests (eval
corpus `data/eval-cases` + `test-agent-workflows` §7 + `test-finding-evidence`):
source+sink same expression (CONFIRMED with exact evidence), intermediate
assignments (EVAL-SAST-010), sanitization before sink (EVAL-SAST-011),
sanitization after sink (EVAL-SAST-012), branch-dependent paths
(EVAL-SAST-013), unknown function behavior (EVAL-SAST-014 → UNASSESSED,
never scored), ambiguous framework semantics (EVAL-SAST-016 → UNASSESSED),
incomplete snippets (EVAL-SAST-015 → UNASSESSED; verification contract
returns UNRESOLVED on excerpt mismatch), unsupported constructs (eval
case-level UNASSESSED policy). The suites distinguish CONFIRMED /
REJECTED / UNRESOLVED / UNASSESSED / NOT_ASSESSED accurately and never
confirm without exact source evidence. **No semantic analysis engine was
implemented** — these are boundary-state tests of the existing contracts;
the capability inventory in §1 is unchanged.

## 3.2 Phase 8 note

The Phase 8 cross-language `sql-concat` closure (11 variant frags) is
**lexical** work in the same line-regex family — it does not change any
capability in §1: parser/CFG/taint/call-graph/framework semantics remain
NOT IMPLEMENTED. Interpolation alternatives (f-string, template, GString,
s-interp, `fmt.Sprintf`) are string-shape detectors, not data-flow analysis;
cases whose truth depends on callee or cross-line semantics stay UNASSESSED
(EVAL-SQL-027/028).

## 3.3 Phase 9 note

The candidate→finding promotion contract (`promoteCandidate`) implements an
evidence-gated **verification boundary**, not semantic analysis: VERIFIED
requires a different detector family with exact redacted span evidence;
liveness/revocation verification remains **NOT IMPLEMENTED** (contract-only,
tested). No capability in §1 changed.

## 4. Honest statement of what Phase 6 did and did not do

- **Did:** evidence source-mapping implementation + tests; verification
  contract + tests; this assessment; the eval foundation that makes future
  semantic milestones measurable (Work A).
- **Did NOT:** build any parser, CFG, taint engine, call graph, or framework
  model; claim any of the above; touch the Main App; import any external
  analysis framework or ruleset.
