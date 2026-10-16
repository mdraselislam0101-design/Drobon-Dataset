# PACK_FLOW_DSL_PROPOSAL.md — expressing flow rules in rule packs (PROPOSAL ONLY)

Status: **PROPOSAL ONLY (2026-10-16).** No schema, validator, generator, rule, or
test has changed. Rule-pack counts stay 951; the flow gap stays visible as
ledger row `R-SAST-P-04` (VERIFIED_PARTIAL 1/2). This document exists to close
backlog item GAP-015 (design documentation) and to give the owner a concrete
decision surface. It grants nothing and invents no detection.

## 1. Problem

The Main App SAST engine has a **bounded semantic layer** (`docs/SAST.md`,
Drobon `c32c797`): literal masking plus intra-file taint flows, shipping its
first flow-driven rules (DG-SAST-048…050). Dataset rule packs
(`drobon.pack.sast/v1`) are **lexical only** — one regex per pattern, no way to
express "untrusted input reaching a sink". A pack rule can therefore never
represent the app's flow rules; parity is capped at the lexical layer
(ledger `R-SAST-P-04` passing subreq: lexical parity verified; failing subreq:
flow expressibility).

## 2. Goals (what a flow DSL would add)

1. Express **source → sink** pairs per language family without embedding rule
   logic in the app (rules stay data; matching stays in engines).
2. Keep every existing guarantee: deterministic ids, executed positive AND
   negative tests per rule, ReDoS-safe patterns, CWE resolution, remediation
   linkage, closed schemas.
3. Stay honest: a flow rule must not claim proof of exploitability — the same
   "review required" framing as lexical rules.

Non-goals: whole-program interprocedural analysis, cross-file taint, solver
engines, or any change to the Main App (loader and matcher remain app work,
class E).

## 3. Sketch (illustrative, not normative)

New optional pattern kind in `drobon.pack.sast/v1` (one rule may mix lexical
and flow patterns):

```json
{
  "kind": "flow",
  "source": { "regex": "\\brequest\\.(args|form|values)\\b", "flags": "i" },
  "sanitizers": [{ "regex": "\\bshlex\\.quote\\s*\\(" }],
  "sink": { "regex": "\\bsubprocess\\.(run|call|Popen)\\s*\\(" },
  "mode": "intra-file"
}
```

Semantics sketch: within one file, if a line matches `source` and a later line
matches `sink` with no intervening `sanitizer` match on the tainted name, the
rule fires **with flow evidence** (both locations) or falls back to a
"suspected flow, review required" finding. Exact matching machinery is the
app's bounded-layer contract (literal masking + intra-file flows) — the pack
only declares the triple.

## 4. Validation sketch (must land with any schema change)

- `validate-packs.mjs`: closed schema for `kind: "flow"`; both regexes pass
  `lintRedos`; `mode` enum `{intra-file}` (cross-file stays out of scope);
  at least one positive test whose fixture contains BOTH source and sink
  lines, and at least one negative with source-only, sink-only, and
  sanitized-flow fixtures.
- `scripts/test-packs.mjs`: evaluator rows for flow semantics (order,
  sanitizer veto, reverse-order negative).
- Determinism: generator emits flow rules from a cell kind with the same id
  stability; `test-determinism.mjs` unchanged in contract.

## 5. Options for the owner (decision surface)

| Option | Meaning | Cost |
|---|---|---|
| A. Adopt the sketch above | packs gain `kind: "flow"`; app loader maps it to its bounded layer | schema + validator + tests + app loader work (class E) |
| B. Keep packs lexical | flow rules stay app-code (DG-SAST-048…050 pattern); ledger gap stays PARTIAL forever | none; documented limitation |
| C. Hybrid: lexical packs + app-only flow annotations | app exports flow-rule metadata as data later | deferred design |

Evidence supports no recommendation beyond "B is the honest status quo until
an app loader exists" — authoring flow packs with no consumer would be dead
data (SCOPE.md: no seam, no directory).

## 6. What becomes unblocked / what stays blocked

- Unblocked by A: `R-SAST-P-04` reaching FULL, GAP-015 closed at the design
  level (implementation remains class E + schema change).
- Stays blocked regardless: production intelligence (BLK-003), licensing
  (BLK-001/002), all owner policy items (BLK-005…018).
