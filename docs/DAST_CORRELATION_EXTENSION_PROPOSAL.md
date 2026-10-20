# DAST correlation check types — minimal v1-compatible extension proposal

**Status: BLOCKED_PENDING_OWNER_DECISION. Nothing here is implemented.**
The DAST evaluator still has exactly the 7 closed check types in
`scripts/validate-packs.mjs`, reads one observation, and the pack count is
unchanged by this document. No v2 schema, parallel engine, registry or
evaluator was created.

- Date: 2026-10-19
- Supersedes the schema framing (not the analysis) of
  `docs/DAST_CHECK_TYPE_EXTENSION_PROPOSAL.md`, which proposed a
  `drobon.pack.dast/v2` version. This proposal keeps the existing
  `drobon.pack.dast/v1` schema and adds two values to its closed check
  vocabulary, behind an owner-gated validator constant.
- Repository state: branch `arena/a4caaeb8-drobon-dataset`, HEAD
  `ed599c654e972cf517331bb504d65f3e8c2dbcf1`; no commit, push or tag.

## 1. Why the existing types cannot close the gap

`evalDastCheck(check, observation)` receives one normalised observation
(`url`, `status`, `headers`, `body?`, `contentType?`). Every one of the 7 types
answers a question about **one** header key or **one** body string. A finding
that requires two headers to agree, or a request line that is not in the
observation, cannot be expressed by any combination of the existing types:
two independent rules do not establish that the headers were observed on the
same response, and no request field exists at all. The two gaps are therefore
real vocabulary gaps, not missing rules.

## 2. Smallest compatible extension

Both changes are additive to the existing v1 contract. Neither changes the
meaning of an existing type, rule, pattern, record or evaluation case.

### 2.1 `response-headers-correlate`

Add one value to the existing `DAST_CHECK_TYPES` array:

```jsonc
{
  "type": "response-headers-correlate",
  "conditions": [                    // 2..4 entries, unique header after lower-casing
    { "header": "Access-Control-Allow-Origin", "valuePattern": "^\\*$" },
    { "header": "Access-Control-Allow-Credentials", "valuePattern": "^true$" }
  ],
  "semantics": "all-headers-on-one-response"
}
```

Closed keys: `check` = `type`, `conditions`, `semantics`; each condition =
`header`, `valuePattern` (optional, ReDoS-linted, ≤500 chars), `absent`
(optional boolean). `semantics` is a literal; unknown values are rejected.
Duplicate headers after case folding are rejected, not merged. `absent: true`
with `valuePattern` is rejected as contradictory.

Semantics: lower-case the header map exactly as today; every condition is
evaluated against the **same** header map; return true iff all conditions hold.
Missing/non-object `headers` makes every condition false and never throws.
Evidence records each condition's observed line (or the declared absence) in
declaration order, so a finding always contains at least two conditions.

### 2.2 `request-response-pair`

Add a second value to `DAST_CHECK_TYPES` and one optional object to the
observation schema:

```jsonc
"request": {
  "method": "GET",                  // required inside request, closed enum
  "path": "/account/1",             // required inside request
  "headers": { "Cookie": ["..."] }  // optional, same header validation as response
}
```

Check schema: `request` = `methods` (1..4 closed-enum uppercase tokens),
`pathPattern` (optional, ReDoS-linted), `headerPresent` (0..4 tokens);
`response` = `statusIn` (optional, 1..8 unique integers 100..599),
`headerPresent` (0..4 tokens); `semantics` literal. Return true iff the request
exists and every declared condition matches. A missing `request` returns false
and must be reported as `NOT_ASSESSED` coverage for that observation — never as
a pass and never as a negative finding.

Evidence records `"<METHOD> <path>"`, the matched request header lines and the
matched response header lines. A fabricated request line is a defect.

## 3. Owner gate and compatibility

- `DAST_CHECK_TYPES` gains the two values only when the owner-approved constant
  `DAST_CORRELATION_ENABLED` is flipped from `false` to `true`. While it is
  `false`, `validate-packs` rejects both types with a clear error. The constant
  is the single switch; there is no second schema, parser or registry.
- Existing 90 rules, 1,137 patterns/records/remediation entries and 1,231
  evaluation cases must produce byte-identical results after the change.
- A loader that does not know the new types must reject the file. Silent
  downgrade to a single-header check is forbidden; that would be the simulation
  this proposal exists to prevent.
- The rule/pattern/record/remediation/eval asset conventions are unchanged.
- Rollback is flipping the constant back; no v1 file is rewritten.

## 4. Required tests before any correlation rule ships

- ≥2 positives that satisfy every condition on one response.
- ≥2 negatives where each condition holds on a *different* observation but no
  single observation satisfies all conditions (proves no independent-rule
  simulation).
- Boundaries: 2 and 4 conditions; duplicate header after case folding; 5
  conditions; missing/unknown `semantics`; `absent` + `valuePattern` conflict.
- Malformed: missing/null/array `headers`; non-string value; malformed regex;
  ReDoS-shaped pattern.
- Request/response: missing `request` → false + `NOT_ASSESSED`; method case;
  path boundary; `statusIn` inclusive ends; request-only vs response-only header.
- Determinism and adjacent-rule regression against the frozen v1 corpus.

## 5. Owner decision required

Proposed `docs/OWNER_DECISIONS.json` entry (owner inserts it; this agent does
not modify the file):

```
subject:          DAST_CORRELATION_CHECK_TYPES
requiredDecision: "Approve adding exactly two check types
                   (response-headers-correlate, request-response-pair) to the
                   existing drobon.pack.dast/v1 vocabulary, with the closed
                   schemas in docs/DAST_CORRELATION_EXTENSION_PROPOSAL.md, and
                   flip DAST_CORRELATION_ENABLED only after the full test matrix
                   is green."
status:           OWNER_DECISION_REQUIRED
decidedAt:        null
decider:          null
eligibleScope:    DAST pack schema/evaluator; Main App loader still out of scope
```

**If approved:** implement the validator/evaluator branch and the full negative
matrix first; then author a bounded first batch (CORS credentials/origin,
cacheable `Set-Cookie`, CSP enforced-vs-report-only, request/response pairs).
**If refused:** the families remain `SCHEMA_BLOCKED` and no workaround is
attempted.

## 6. Ceiling

These two types add a bounded set of genuine families (single digits to low
tens), not hundreds of rules. They do not close the 1,000 DAST+SCA target and do
not make the Dataset production-ready. The SCA pack schema remains a separate
owner gate, and the overall Dataset verdict remains **NO-GO**.
