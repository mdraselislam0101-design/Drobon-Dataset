# DAST check-type extension proposal — multi-header correlation and request/response pairs

**Status: BLOCKED_PENDING_OWNER_DECISION.**
**2026-10-19 note:** the DAST cumulative master pump forbids a new schema
version or a parallel engine. The `drobon.pack.dast/v2` framing below is
superseded by `docs/DAST_CORRELATION_EXTENSION_PROPOSAL.md`, which proposes the
same two check types as an additive extension of the existing v1 vocabulary
behind an owner-gated constant. The analysis and test matrix below remain
valid; nothing is implemented in either document.
Nothing in this document is implemented. The DAST schema on disk remains
`drobon.pack.dast/v1` with the same 7 closed check types, and the rule count
is unchanged by this proposal. No rule, pattern, record, remediation entry or
evaluation case was authored from this proposal, and no single-header rule was
used to simulate the correlations described here.

- Date: 2026-10-19
- Author: Drobon Dataset agent (Arena session `arena/a4caaeb8-drobon-dataset`)
- Repository state when written: HEAD `ed599c654e972cf517331bb504d65f3e8c2dbcf1` on
  `arena/a4caaeb8-drobon-dataset`; no commit, push or tag was made.
- Canonical owner register: `docs/OWNER_DECISIONS.json` (closed keys; this
  proposal does **not** add an entry — the owner must).

## 1. Problem statement

The DAST evaluator (`evalDastCheck` in `scripts/validate-packs.mjs`) reads one
normalised HTTP observation:

```
observation = { url, status, headers, body?, contentType? }   // headers: map<string, string|string[]>
```

Each of the 7 closed check types reads **one header key** (or one body string)
and answers a single boolean:

| check type | reads |
|---|---|
| `http-url` | `observation.url` scheme |
| `missing-response-header` | absence of one header |
| `response-header-missing-directive` | one header's directive list |
| `response-header-matches` | one header's value against one regex |
| `response-body-matches` | `observation.body` (optionally scheme-scoped) |
| `response-header-host-differs` | one redirect header + `observation.url` |
| `cookie-missing-flag` | the `Set-Cookie` value list |

There is no rule-level mechanism to require **two headers to agree**, and the
observation has **no request side** at all. As a result, the following classes
of genuine DAST finding are not expressible today and must not be approximated
with independent single-header rules:

1. **CORS credential/origin correlation** — `Access-Control-Allow-Origin`
   echoes an untrusted origin *and* `Access-Control-Allow-Credentials: true`.
   Each header alone can be legitimate; only the pair is the finding.
2. **Cache + session correlation** — a cacheable response (`Cache-Control`
   without `no-store`/`private`) carrying `Set-Cookie`. Either header alone is
   common and benign.
3. **CSP enforcement correlation** — an enforced `Content-Security-Policy`
   whose directives are weaker than a parallel
   `Content-Security-Policy-Report-Only`. Comparing the two policies requires
   two headers with the same directive vocabulary.
4. **Request/response pairs** — e.g. a state-changing `GET` that also returns
   `Set-Cookie`, or an unauthenticated `TRACE`/`OPTIONS` response. The current
   engine never sees the request method, request headers or request path, so it
   cannot make these judgements and does not claim to.
5. **Redirect-chain reasoning** — `Location` plus the response that follows it.
   The engine sees one response, not a chain; `response-header-host-differs`
   deliberately reports only the single-hop fact.

Writing these as separate single-header rules would be a false claim: two
independent booleans do not establish that the headers were observed on the
same response, and no observation of the request side exists. That is why the
gap is recorded as a schema proposal instead of being worked around.

## 2. Proposal A — `response-headers-correlate` (new check type)

### 2.1 Name and version

- Proposed check type id: `response-headers-correlate`
- Proposed pack schema: `drobon.pack.dast/v2` (additive, opt-in; see §6)
- `check.type` value is the only discriminator; the v2 schema is **not** a
  rename of v1 and v1 files remain valid under the v1 parser.

### 2.2 Closed input schema

```jsonc
{
  "type": "response-headers-correlate",
  "conditions": [                       // required, 2..4 entries
    {
      "header": "Access-Control-Allow-Origin",   // required, HTTP token, 1..64 chars
      "valuePattern": "^\\*$|^https://untrusted\\.example$", // optional, <=500 chars, ReDoS-linted
      "absent": false                            // optional boolean, default false
    }
  ],
  "semantics": "all-headers-on-one-response"     // required, exactly this literal
}
```

Closed-key rules:

- `check` allows only `type`, `conditions`, `semantics`.
- Each condition allows only `header`, `valuePattern`, `absent`.
- `conditions` is required, must contain 2–4 entries, and each `header` must be
  unique after lower-casing (duplicate entries are a validation error, not a
  silent merge).
- At least one condition must carry `valuePattern`; `absent: true` conditions
  may omit it. `absent: true` together with `valuePattern` is a validation
  error (contradictory condition).
- `valuePattern` obeys the same bounds and `lintRedos` contract as v1.
- `semantics` is a closed literal. Unknown values are rejected; there is no
  default because a default would make the intent ambiguous.

### 2.3 Deterministic semantics

Given one normalised observation:

1. Lower-case the header map exactly as `normalizeHeaders` does today.
2. Evaluate each condition against the **same** header map:
   - `absent: false` and no `valuePattern` → true iff the header is present
     (one or more values).
   - `absent: false` with `valuePattern` → true iff at least one value of that
     header matches the regex (case-insensitive, same as v1).
   - `absent: true` → true iff the header is absent.
3. Return `true` iff **every** condition is true; otherwise `false`.
4. Missing/non-object `headers` → all conditions evaluate false; the check
   returns `false` and never throws.
5. One regex is compiled per condition with the `i` flag; no cross-condition
   capture groups, no back-references between conditions, no ordering effects.

There is deliberately no `any`/`not`/`xor` semantics in the first version:
those combinations are difficult to reason about, easy to mis-author and hard
to explain in evidence. `absent` expresses the only negation needed for the
initial families.

### 2.4 Evidence contract

A finding must carry the exact observed header lines that satisfied the
conditions, in the order the conditions are declared, each as
`"<Header-Name>: <value>"` with the header name as declared (not lower-cased
in the evidence string). Every present condition contributes its line; an
`absent: true` condition contributes a declared absence (`"<Header-Name>:
<absent>"`), so a finding always records at least two conditions evaluated on
the same response — which is what distinguishes it from a v1 single-header
match. If the app's finding model cannot store multiple evidence lines, the
check type must not be enabled; truncating to one line would destroy the
correlation proof.

### 2.5 Required tests (before any rule may ship)

- ≥2 positives that satisfy every condition on one response.
- ≥2 negatives where **each condition individually holds on different
  observations** but no single observation satisfies all conditions. This is
  the crucial anti-false-positive test; it must fail if the evaluator is
  implemented as independent single-header checks.
- Boundary: exactly 2 and exactly 4 conditions; duplicate header after case
  folding (must be rejected at schema validation); empty `conditions` array;
  5 conditions (must be rejected); missing `semantics` (rejected).
- Malformed: `headers` missing/null/array; header value `null`; malformed
  regex (rejected at validation); ReDoS-shaped pattern (rejected by lint).
- Contradictory: same header both `absent: true` and present with pattern
  (rejected at validation, and asserted as such).
- Determinism: identical observation evaluated twice gives identical evidence
  order and booleans.
- Adjacent regressions: all v1 check types keep their current results, and v1
  rules are unaffected by the v2 parser.

## 3. Proposal B — `request-response-pair` (new check type + observation extension)

### 3.1 Observation extension (v2 only)

```jsonc
{
  "url": "https://app.example/account/1",
  "status": 200,
  "headers": { "...": "..." },
  "body": "optional",
  "contentType": "optional",
  "request": {                          // optional; absence means "not observed"
    "method": "GET",                    // required inside request
    "path": "/account/1",               // required inside request
    "headers": { "Cookie": ["..."] }    // optional, same header rules as response
  }
}
```

`request` is optional at the observation level. Its absence is **unknown**,
not a negative: a `request-response-pair` check returns `false` and the rule
must report `NOT_ASSESSED` coverage for that observation. It must never be
treated as "no request was made" or as a pass.

### 3.2 Closed input schema

```jsonc
{
  "type": "request-response-pair",
  "request": {                          // required
    "methods": ["GET", "HEAD"],         // required, 1..4 uppercase tokens from a closed enum
    "pathPattern": "^/account/[0-9]+$", // optional, <=500 chars, ReDoS-linted
    "headerPresent": ["Cookie"]         // optional, 0..4 tokens
  },
  "response": {                         // required
    "statusIn": [200, 204],             // optional, 1..8 integers 100..599, unique
    "headerPresent": ["Set-Cookie"]     // optional, 0..4 tokens
  },
  "semantics": "all-request-and-response-conditions"  // required literal
}
```

Closed keys: `check` = `type`, `request`, `response`, `semantics`;
`request` = `methods`, `pathPattern`, `headerPresent`;
`response` = `statusIn`, `headerPresent`. Methods are a closed enum
(`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `TRACE`).
At least one condition across request+response must be present beyond
`methods`, otherwise the rule degenerates to "this method was used".

### 3.3 Deterministic semantics

Return `true` iff `observation.request` exists **and**:

1. the request method is in `methods` (case-sensitive uppercase comparison);
2. if `pathPattern` is present, it matches the request path;
3. every token in `request.headerPresent` exists in `observation.request.headers`;
4. if `statusIn` is present, `observation.status` is a member;
5. every token in `response.headerPresent` exists in `observation.headers`.

Any missing input (no `request`, no `headers`, no `path`) makes the
corresponding condition false; the check never throws. No implicit scope such
as "only authenticated requests" is inferred.

### 3.4 Evidence contract

The finding evidence includes the request line
(`"<METHOD> <path>"`), every matched request header line, and every matched
response header line, preserving declaration order. If `request` is absent,
no finding is produced and the coverage record says `NOT_ASSESSED`; appending
a fabricated request line is a defect.

### 3.5 Required tests

The same matrix as §2.5 plus:

- request present vs absent (absent → `false` + `NOT_ASSESSED`, never a pass);
- method case mismatch (`get` vs `GET`) → no match;
- path pattern boundary (`/account/1` vs `/account/1/` vs `/account/x`);
- `statusIn` boundary (inclusive ends);
- request header present on the request but the same name only on the response
  (must not satisfy the request condition);
- a v2 rule fed to a v1 parser must fail validation loudly, not be skipped.

## 4. Validation rules shared by both proposals

- `schemaVersion` must be `drobon.pack.dast/v2`; a v2 check in a v1 file is an
  error.
- All existing bounds still apply: `MAX_PATTERN` 500, `MAX_HEADER_VALUE` 1000,
  `MAX_HEADERS` 30, `MAX_BODY` 4000, `MAX_TESTS` 50, `MAX_URL` 400.
- `lintRedos` applies to every `valuePattern`/`pathPattern` with no exemption.
- Rule `tests` must still provide 2..50 executable observation tests; for the
  new types those tests must include the negative pairs described above.
- `generate-assets` must not emit v2 cells until the schema flag is enabled;
  the deterministic generator must remain byte-identical for v1 input.

## 5. Compatibility and rollout

1. **No change to v1.** `drobon.pack.dast/v1` keeps its 7 types and its exact
   evaluator semantics. Existing 90 rules and 1,231 evaluation cases must
   produce byte-identical results.
2. **Opt-in version gate.** v2 rules are only accepted when the validator and
   the app loader are both updated; a loader that sees `drobon.pack.dast/v2`
   must refuse the file with a clear error, never partially interpret it.
3. **No silent downgrade.** A v2 correlation check must never be evaluated as
   any v1 type; that would be exactly the simulation this proposal forbids.
4. **App contract.** This Dataset-side change does not integrate anything. The
   Main App loader is absent today (GAP-006 / BLK-006), and this proposal would
   add a second, larger contract for it to implement.
5. **Rollback.** Removing the v2 flag restores v1-only validation; no v1 file
   is rewritten by the rollout.

## 6. Regression protection

- A frozen fixture set of the current 90 DAST rules + 130 DAST evaluation
  cases is the v1 baseline; v2 work must keep it green unchanged.
- The dedup report must stay at `conflictTuples: 0`; a v2 rule that duplicates
  a v1 rule's observable condition is rejected with the canonical id cited.
- `validate-packs.mjs` gains the v2 branch only behind an explicit constant;
  the constant flip is the owner-approved change, reviewed separately.
- `test-packs.mjs` must add a negative control proving a v2 file is rejected
  while the flag is off.

## 7. Owner decision required

Proposed entry in `docs/OWNER_DECISIONS.json` (inserted by the owner, not by
this agent; keys must stay within the existing closed set):

```
subject:              DAST_PACK_V2_CORRELATION
requiredDecision:     "Approve drobon.pack.dast/v2 with exactly the two check
                       types response-headers-correlate and request-response-pair,
                       the closed schemas in docs/DAST_CHECK_TYPE_EXTENSION_PROPOSAL.md,
                       and no other schema change."
status:               OWNER_DECISION_REQUIRED
decidedAt:            null
decider:              null
eligibleScope:        DAST pack schema v2 + validator/evaluator branch; Main App
                       loader still out of scope
```

**If approved:** the schema branch, evaluator, generator support and the full
test matrix in §2.5/§3.5 must be implemented before a single rule is authored;
then a first batch (CORS credentials/origin, cacheable `Set-Cookie`, CSP
enforced-vs-report-only, and request/response method-state pairs) can be
authored with the same asset discipline as v1.

**If refused:** the families above stay recorded as `SCHEMA_BLOCKED` in the gap
matrix and are not counted as rules. No workaround will be attempted.

## 8. What this does not fix

Approving this proposal would not close the 1,000-rule DAST+SCA target and
would not make the Dataset production-ready. The structural ceiling is set by
the closed check vocabulary, the passive single-observation model and the
absence of an App loader; two new check types add a small, bounded set of
genuine families (single digits to low tens), not hundreds of rules. The SCA
rule-pack schema is a separate owner decision
(`docs/SCA_RULE_SCHEMA_PROPOSAL.md`) and remains blocked. Overall verdict for
the Dataset stays **NO-GO**.
