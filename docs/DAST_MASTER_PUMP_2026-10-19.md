# DROBON AEGIS — DAST master pump (2026-10-19)

**Verdict: DAST completion for this pump is VERIFIED for the three rules added
and the one rule corrected; the Dataset as a whole remains NO-GO.**
No commit, push, tag, release or deployment was made, and no Main App file was
read into the corpus or modified.

| Field | Value |
|---|---|
| Date | 2026-10-19 |
| Branch | `arena/a4caaeb8-drobon-dataset` |
| HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged) |
| Repository | `mdraselislam0101-design/Drobon-Dataset` only |
| Main App | read-only contract facts only; not modified, not bundled |
| New rules | 3 (`DPK-DAST-092`…`094`) |
| Corrected rule | 1 (`DPK-DAST-024`, same id) |
| Final DAST count | **89** (started at 86; the brief's 68/68 baseline was unverified) |
| Overall verdict | **NO-GO** |

## 1. Executive summary

The pump did four things, all additively:

1. **Corrected a real detection defect** in `DPK-DAST-024` (HSTS `max-age`).
   The old pattern `max-age\s*=\s*[0-9]{1,7}` used *digit count* as a proxy for
   duration, so `max-age=10000000` (115 days) was treated as strong while
   `max-age=3153599` (one second short of a year) was flagged weak. The cell now
   matches numeric values strictly below 31,536,000. The rule id, tests and
   history are preserved; only the cell/pattern payload changed.
2. **Added three genuinely distinct DAST rules** using the existing 7 closed
   check types: CSP `frame-ancestors` standalone wildcard (092), plaintext
   `http:` source inside `script-src` (093), and `Refresh` header redirect to an
   absolute/protocol-relative target (094).
3. **Added evaluation coverage** for every new rule: 6 cases
   (`EVAL-DAST-116`…`121`), one positive and one forbidden-detection negative
   per rule. All six pass on first execution.
4. **Recorded the structural ceiling and a schema gate**: two families that
   cannot be expressed with one header / one observation (CORS credentials
   correlation, request/response pairs) are now documented in
   `docs/DAST_CHECK_TYPE_EXTENSION_PROPOSAL.md` as
   **BLOCKED_PENDING_OWNER_DECISION**. No new check type was enabled, and no
   single-header rule was used to simulate correlation.

The stated DAST+SCA target of 1,000 rules is **not met** (89 DAST + 0 SCA).
This pump did not attempt to close it by padding: 89 is the verified count, and
§8 explains why data authoring alone cannot reach 1,000 under the current
schema.

## 2. Phase A — baseline, independently recalculated

Baseline was measured from the working tree before any edit, not copied from a
prior report. `git` values were read with `git rev-parse` / `git status`.

| Metric | Baseline | Final | Definition |
|---|---:|---:|---|
| Branch | `arena/a4caaeb8-drobon-dataset` | same | `git rev-parse --abbrev-ref HEAD` |
| HEAD | `ed599c6…` | same | `git rev-parse HEAD` |
| Tracked modifications | 2,315 `M` | 2,317 `M` | `git status --porcelain` prefix ` M` |
| Untracked files | 1,893 `??` | 1,914 `??` | prefix `??` (includes prior pumps + 21 this pump) |
| Deleted files | 0 | 0 | no `D` entries |
| DAST rules | 86 | **89** | one JSON file in `packs/dast/v1/rules` |
| DAST rule ids | `DPK-DAST-001…091` (86 used) | `…094` (89 used) | unique ids, no recycle |
| Pack rules (all) | 1,133 | **1,136** | SAST 950 + secrets 97 + DAST 89 |
| Patterns | 1,133 | **1,136** | one file per rule for DAST |
| Records | 1,093 | **1,096** | 40 legacy patterns remain record-less (pre-existing) |
| Remediation | 1,133 | **1,136** | exactly one per pack rule |
| CWE entries | 63 | 63 | unchanged |
| DAST check types | 7 | **7** | closed vocabulary, no new type |
| DAST categories | 12 | 12 | no new category |
| Eval cases | 1,216 | **1,222** | one manifest per case |
| DAST eval cases | 115 | **121** | 80 positive / 41 negative |
| Generator input cells | 928 SAST / 89 secrets / 76 DAST | 928 / 89 / 79 | **cells, not rules**; never quoted as inventory |

Baseline DAST check-type histogram and its final value:

| Check type | Baseline | Final |
|---|---:|---:|
| `http-url` | 1 | 1 |
| `missing-response-header` | 16 | 16 |
| `response-header-missing-directive` | 12 | 12 |
| `cookie-missing-flag` | 3 | 3 |
| `response-header-matches` | 34 | **37** |
| `response-body-matches` | 19 | 19 |
| `response-header-host-differs` | 1 | 1 |
| **Total** | **86** | **89** |

The generator's `dast: 79` input-cell count is not the rule count: one cell can
emit more than one rule (and 79 cells currently emit 89 rules). Inventory is
always recomputed from `packs/**/v1/rules/*.json`, never from the generator
manifest.

### 2.1 How a DAST rule becomes executable

Verified by reading the implementation, not inferred:

1. A **cell** in `data/asset-cells/dast*.json` declares title, description,
   severity, CWE, category, remediation text, a closed `check` object and ≥2
   executable observation tests.
2. `scripts/generate-assets.mjs` validates the cell, runs `lintRedos` on every
   pattern, writes one rule file in `packs/dast/v1/rules/`, one pattern in
   `knowledge/patterns/`, one record in `knowledge/records/` and one remediation
   entry. It also runs the key-shape leak pre-screen so secret-shaped fixtures
   cannot enter `packs/dast`.
3. `scripts/validate-packs.mjs` enforces the closed schema:
   `check.type` must be one of the 7 types, `check` keys are closed per type,
   header names must be HTTP tokens, patterns are bounded to 500 chars and
   ReDoS-linted, observations are closed (`url`, `status`, `headers`, `body`,
   `contentType`) and each rule must carry 2–50 tests.
4. `evalDastCheck(check, observation)` is a pure function over one normalized
   observation. Missing headers, malformed URLs, absent bodies and unparseable
   redirect targets evaluate `false` and never throw.
5. `scripts/test-packs.mjs` executes each rule's `tests`, and
   `scripts/validate-assets.mjs` cross-checks rule ↔ pattern ↔ record ↔
   remediation linkage.
6. `data/eval-cases/EVAL-DAST-*.json` exercises the same evaluator through
   `scripts/run-eval.mjs`, with expected detections and forbidden detections.
7. `scripts/test-doc-drift.mjs`, `test-consistency.mjs` and
   `scripts/inventory.mjs` recompute every published count from the tree.

A rule therefore counts only when it is unique, schema-valid, pattern-linked,
evidence-backed by executable tests, and exercised by evaluation. Nothing in
this pump was counted on the strength of a plan.

### 2.2 Semantic duplicate audit

- **DAST signature comparison:** all 89 rules were grouped by normalized
  `check.type + header/directive/flag + valuePattern`. Result: **0 duplicate
  signatures and 0 duplicate titles**; 89 unique ids, 0 rules without a
  pattern, 0 rules without remediation.
- **Dedup tool:** `node scripts/dedup-report.mjs` → 100 advisory files,
  84 identity items, 9 multi-file tuples, **0 conflict tuples**. Advisory shards
  share identity by design and were not counted as rules.
- **Near-neighbour review of the new rules** (all rejected as duplicates):
  - `frame-ancestors` value vs `DPK-DAST-010` (directive missing) — different
    observation: absent directive vs present wildcard. Kept distinct.
  - `script-src http:` vs `DPK-DAST-070` (script-src `*`), `DPK-DAST-002`
    (header missing), `DPK-DAST-021`/`061` (keyword sinks), `DPK-DAST-072`
    (report-only header) — different evidence. Kept distinct.
  - `Refresh url=` vs `DPK-DAST-050`/`056`/`085` (all read `Location`) — a
    different header. Kept distinct.
- **Rejected as cosmetic variants:** `style-src *` (same check/shape as
  `DPK-DAST-070`, directive substitution), `img-src http:` (same shape as 093,
  lower-signal directive), a second `frame-ancestors` rule repeating 010,
  `Location: http://` downgrade (already covered by `DPK-DAST-050`/`001`
  families), and extra database-dialect error rules (`DPK-DAST-062` matches the
  dialects already).
- **Legacy record gap:** 40 patterns have no record file. This is a
  pre-existing, documented retention decision; this pump did not fabricate
  records to close it.

## 3. Phase B — genuine gap matrix and dispositions

Scope inspected: HSTS/security headers, CSP semantics and directive
relations, CORS, cookies, redirects, cache-control, information disclosure,
framework misconfiguration, request/response pairs, authorization context, TLS
application configuration, and API misconfiguration.

| Candidate | Observation needed | Disposition | Evidence |
|---|---|---|---|
| CSP `frame-ancestors` standalone wildcard | one CSP header value | **IMPLEMENTED** `DPK-DAST-092` | 4 rule tests + `EVAL-DAST-116/117`; scoped host wildcard is a negative |
| Plaintext `http:` source in `script-src` | one CSP header value | **IMPLEMENTED** `DPK-DAST-093` | 4 tests + `EVAL-DAST-118/119`; https-only and `img-src http:` negatives |
| Redirect via `Refresh` header | one `Refresh` value | **IMPLEMENTED** `DPK-DAST-094` | 4 tests + `EVAL-DAST-120/121`; relative target negative |
| HSTS `max-age` duration | one STS value | **CORRECTED** `DPK-DAST-024` | value threshold < 31,536,000; 7 tests; no id change |
| CORS origin + credentials correlation | two headers on one response | **SCHEMA_BLOCKED** | proposal §2; no rule authored |
| Cacheable response + `Set-Cookie` | two headers on one response | **SCHEMA_BLOCKED** | proposal §2 |
| Enforced CSP vs report-only CSP | two headers + directive comparison | **SCHEMA_BLOCKED** | proposal §2 |
| Request method + response behaviour (state-changing GET, TRACE/OPTIONS) | request line + response | **SCHEMA_BLOCKED** | proposal §3; engine never sees a request |
| Redirect chain reasoning | multiple responses | **SCHEMA_BLOCKED** | one observation only; `056` reports the single hop |
| Active OPTIONS/TRACE probing | a live request | **OUT_OF_SCOPE** | the engine is passive; sending requests was never authorized or implemented |
| TLS version/cipher assessment | TLS handshake metadata | **NOT_ASSESSABLE** | HTTP observation carries no handshake fields; no fake TLS finding authored |
| Authorization/IDOR reasoning | identity, roles, object ownership | **NOT_ASSESSABLE** | no request/session context; not claimed |
| `style-src *`, `img-src http:`, extra DB dialects | same shape as existing rules | **REJECTED_DUPLICATE** | canonical ids cited above |
| Missing optional directives (`sandbox`, etc.) | absence of a directive | **REJECTED_SPECULATIVE** | absence is not a defect without a deployment contract |

No candidate was accepted merely to increase a number; no candidate was
silently dropped from the table.

## 4. Phase C — schema inspection and decision

The schema was inspected before any extension was considered. Two facts are
load-bearing:

1. `DAST_CHECK_TYPES` is a closed array of exactly 7 strings; `checkDastCheck`
   rejects anything else. Every existing type reads **one** header key (or one
   body), and `evalDastCheck` receives **one** observation.
2. The observation object has no request side: only `url`, `status`, `headers`,
   `body`, `contentType`.

Consequently the correlation and request/response families cannot be
implemented, and were not approximated. A full backward-compatible proposal
was written instead:
`docs/DAST_CHECK_TYPE_EXTENSION_PROPOSAL.md`.

- Proposed types: `response-headers-correlate` and `request-response-pair`.
- Proposed schema: `drobon.pack.dast/v2`, opt-in, closed keys, deterministic
  semantics, evidence requiring all correlated lines, unsupported observation
  → `false` + `NOT_ASSESSED`, never a pass.
- Status: **BLOCKED_PENDING_OWNER_DECISION**. No v2 file, type, rule, pattern,
  record, remediation entry or evaluation case exists on disk.
- The proposal also states explicitly that approving it would **not** close the
  1,000-rule target.

## 5. Phase D — assets added (all original, all additive)

| Rule | Title | CWE / severity | Category | Check | Tests | Pattern / record / remediation | Eval |
|---|---|---|---|---|---:|---|---|
| `DPK-DAST-092` | CSP `frame-ancestors` allows every origin | CWE-693 / MEDIUM | `csp-weakness` | `response-header-matches` on CSP | 4 (2 pos, 2 neg) | `DPK-PAT-1161` / `DPK-REC-1121` / `DPK-DAST-092` | `EVAL-DAST-116`, `117` |
| `DPK-DAST-093` | CSP `script-src` allows plaintext HTTP origins | CWE-319 / MEDIUM | `csp-weakness` | `response-header-matches` on CSP | 4 (2 pos, 2 neg) | `DPK-PAT-1162` / `DPK-REC-1122` / `DPK-DAST-093` | `EVAL-DAST-118`, `119` |
| `DPK-DAST-094` | `Refresh` header redirects to an absolute URL | CWE-601 / LOW | `open-redirect` | `response-header-matches` on `Refresh` | 4 (2 pos, 2 neg) | `DPK-PAT-1163` / `DPK-REC-1123` / `DPK-DAST-094` | `EVAL-DAST-120`, `121` |

Asset discipline:

- Every new rule carries `limitation`, `fpNotes` (pattern), `whyItMatters` +
  actions + verification (remediation), and provenance
  `origin: original-authored`, `validationStatus: VALIDATED`.
- Every new pattern has 4 executable examples; every new rule has 4 observation
  tests; every evaluation fixture is `synthetic: true`, `testOnly: true`, and labelled
  `"synthetic test fixture - NOT vulnerability intelligence"`.
- ReDoS rewrites: the first drafts of the `Refresh` and `script-src` patterns
  were quarantined by `lintRedos` ("nested quantifier"). The lint was **not**
  relaxed. Both patterns were rewritten to alternation/lookahead forms and
  verified on 8 observations before generation.
- `generate-assets` final run: `written 4459`, `removed 0`,
  `quarantined []`, counts `sast 928 / secrets 89 / dast 79` cells,
  `patterns 1136 / records 1096 / remediation 1096` (generator scope; the tree
  holds 1,136 remediation files because every pack rule has one).
- HSTS correction detail: `max-age=3153599` → match; `31536000` → no match;
  `10000000` → match (115 days is genuinely below one year); `9999999` → match;
  `63072000` → no match.

Boundary and malformed coverage:

- 092 pins a bare `*`, `'self' *`, and the negative scoped host wildcard
  `https://*.example.com`.
- 093 pins `http:` at end-of-policy and an `http://` host source; `https://`
  and `img-src http:` are negatives.
- 094 pins `url=https://…`, uppercase `URL='//…'`, a delay-only value and a
  response with no `Refresh` header.
- Each rule carries 2 negatives inside its own test array: 092 uses a scoped
  host wildcard and `frame-ancestors 'self'`; 093 uses an HTTPS-only source and
  a different directive; 094 uses a delay-only `Refresh` and an absent header.
  Missing-evidence totality is enforced evaluator-wide: `test-packs` feeds 6
  malformed shapes (no headers, null headers, array headers, no body,
  unparseable URL, non-string URL) through 8 check instances, asserting
  never-throws and boolean results. A single-header check has no
  contradictory-evidence state; contradiction only becomes possible under the
  proposed v2 correlation schema, where it is rejected at validation.
- Adjacent-rule regression: the full 89-rule suite re-ran (pack-tests 4,710
  assertions, 0 failed). `DPK-DAST-024` is the only rule whose payload changed;
  its 7 tests are green. No other rule file was edited.

## 6. Phase E/F — verification and regression results

Commands were executed; results are pasted from the run, not projected.

| Check | Result |
|---|---|
| `node /tmp/probe5.mjs` (pattern semantics before generation) | 8/8 observations correct, `lint` null for both |
| `node scripts/generate-assets.mjs` | written 4,459 · removed 0 · quarantined `[]` |
| `node scripts/validate-packs.mjs packs` | **PASS (1,139 files, 0 errors)** |
| `node scripts/validate-assets.mjs` | PASS (2,232 files = 1,136 patterns + 1,096 records, 0 errors) |
| `node scripts/validate-audiences.mjs` | PASS (1,147 files, 0 errors) |
| `node scripts/validate-cwe.mjs knowledge/cwe` | PASS (63 files, 0 errors) |
| `node scripts/validate-corpus.mjs` | PASS (3 files, 0 errors) |
| `node scripts/validate-matrix.mjs …` | PASS (inventory recomputed, no license file) |
| `node scripts/test-consistency.mjs` | PASS (222/222) |
| `node scripts/test-doc-drift.mjs` | PASS (119/119) |
| `node scripts/test-current-state.mjs` | PASS (153/153) |
| `node scripts/test-eval.mjs` | PASS (41/41) |
| `node scripts/validate-capability-coverage.mjs` | PASS (656/656) |
| `node scripts/coverage-report.mjs --check` | PASS |
| `node scripts/dedup-report.mjs` | conflictTuples **0** |
| `node scripts/originality-report.mjs --check` | 0 rules without pattern; 40 legacy record-less patterns (pre-existing) |
| `node scripts/manifest.mjs --scope all --write/--check` | PASS (6,026 files verified — final tree including this report) |
| `node scripts/inventory.mjs --check` | CURRENT_INVENTORY matches tree |
| `node scripts/render-capability-coverage.mjs` | matrix up to date |
| `npm test` | **exit 0** — 18 suites, **19,494 assertions**, 0 failed |
| `npm run test:determinism` | 5/5; whole-tree digest `f7500f5e6f00…` |

Suite deltas versus the last closed pump (19,449 → 19,494, +45):
packs 4,698 → 4,710 (+12 = 3 rules × 4 tests);
assets 8,956 → 8,980 (+24 = 3 patterns with 4 examples each + 3 records +
3 remediation entries);
audiences 3,443 → 3,452 (+9 = the 3 new remediation entries in audience
linkage/pack counts);
all other suites unchanged. No assertion was deleted, skipped, weakened or
rewritten to obtain a green result; the only test edits were count pins whose
values legitimately changed (listed in §10).

Evaluation through `run-eval`:

| Metric | Baseline | Final |
|---|---:|---:|
| Cases | 1,216 | **1,222** |
| DAST cases | 115 (77 pos / 38 neg) | **121 (80 pos / 41 neg)** |
| True positives | 1,148 | **1,151** |
| False negatives | 0 | 0 |
| False positives | 1 | 1 |
| Preserved FAIL | `EVAL-SAST-008` | `EVAL-SAST-008` (unchanged) |
| UNASSESSED (never scored) | 11 | 11 |
| DAST rules with positive coverage | 86/86 | **89/89** |
| DAST rules with an explicit eval-level negative pair | 58 | **61** |

Case-variant mix (all 1,222 cases): 813 positive, 369 negative, 21 boundary,
10 near-miss, 9 mutation. The 6 new cases are 3 positive and 3 negative, one of
each per new rule.

`EVAL-SAST-008` is the deliberately preserved false positive: the SAST rule
matches line 2 as well as line 3, and the case stays red rather than being
"fixed" by weakening the expectation. Precision on the assessed synthetic
population is `1151 / 1152 = 0.99913`; recall is 1.0 **only for this synthetic
assessed population** and is not a universal detection claim. The 11
UNASSESSED cases remain outside the score, and their limitations are unchanged.

## 7. Phase G — metrics with definitions

| Metric | Value | How it is computed |
|---|---:|---|
| Unique pack rules | **1,136** | JSON files in `packs/{sast,secrets,dast}/v1/rules`; ids unique |
| — SAST | 950 | id prefix `DPK-SAST-` |
| — secrets | 97 | id prefix `DPK-SEC-` |
| — DAST | **89** | id prefix `DPK-DAST-` |
| DAST executable / blocked | 89 / 0 | all schema-valid and evaluable on an observation |
| DAST check types | 7 | closed enum, unchanged |
| DAST categories | 12 | rule `category` field |
| Distinct DAST CWEs | 15 | rule `cwe` field |
| DAST eval coverage | 89/89 positive | rule appears in ≥1 positive case's `expected.detections` |
| DAST eval negative pairs | 61/89 | rule also appears in ≥1 negative case's `forbiddenDetections` |
| Pack-level negative tests | ≥1 positive + ≥1 negative per rule; the 3 new rules carry 2+2 | rule `tests` array, executed by `test-packs` |
| Patterns | **1,136** | files in `knowledge/patterns`; 1 per pack rule |
| Records | **1,096** | files in `knowledge/records`; 40 legacy patterns have none |
| Remediation | **1,136** | files in `knowledge/remediation`, keyed by `ruleId` |
| Provenance | 100% new assets `original-authored` | asset `origin` field + eval `provenance` |
| Duplicate signatures | 0 | normalized check signature grouping |
| Dedup conflict tuples | 0 | `dedup-report.mjs` |
| Tests | exit 0, 19,494 assertions | `npm test` |
| Inventory / coverage | match tree | `inventory --check`, `coverage-report --check` |
| Owner decisions changed | 0 | `docs/OWNER_DECISIONS.json` untouched |
| License file | absent | no LICENSE created |
| App isolation | intact | no Main App edit, no loader claimed |
| Git writes | none | HEAD unchanged; 0 deletions |

Terminology is deliberate: 1,136 **rules**, 1,136 **patterns**, 1,096
**records**, 1,136 **remediation entries**. Patterns and remediation are not
called rules.

## 8. Structural ceiling and the 1,000 target

The DAST+SCA target of 1,000 rules is **NOT MET**:

- DAST: **89**
- SCA rule packs: **0** (`packs/sca/` is empty; the SCA pack schema is a
  separate owner decision)
- Total: **89 / 1,000 = 8.9%**

This is not a scheduling shortfall that more of the same authoring would fix.
The current DAST vocabulary is 7 check types, each reading exactly one header
or one body from exactly one observation. Genuine distinct rules are bounded by
the number of meaningful header/directive/value families that exist, not by the
number of strings a pattern can match. Splitting a directive, adding cosmetic
title variants or re-labelling the same signal would inflate the count while
reducing detection quality, so none of that was done.

The two proposed check types (`response-headers-correlate`,
`request-response-pair`) would add a bounded set of genuine families
(single digits to low tens), not hundreds. Even with owner approval, the 1,000
target would still be unmet. SCA contributes 0 until its pack schema is
approved. The honest conclusion is: **DAST is locally complete for the
implemented vocabulary; the 1,000 target requires a different structural
decision, and is out of scope for data authoring alone.**

## 9. Phase H — blockers (visible, not hidden)

| ID / gate | Exact reason | Affected capability | What can continue | Minimal decision | Consequence of approve / refuse |
|---|---|---|---|---|---|
| `BLK-001` | No LICENSE grant for original dataset content | Production use of any asset | Local verification only | Owner license decision | Approve: rights gate advances; refuse: assets remain non-production |
| `BLK-002` / `GATE-1…3` | Per-source redistribution / production lock not authorized | Advisory records, production ingestion | Synthetic fixtures and static checks | Owner/production authorization | Approve: ingestion gates can be planned; refuse: status quo |
| `BLK-004` | Approval expiry / re-review cadence undecided | Corpus refresh | none needed for this pump | Owner cadence decision | Approve: refresh schedule; refuse: no refresh |
| SCA pack schema | No approved schema for SCA rule packs | SCA rules (0 today) | SCA engine contract tests only | Owner schema decision (`docs/SCA_RULE_SCHEMA_PROPOSAL.md`) | Approve: SCA authoring may start; refuse: SCA stays 0 |
| **DAST v2 proposal** (new, not registered) | Correlation / request-response need a new closed check type and observation field | CORS credentials, cache + `Set-Cookie`, CSP enforced-vs-report-only, request/response pairs | The 7-type v1 corpus and all current tests | Owner decision on `docs/DAST_CHECK_TYPE_EXTENSION_PROPOSAL.md` | Approve: schema/validator work may begin (not automatic); refuse: families stay `SCHEMA_BLOCKED` |
| App loader absent (`GAP-005/006`) | Main App has no consumer of `packs/dast` | Delivery of any DAST rule to users | Dataset-side validation | App-side loader decision, outside this repo | Approve: integration work; refuse: dataset remains unconsumed |
| SAST gap | 950 SAST rules vs 1,000 target | SAST breadth | Existing rules | Separate SAST pump | Not closed here |
| 11 UNASSESSED eval cases | Fixtures cannot establish the required context | Eval completeness | Preserved as UNASSESSED | Case-by-case assessment design | Must not be counted as passes |
| 40 legacy patterns without records | Retention decision open | Record coverage | Existing 1,096 records | Owner retention decision | No records were fabricated |

This report makes no claim of live-site testing, active probing, exploitability,
commercial parity, or production readiness. It also does not claim that DAST
completion is Dataset completion.

## 10. Phase I — changed files, count pins and git state

New files (21): 3 rules, 3 patterns, 3 records, 3 remediation entries, 6 eval
cases, 1 asset cell (`data/asset-cells/dast-11.json`), 1 proposal, this report.
Modified files this pump:

- Assets: `data/asset-cells/dast.json` (`hsts-short` cell only; `DPK-DAST-024`
  payload), plus generated assets listed above.
- Count/matrix pins: `README.md`, `docs/PACKS.md` (Batch 10),
  `docs/AUDIENCES.md`, `docs/CAPABILITY_COVERAGE.md`,
  `docs/CAPABILITY_GAP_MATRIX.md`, `docs/CORPUS_GAP_REPORT.md`,
  `docs/CORPUS_TARGETS.json` (validated total 2,440 → 2,446),
  `docs/REQUIREMENTS_MATRIX.json`, `docs/COVERAGE_MAP.json`,
  `docs/CAPABILITY_COVERAGE_MATRIX.json` + rendered `.md`,
  `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md`,
  `docs/SCA_RULE_SCHEMA_PROPOSAL.md`, `docs/CURRENT_INVENTORY.json`.
- Test pins (legitimate count changes only): `scripts/test-doc-drift.mjs`
  (86/1,133/1,093 → 89/1,136/1,096), `scripts/test-current-state.mjs`
  (same counts), `scripts/test-eval.mjs` (TP 1,148 → 1,151).

Historical reports were not edited:
`docs/ULTIMATE_TOTAL_GAP_CLOSURE_MASTER_PUMP_2026-10-19.md`,
`docs/NEXT_MASTER_PUMP_SAST_EVALUATION_SCA_GAP_CLOSURE_2026-10-19.md`,
`docs/EVAL_ID_CAPACITY_AND_FINAL_GAP_CLOSURE_2026-10-19.md`,
`docs/DAST_SCA_GAP_CLOSURE_MASTER_PUMP_2026-10-19.md`,
`docs/CUMULATIVE_GAP_CLOSURE_DAST_SCA_2026-10-19.md`.

Classification of the worktree:

- **Pre-existing (prior pumps):** 2,315 tracked modifications and 1,893
  untracked files present at baseline; preserved untouched.
- **This pump:** +2 net tracked modifications and +21 untracked files;
  0 deletions, 0 renames, 0 history rewrites.
- Final `git status --porcelain`: **2,317 `M` / 1,914 `??` / 0 `D`**,
  HEAD `ed599c654e972cf517331bb504d65f3e8c2dbcf1`, branch unchanged.

## 11. Verdict and prioritised next steps

**VERIFIED:** the 3 new rules and their 6 evaluation cases; the HSTS
correction; all pack/asset/eval/schema/count validations; `npm test` exit 0
with 19,494 assertions; determinism.

**BLOCKED:** the two correlation/request-response families
(`BLOCKED_PENDING_OWNER_DECISION`), SCA rule packs, production/license gates,
and App integration.

**NOT IMPLEMENTED:** any v2 check type, any SCA pack, any active probing.

**NOT ASSESSED:** TLS handshake properties, authorization/IDOR semantics, and
the 11 preserved UNASSESSED evaluation cases.

Prioritised next steps (all require separate authorization):

1. Owner decision on `docs/DAST_CHECK_TYPE_EXTENSION_PROPOSAL.md`; if
   approved, implement the validator/evaluator branch and the full negative
   matrix before authoring a single v2 rule.
2. Owner decision on `docs/SCA_RULE_SCHEMA_PROPOSAL.md`; SCA remains 0 until
   then.
3. Keep the 7-type v1 corpus frozen as the regression baseline for any v2 work.
4. Resolve the 40-pattern record gap and the 11 UNASSESSED cases through
   explicit decisions, not by lowering evidence standards.
5. Do not pursue the 1,000 target by authoring cosmetic variants; revisit the
   target itself or the schema scope with the owner.

**Overall Dataset verdict: NO-GO.** This pump closes DAST work it can verify;
it does not close the Dataset, the rights gates, or the structural ceiling.
