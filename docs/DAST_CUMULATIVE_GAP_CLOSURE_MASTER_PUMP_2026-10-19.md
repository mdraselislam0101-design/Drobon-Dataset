# DROBON AEGIS — DAST cumulative gap-closure master pump (2026-10-19)

**Verdict: the work in this pump is VERIFIED; the Dataset remains NO-GO.**

This pump resolved the 40 record-less patterns at their root cause, accounted
for all 11 UNASSESSED evaluation cases individually, repaired one over-broad
DAST rule that produced false positives on every non-text media type, verified
every earlier DAST repair against the live evaluator, and re-ran the full
verification battery. No DAST v2, parallel engine, duplicate registry or
alternative rule catalogue was created. No commit, push, PR, tag, release or
deployment was made, and the Main App was not touched.

| Field | Value |
|---|---|
| Date | 2026-10-19 |
| Repository | `mdraselislam0101-design/Drobon-Dataset` only |
| Branch | `arena/a4caaeb8-drobon-dataset` |
| HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged, read before and after) |
| Initial git state | 2,362 `M` / 1,942 `??` / 0 `D` |
| Final git state | 2,366 `M` / 1,987 `??` / 0 `D` (default listing, this report counted) |
| Evaluator defects repaired | 1 rule-level (`DPK-DAST-045`) + 1 generator-level (record emission + id allocation) |
| New check types | **0** (closed vocabulary stays at 7) |
| Rules added | **0** |
| Rules changed | **1** (`DPK-DAST-045`, same identity) |
| Records added | **40** (closing the legacy gap; records are not a counted rule category) |
| Evaluation cases added | 3 (`EVAL-DAST-137`…`139`) |
| Overall verdict | **NO-GO** |

## 1. Baseline reconciliation — the brief's figures are one pump stale

The brief's baseline (90 DAST, 1,137 packs, 1,097 records, 1,231 cases, 2,448
corpus, 19,512 assertions, validate-packs 1,140, validate-assets 2,234)
describes the tree **before** the previous iteration. It was re-measured
rather than assumed:

| Metric | Brief claims | Measured at this pump's start | Measured at the end | Method |
|---|---:|---:|---:|---|
| DAST rules | 90 | **91** | 91 | files in `packs/dast/v1/rules` |
| Pack rules | 1,137 | **1,138** | 1,138 | 950 SAST + 97 secrets + 91 DAST |
| Patterns | 1,137 | **1,138** | 1,138 | files in `knowledge/patterns` |
| Records | 1,097 | **1,098** | **1,138** | files in `knowledge/records` |
| Remediation | 1,137 | **1,138** | 1,138 | files in `knowledge/remediation` |
| Evaluation cases | 1,231 | **1,237** | **1,240** | files in `data/eval-cases` |
| Corpus validated total | 2,448 | **2,450** | 2,450 | sum of `CORPUS_TARGETS` categories |
| `npm test` assertions | 19,512 | **19,540** | **19,668** | `ok - ` lines in the full chain |
| `validate-packs` files | 1,140 | **1,141** | 1,141 | 1,138 rules + 3 `pack.json` |
| `validate-assets` files | 2,234 | **2,236** | **2,276** | patterns + records only |
| Eval TP / FP / FN | 1,157 / 1 / 0 | **1,160 / 1 / 0** | **1,161 / 1 / 0** | `run-eval` |
| UNASSESSED | 11 | 11 | 11 | same 11 ids, pinned |
| Git `M` / `??` / `D` | 2,332 / 1,930 / 0 | 2,362 / 1,942 / 0 | 2,366 / 1,987 / 0 | `git status --porcelain` |

The brief's counts were not wrong when written; they are stale by one pump. No
figure in this report is copied from a prior report; every one was recomputed
from files or from the command's own output.

**Validator-count reconciliation (Workstream E).** The three totals measure
different populations and are not contradictory:

- `validate-packs` 1,141 = 1,138 rule files + 3 `packs/*/v1/pack.json` files.
- `validate-assets` 2,276 = 1,138 patterns + 1,138 records (it does not read
  remediation entries).
- `run-eval` 1,240 = evaluation cases, a different population again.

## 2. Workstream A — the 40 record-less patterns, resolved

### 2.1 Root cause (not what the previous reports assumed)

The finding was reported as "40 patterns without a record". Measurement shows
the true shape:

- The 40 orphans are **DPK-PAT-0001…0040**, generated from the 40 hand-written
  **legacy rules** (`DPK-DAST-001…010`, `DPK-SAST-001…022`, `DPK-SEC-001…008`).
- Those 40 rules had **no record at all** (1,138 rules vs 1,098 records — the
  difference is exactly 40), so their patterns had none either.
- Cause: `scripts/generate-assets.mjs` composes patterns for legacy rules in the
  `legacyRules.forEach` block, but records were emitted only from cell jobs in
  `buildFiles`. The legacy path had no record branch. This was a generator
  omission, not a data loss and not a broken link.

### 2.2 Disposition of every one of the 40

Every item is disposition class **1 — valid pattern with a genuinely missing
record**, and every one is now closed. None was deleted, none was renumbered,
none was duplicated.

| # | Pattern | Rule | Record (new) | Status |
|---:|---|---|---|---|
| 1 | DPK-PAT-0001 | DPK-DAST-001 | DPK-REC-1126 | CLOSED |
| 2 | DPK-PAT-0002 | DPK-DAST-002 | DPK-REC-1127 | CLOSED |
| 3 | DPK-PAT-0003 | DPK-DAST-003 | DPK-REC-1128 | CLOSED |
| 4 | DPK-PAT-0004 | DPK-DAST-004 | DPK-REC-1129 | CLOSED |
| 5 | DPK-PAT-0005 | DPK-DAST-005 | DPK-REC-1130 | CLOSED |
| 6 | DPK-PAT-0006 | DPK-DAST-006 | DPK-REC-1131 | CLOSED |
| 7 | DPK-PAT-0007 | DPK-DAST-007 | DPK-REC-1132 | CLOSED |
| 8 | DPK-PAT-0008 | DPK-DAST-008 | DPK-REC-1133 | CLOSED |
| 9 | DPK-PAT-0009 | DPK-DAST-009 | DPK-REC-1134 | CLOSED |
| 10 | DPK-PAT-0010 | DPK-DAST-010 | DPK-REC-1135 | CLOSED |
| 11 | DPK-PAT-0011 | DPK-SAST-001 | DPK-REC-1136 | CLOSED |
| 12 | DPK-PAT-0012 | DPK-SAST-002 | DPK-REC-1137 | CLOSED |
| 13 | DPK-PAT-0013 | DPK-SAST-003 | DPK-REC-1138 | CLOSED |
| 14 | DPK-PAT-0014 | DPK-SAST-004 | DPK-REC-1139 | CLOSED |
| 15 | DPK-PAT-0015 | DPK-SAST-005 | DPK-REC-1140 | CLOSED |
| 16 | DPK-PAT-0016 | DPK-SAST-006 | DPK-REC-1141 | CLOSED |
| 17 | DPK-PAT-0017 | DPK-SAST-007 | DPK-REC-1142 | CLOSED |
| 18 | DPK-PAT-0018 | DPK-SAST-008 | DPK-REC-1143 | CLOSED |
| 19 | DPK-PAT-0019 | DPK-SAST-009 | DPK-REC-1144 | CLOSED |
| 20 | DPK-PAT-0020 | DPK-SAST-010 | DPK-REC-1145 | CLOSED |
| 21 | DPK-PAT-0021 | DPK-SAST-011 | DPK-REC-1146 | CLOSED |
| 22 | DPK-PAT-0022 | DPK-SAST-012 | DPK-REC-1147 | CLOSED |
| 23 | DPK-PAT-0023 | DPK-SAST-013 | DPK-REC-1148 | CLOSED |
| 24 | DPK-PAT-0024 | DPK-SAST-014 | DPK-REC-1149 | CLOSED |
| 25 | DPK-PAT-0025 | DPK-SAST-015 | DPK-REC-1150 | CLOSED |
| 26 | DPK-PAT-0026 | DPK-SAST-016 | DPK-REC-1151 | CLOSED |
| 27 | DPK-PAT-0027 | DPK-SAST-017 | DPK-REC-1152 | CLOSED |
| 28 | DPK-PAT-0028 | DPK-SAST-018 | DPK-REC-1153 | CLOSED |
| 29 | DPK-PAT-0029 | DPK-SAST-019 | DPK-REC-1154 | CLOSED |
| 30 | DPK-PAT-0030 | DPK-SAST-020 | DPK-REC-1155 | CLOSED |
| 31 | DPK-PAT-0031 | DPK-SAST-021 | DPK-REC-1156 | CLOSED |
| 32 | DPK-PAT-0032 | DPK-SAST-022 | DPK-REC-1157 | CLOSED |
| 33 | DPK-PAT-0033 | DPK-SEC-001 | DPK-REC-1158 | CLOSED |
| 34 | DPK-PAT-0034 | DPK-SEC-002 | DPK-REC-1159 | CLOSED |
| 35 | DPK-PAT-0035 | DPK-SEC-003 | DPK-REC-1160 | CLOSED |
| 36 | DPK-PAT-0036 | DPK-SEC-004 | DPK-REC-1161 | CLOSED |
| 37 | DPK-PAT-0037 | DPK-SEC-005 | DPK-REC-1162 | CLOSED |
| 38 | DPK-PAT-0038 | DPK-SEC-006 | DPK-REC-1163 | CLOSED |
| 39 | DPK-PAT-0039 | DPK-SEC-007 | DPK-REC-1164 | CLOSED |
| 40 | DPK-PAT-0040 | DPK-SEC-008 | DPK-REC-1165 | CLOSED |

Remaining exceptions: **0**. Verified independently by the same computation the
originality report uses (`records.relatedPatterns`) and by rule coverage:

```
patterns 1138 records 1138
patterns without record: 0
patterns with >1 record: 0
rules without record: 0
rules with >1 record: 0
```

### 2.3 How it was implemented (existing architecture, no new component type)

1. **Authored bodies, not generated prose.** `data/legacy-record-bodies.json`
   holds 40 hand-written concept bodies (title, description, applicability,
   risk). Each restates that rule's own authored mechanics; nothing was fetched
   or inferred from third-party material. The file sits in `data/` beside
   `osv-seed-packages.json` because `data/asset-cells/*.json` must be arrays of
   cell classes and this is not a cell file.
2. **Generator emits the record.** The legacy branch now composes a
   `drobon.knowledge.record/v1` record per legacy rule with
   `cell: legacy:<ruleId>`, `relatedPatterns: [patId]`,
   `relatedRules: [ruleId]`, `origin: original-authored`,
   `validationStatus: VALIDATED`, and validates it with the same
   `validateRecord` used for every other record. A missing body is **quarantined**
   (the run then refuses to write), never silently skipped.
3. **Stable ids.** The allocated `recId` is persisted in
   `manifest.legacy[]`, so re-runs are byte-identical.
4. **Id-allocation defect fixed (found while doing this).** `nextPat` and
   `nextRec` were seeded only from `manifest.cells`; only *rule* numbers were
   floored at the on-disk maximum. A hand-authored or legacy record with the
   next free id could therefore have been overwritten by the next generated
   cell. Both counters are now floored at the on-disk maximum before allocation.
5. **Regression tests.** Four new `test-assets` assertions make the gap
   impossible to reintroduce: every rule has exactly one record; no rule has
   two; every pattern has exactly one; no pattern has two; `record.cell` equals
   the cell of every related pattern; all 40 legacy manifest entries carry a
   `DPK-REC-nnnn` id. `originality-report` now prints `rules without record`
   alongside `patterns without record`.

Records are **not** a counted corpus category, so this changes no rule count and
no corpus total. It closes an asset-integrity gap, not a metric.

## 3. Workstream B — the 11 UNASSESSED cases, individually

All 11 were enumerated from the current evaluator output (not from memory) and
inspected one by one. `run-eval` emits them under `caseOutcomes.UNASSESSED`.

| Case | Fixture (verbatim) | Why UNASSESSED | Executable today? | Final status |
|---|---|---|---|---|
| EVAL-CMD-023 | `# TODO: avoid \`echo $user\`` | Commented-out command: live code vs dead comment is a policy choice with no ground truth | No detector named; nothing executed | UNASSESSED (verified) |
| EVAL-CMD-024 | `run_cmd(user_input)` | Whether `run_cmd` forwards to a shell is unknowable from the call site | No detector named | UNASSESSED (verified) |
| EVAL-CMD-025 | `bash -c "$user` | Line truncated mid-expression; the rest of the statement is missing | No detector named | UNASSESSED (verified) |
| EVAL-SAST-004 | `cursor.execute(sql)` | Provenance of the prebuilt identifier needs data-flow analysis, which this engine does not have | No detector named | UNASSESSED (verified) |
| EVAL-SAST-007 | commented `os.system("ls " + user_input)` | Same dead-code policy question as CMD-023 | No detector named | UNASSESSED (verified) |
| EVAL-SAST-014 | `cursor.execute(build_sql(user))` | Whether `build_sql` embeds its argument needs callee analysis | No detector named | UNASSESSED (verified) |
| EVAL-SAST-015 | `cursor.execute("… name = '" + user_input` | Truncated: the concatenation's right-hand side is cut off | No detector named | UNASSESSED (verified) |
| EVAL-SAST-016 | `db.records.raw(user + sort)` | Unknown framework contract: `raw()` may parameterise, escape or interpolate | No detector named | UNASSESSED (verified) |
| EVAL-SEC-111 | `url = "https://api:v1Beta2rcX@host.internal/"` | A version-like token and a weak password are lexically identical | No detector named | UNASSESSED (verified) |
| EVAL-SQL-027 | `rows, err := db.Query(buildQuery(user))` | Callee semantics unknown (Go) | No detector named | UNASSESSED (verified) |
| EVAL-SQL-028 | `rows, err := db.Query("… name = '" + user` | Truncated mid-expression (Go) | No detector named | UNASSESSED (verified) |

### 3.1 What was and was not done

A scan of every SAST/secrets regex over each fixture showed which detectors
*would* match if they were named (for example `DPK-SAST-475` matches the
commented shell expansion; `DPK-SEC-108` matches the userinfo password).
That made it tempting to attach `forbiddenDetections` and turn each case into a
passing "detector stays silent" test. **That was deliberately not done**, for
two reasons:

1. It would convert a documented *limitation* into an asserted *expectation*:
   `db.Query(buildQuery(user))` should ideally be caught; asserting silence
   would freeze the blind spot as correct behaviour.
2. Deciding whether commented-out code is a finding is a policy the repository
   has never adopted. Inventing it here would be exactly the "change the
   expected outcome without evidence" the brief forbids.

So the cases stay UNASSESSED, and the ambiguity is now **pinned** so it cannot
drift: `test-eval` asserts the UNASSESSED population is exactly those 11 ids
(sorted), that each contributes 0 TP / 0 FP / 0 FN, and that none executes a
detector. Result: **11 accounted for, 0 converted, 0 silently dropped**.

## 4. Workstream C — the seven check types and a real rule defect

### 4.1 The closed vocabulary (read from the implementation, not assumed)

`DAST_CHECK_TYPES` in `scripts/validate-packs.mjs` contains exactly:

1. `http-url`
2. `missing-response-header`
3. `response-header-missing-directive`
4. `response-header-matches`
5. `response-body-matches`
6. `response-header-host-differs`
7. `cookie-missing-flag`

No check type was added or removed by this pump.

### 4.2 Defect repaired — `DPK-DAST-045` (charset-less Content-Type)

**Measured before the repair** (live evaluator, current rule):

```
045 -> true   {"Content-Type":"application/json"}
045 -> true   {"Content-Type":"image/png"}
045 -> true   {"Content-Type":"application/javascript"}
045 -> true   {"Content-Type":"text/css"}
045 -> true   {}                       ← no Content-Type at all
```

The rule used `response-header-missing-directive` (`Content-Type`/`charset`),
which fires for *any* media type without a charset parameter and for an absent
header (already covered by `DPK-DAST-074`). That is an over-broad rule producing
false positives on JSON APIs, images, JavaScript and CSS:

- RFC 8259 defines JSON as UTF-8 and forbids adding a charset parameter;
- RFC 9239 makes charset obsolete for JavaScript;
- `text/css` is UTF-8 by definition;
- binary types have no charset parameter at all.

**Repair (same rule id, same assets):**

```json
{ "type": "response-header-matches",
  "header": "Content-Type",
  "valuePattern": "^(?:text/html|text/plain)(?!.*\\bcharset\\b)" }
```

**Measured after the repair:**

```
true   text/html          false  text/html; charset=utf-8     false  application/json
true   text/plain         false  text/html;charset=UTF-8      false  image/png
true   TEXT/HTML          false  text/css                     false  application/javascript
                               absent header -> false (DPK-DAST-074 owns that case)
```

The rule now reports only the two media types whose decoding genuinely depends
on a declared charset. Description, limitation, remediation, record text and
risk were rewritten through the existing per-cell `overrides` mechanism to state
the media-type scope explicitly.

Tests: 8 executable observation tests (3 positive, 5 negative), plus evaluation
cases `EVAL-DAST-137` (JSON must not fire; also asserts `074` stays silent),
`EVAL-DAST-138` (PNG must not fire) and `EVAL-DAST-139` (upper-case `TEXT/HTML`
fires). `EVAL-DAST-012`, `-013` and `-002` (which forbids 045 on a
charset-bearing page) still pass unchanged.

### 4.3 Earlier repairs re-verified against the live evaluator

A 28-assertion probe re-tested every previously repaired behaviour on the
current tree; **28/28 passed**:

| Area | Probe | Result |
|---|---|---|
| CSP wildcard token boundaries | `default-src *`, `* data:`, `https://*.example.com` (must not match) for 022/070/086/092 | PASS |
| `SameSite=None` order independence | `Secure` before and after `SameSite=None`; missing `Secure` | PASS |
| RFC 7230 OWS | `Access-Control-Expose-Headers: " * "`, `ACAO: " * "`, padded `nosniff` | PASS |
| Protocol-relative userinfo | `//user:pass@host` matches 085, `//cdn/x` does not | PASS |
| Quoted/unquoted mixed content | 055 and 080 both forms; https negative | PASS |
| COEP `credentialless` | 046 fires only on `unsafe-none`; `credentialless`/`require-corp`/absent are negatives | PASS |
| Severity consistency | 022/070/086/092 all MEDIUM (DAST mix: 50 MEDIUM / 41 LOW) | PASS |

No earlier fix was reverted or weakened.

### 4.4 One confirmed defect left open (owner-gated)

`DPK-DAST-050` (`^//` on `Location`) still reports same-host scheme-relative
redirects, and every true positive it produces is already produced by
`DPK-DAST-056`, which compares resolved hostnames. A single-header check cannot
express "different host", so the only honest fixes are retirement or a rewrite —
both permanent id/asset decisions. Unchanged, and reported as
**BLOCKED_PENDING_OWNER_DECISION** (carried forward from the previous report).

## 5. Workstream D — correlation and request/response pairs stay blocked

- `docs/OWNER_DECISIONS.json` contains **no** DAST entry (3 top-level keys,
  schema `drobon.corpus.decisions/v1`; byte hash unchanged at
  `a359d3f5…d49b`). No approval exists, so nothing was enabled.
- `docs/DAST_CORRELATION_EXTENSION_PROPOSAL.md` and
  `docs/DAST_CHECK_TYPE_EXTENSION_PROPOSAL.md` are both still marked
  `BLOCKED_PENDING_OWNER_DECISION`; the older document keeps its
  "superseded framing, valid analysis" note. Neither was deleted or rewritten.
- The evaluator still reads one observation and one header per check. No
  single-header rule was added to imitate correlation. The blocked families
  (CORS origin + credentials, cacheable `Set-Cookie`, CSP enforced vs
  report-only, request/response pairs) are unchanged.
- Safe fallback in the meantime: the single-observation checks continue to
  report each observable condition separately, which is exactly what they claim
  to do.

## 6. Workstream E — integrity, provenance and counts

| Check | Command | Result |
|---|---|---|
| Pack/schema validation | `node scripts/validate-packs.mjs packs` | PASS — 1,141 files, 0 errors |
| Pattern/record validation | `node scripts/validate-assets.mjs` | PASS — 2,276 files, 0 errors |
| Coverage report | `node scripts/coverage-report.mjs --check` | PASS |
| Inventory | `node scripts/inventory.mjs --check` | matches the tree |
| Duplicate/canonicalisation | `node scripts/dedup-report.mjs` | 100 files / 84 items / 9 tuples / **0 conflicts** |
| Originality | `node scripts/originality-report.mjs --check` | PASS; `patterns without record: 0; rules without record: 0` |
| Independent eval coverage | `node scripts/eval-coverage-report.mjs` | **1,138/1,138** rules (DAST 91/91) |

Additional integrity findings verified rather than assumed:

- **No duplicate records**: 1:1 rule↔record and pattern↔record in both
  directions (new assertions).
- **No malformed provenance**: every new record is `origin: original-authored`,
  `validationStatus: VALIDATED`, `cell: legacy:<ruleId>`; the generator's own
  `validateRecord` gate ran before writing.
- **No production data added**: the only new files are one authored body file,
  one changed rule, three evaluation cases and this report.
- **No stale report presented as current**: no historical report was edited;
  this is a new file.
- **No metric inflation**: DAST rules stayed at 91; the record growth is an
  asset-integrity repair in an uncounted category.

## 7. Workstream F — SCA, rights and Main App remain separate blockers

| Item | Evidence | Status |
|---|---|---|
| SCA rule packs | `find packs -path '*sca*' -name '*.json'` → **0** | UNCHANGED / BLOCKED |
| LICENSE | `ls LICENSE` → no such file | BLOCKED (invariant preserved) |
| `docs/OWNER_DECISIONS.json` | no git status/diff entry; hash unchanged | UNCHANGED |
| Main App | no App checkout was present in this session and no command was run against it; no loader, migration, dependency or production data touched | NOT TOUCHED |
| App ingestion readiness | still no consumer of `packs/dast` in the App | BLOCKED |
| Third-party permission | no claim made; the D-ORIG owner statement is not treated as a redistribution grant | NOT CLAIMED |

## 8. Full test results (exact commands, observed outcomes)

| # | Command | Observed result |
|---:|---|---|
| 1 | `node scripts/test-packs.mjs` | PASS — 4,734/4,734 |
| 2 | `node scripts/test-assets.mjs` | PASS — 9,122/9,122 (was 8,996; +126 from the new record assertions) |
| 3 | `node scripts/test-eval.mjs` | PASS — 43/43 (was 41; +2 UNASSESSED pins) |
| 4 | `node scripts/test-consistency.mjs` | PASS — 222/222 |
| 5 | `node scripts/test-doc-drift.mjs` | PASS — 119/119 |
| 6 | `node scripts/test-current-state.mjs` | PASS — 153/153 |
| 7 | `node scripts/generate-assets.mjs` | PASS — written 4,505, removed 0, quarantined 0; patterns 1,138, records 1,138 |
| 8 | `node scripts/validate-packs.mjs packs` | PASS — 1,141 files, 0 errors |
| 9 | `node scripts/validate-assets.mjs` | PASS — 2,276 files, 0 errors |
| 10 | `node scripts/coverage-report.mjs --check` | PASS |
| 11 | `node scripts/inventory.mjs --check` | matches the tree |
| 12 | `node scripts/dedup-report.mjs` | 0 conflicts |
| 13 | `node scripts/originality-report.mjs --check` | PASS (one pre-existing repeated-remediation advisory) |
| 14 | `node scripts/eval-coverage-report.mjs` | 1,138/1,138 rules; 1,240 cases |
| 15 | `node scripts/run-eval.mjs` (run per changed case first, then full) | 1,240 cases; TP 1,161 / FP 1 / FN 0; 1 FAIL; 11 UNASSESSED |
| 16 | `npm test` | **exit 0 — 19,668 assertions**, all 18 sub-suites PASS |
| 17 | determinism (inside `npm test`) | 5/5 PASS — regenerated file sets identical, every file byte-identical |

Sub-suite detail for #16: tests 600, pack 4,734, audience 3,458, asset 9,122,
consistency 222, rehearsal 78, importer 49, agent-policy 91, agent-workflows 57,
finding-evidence 31, secret-candidates 35, sca-engine 38, sca-fixtures 177,
eval 43, doc-drift 119, current-state 153, final 656, determinism 5.

**Not run:** no lint/typecheck/build target exists in this repository
(`package.json` defines none); no check is reported as PASS without output
above.

## 9. Metrics, with definitions

| Metric | Value | Definition |
|---|---:|---|
| Cases total | 1,240 | files in `data/eval-cases` |
| Assessed | 1,229 | `groundTruth.state === 'ASSESSED'` |
| UNASSESSED | 11 | `groundTruth.state === 'UNASSESSED'`; excluded from every denominator |
| TP | 1,161 | expected detection matched with the declared evidence substring |
| FP | 1 | a detection on an ASSESSED no-issue case that was not credited |
| FN | 0 | expected detection not produced (or produced without the exact evidence) |
| FAIL cases | 1 | `EVAL-SAST-008` — pre-existing documented false positive, preserved |
| DAST-only TP | 99 | over 130 DAST cases; 0 FP, 0 FN in that population |
| DAST rules exercised | 91/91 | every DAST rule appears in at least one case |

`EVAL-SAST-008` was **not** repaired: it is a SAST over-match outside this
pump's scope, and its failure is the honest evidence of that defect. It is not
counted as a pass. The 11 UNASSESSED cases are not counted as passes either.

## 10. Files changed by this pump

New:

- `data/legacy-record-bodies.json` (40 authored concept bodies)
- `knowledge/records/DPK-REC-1126.json` … `DPK-REC-1165.json` (40 records)
- `data/eval-cases/EVAL-DAST-137.json`, `-138.json`, `-139.json`
- `docs/DAST_CUMULATIVE_GAP_CLOSURE_MASTER_PUMP_2026-10-19.md` (this report)

Modified:

- `scripts/generate-assets.mjs` — legacy record emission, `recId` persistence,
  on-disk id floors, missing-body quarantine
- `scripts/test-assets.mjs` — 4 new record-coverage assertion groups
- `scripts/test-eval.mjs` — UNASSESSED population pin + TP pin 1,161
- `scripts/originality-report.mjs` — `rulesWithoutRecord` coverage field
- `data/asset-cells/dast-2.json` — `charset-less Content-Type` cell rewritten
- `packs/dast/v1/rules/DPK-DAST-045.json` and its pattern, record and
  remediation (regenerated from the cell)
- `docs/PACKS.md` — Batch 13 entry
- `docs/AUDIENCES.md`, `docs/CORPUS_GAP_REPORT.md`,
  `docs/REQUIREMENTS_MATRIX.json`, `docs/COVERAGE_MAP.json`,
  `docs/CURRENT_INVENTORY.json`, `docs/CAPABILITY_COVERAGE_MATRIX.json` +
  rendered `.md`, `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md`,
  `scripts/test-doc-drift.mjs`, `scripts/test-current-state.mjs` — count pins
- `data/asset-cells/.manifest.json` — legacy `recId`s, regenerated file list

No historical report was overwritten. No prior work was reverted.

## 11. Git state

- Branch: `arena/a4caaeb8-drobon-dataset`
- HEAD: `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged before and after)
- Initial: 2,362 `M` / 1,942 `??` / 0 `D`
- Final: 2,366 `M` / 1,987 `??` / 0 `D` (default listing); with
  `--untracked-files=all` the same tree expands to 1,997 untracked files
- `git diff --stat`: 2,366 files changed, 6,996 insertions, 3,658 deletions — all
  line-level edits inside preserved files; no file deleted, renamed or rewritten
  wholesale.
- Upstream: no push, fetch or remote ref update was performed; HEAD still equals
  the branch point of `main`.
- A full-tree manifest with size and SHA-256 per file was written to
  `/tmp/manifest-pump5.json`. It is a verification artifact only: `/tmp` is not
  durable and the file is not a repository asset.

## 12. Remaining blockers

| ID | Blocker | Status |
|---|---|---|
| `BLK-001` | No LICENSE grant for original content | BLOCKED |
| `BLK-002` / `GATE-1…4` | Per-source redistribution / production lock | BLOCKED |
| SCA pack schema | No approved schema; SCA packs remain **0** | BLOCKED |
| `DAST_CORRELATION_CHECK_TYPES` | Two correlation types need owner approval | BLOCKED_PENDING_OWNER_DECISION |
| `DPK-DAST-050` | Over-broad `^//`: retire with `056` canonical, or re-scope | BLOCKED_PENDING_OWNER_DECISION |
| `GAP-005/006` | Main App has no consumer of `packs/dast` | BLOCKED |
| `GAP-AEGIS-01` | SAST 950 vs the 1,000 planning target | OPEN |
| `GAP-AEGIS-07` | 11 UNASSESSED cases (policy/dataflow decisions) | PARTIALLY_VERIFIED — pinned |
| `GAP-AEGIS-08` | 40 record-less patterns | **CLOSED by this pump** |
| `GAP-AEGIS-09` | DAST vocabulary closed at 7 types | BLOCKED |
| `GAP-AEGIS-10` | 239 unreachable SAST rules | OPEN |
| TARGET-1000 | DAST + SCA = 91 + 0 = **9.1%** | NOT MET |

## 13. Unresolved discrepancies

- The brief's baseline was one pump stale (§1). Reconciled by measurement, not
  by editing the brief's figures anywhere.
- `DPK-DAST-050` remains a known false-positive source by owner decision, not
  by oversight (§4.4).
- The 11 UNASSESSED cases remain genuinely ambiguous rather than repairable
  without a dataflow engine or a new comment policy (§3.1).
- No claim of live-target testing, active probing or real-world exploitability
  is made anywhere: every fixture here is a synthetic observation object.

## 14. Verdict

**VERIFIED:** the 40-record gap closed at its root cause (0 remaining, 1:1 in
both directions, four regression assertions); the 11 UNASSESSED cases
individually accounted for and pinned; the `DPK-DAST-045` repair with before and
after evidence; all 28 earlier-repair probes; all validators; the 19,668-
assertion suite; determinism; the count reconciliation.

**PARTIALLY_VERIFIED:** aggregate evaluation health — one preserved SAST false
positive and 11 pinned UNASSESSED cases remain.

**BLOCKED:** `DPK-DAST-050`, the correlation/request-response check types, SCA
packs, license and rights gates, App integration, the 1,000 target.

**NOT_IMPLEMENTED:** any new check type, any SCA pack, any `.env` rule (no path
or media-type scope), any comment-policy verdict.

**NOT_ASSESSED:** live-site behaviour, TLS handshake properties,
authorization/IDOR semantics, and the 11 preserved UNASSESSED cases.

**Overall Dataset verdict: NO-GO.** Local DAST work is verified, but the
release gates (LICENSE, rights, SCA schema, App integration) are untouched by
this pump and remain open. A green suite is not a GO.

## 15. Next priority-ordered tasks

1. Owner decision on `DPK-DAST-050` (retire with `DPK-DAST-056` canonical, or
   re-scope).
2. Owner decision on `docs/DAST_CORRELATION_EXTENSION_PROPOSAL.md`; if approved,
   implement the validator/evaluator branch and its full negative matrix before
   authoring a correlation rule.
3. Owner decision on `docs/SCA_RULE_SCHEMA_PROPOSAL.md`; SCA stays 0 until then.
4. Decide the two UNASSESSED policy classes explicitly (commented-out code,
   version-like tokens) if the owner wants them scored; otherwise keep them
   pinned as ambiguous.
5. Re-verify the Main App contract in a session where that repository is
   actually available, before any claim of integration readiness.
