# AEGIS MASTER PUMP 2 — evaluation ID capacity, 75-rule closure, SAST gap, release blockers (2026-10-19)

**Scope:** Dataset repository only. Main App read-only. No production data, no advisory feeds,
no licence action, no git writes. All new fixtures are synthetic and `testOnly`.

| Field | Value |
|---|---|
| Repository | `mdraselislam0101-design/Drobon-Dataset` |
| Branch | `arena/a4caaeb8-drobon-dataset` |
| Start HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` |
| End HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged; no git writes) |
| Worktree at start | 2,315 modified · 1,662 untracked · 0 deleted |
| Worktree at end | 2,315 modified · 1,805 untracked · 0 deleted (includes this report) |
| `LICENSE` | absent (BLK-001 invariant preserved) |
| Main App | `c32c797a549453802bd6d82c5673d2a1728457a3`, read-only, untouched |

---

## A. Verified starting baseline and Git state

Recomputed from the tree before editing (not copied from prose):

| Metric | Baseline |
|---|---|
| SAST rules | 950 |
| Eval cases | 1,046 (1,035 assessed · 11 UNASSESSED) |
| TP / FP / FN | 1,067 / 1 / 0 |
| Rules with a positive eval | 1,044 total · 875 SAST |
| SAST rules with an explicit negative pair | 162 |
| Uncovered SAST rules | 75 (45 HIGH · 30 MEDIUM) |
| SCA | 0 packs · 8 synthetic corpora · 26 capabilities / 206 assertions |
| CWE | 63 entries, `cweVersion` 4.20 |
| `npm test` | 19,230 assertions, exit 0 (verified at start of this pump) |
| Git | HEAD `ed599c6`, 2,315 `M` / 1,662 `??` / 0 `D` |

The baseline was re-derived from the tree and cross-checked against the evaluator report
produced at the close of the previous pump (1,046 cases, TP 1,067 / FP 1 / FN 0). No
pre-existing change was reverted.

---

## B. Evaluation ID namespace audit and exact capacity

### B.1 Canonical format and validator

* Schema `drobon.eval.case/v1`; identifier rule enforced in `scripts/eval-foundation.mjs:72`:
  `^EVAL-[A-Z]+-[0-9]{3}$` — three digits, `001`–`999`, per-domain prefix (`EVAL-SAST-`,
  `EVAL-SEC-`, `EVAL-DAST-`, …). Uniqueness is enforced by `loadCases` (duplicate ids are a
  manifest error and the runner exits 2 without producing a report).
* The format is part of the case schema, not a convention: widening it is a schema change.

### B.2 Inventory (SAST domain)

| Quantity | Value |
|---|---|
| SAST cases on disk | 655 |
| Highest allocated id | EVAL-SAST-853 (baseline) |
| Free numbers in 001–999 | **344** |
| Retired ids that must not be recycled | 546, 580, 669, 670, 671, 673, 674, 757, 784, 789, 811, 812 (12) |
| **Usable free capacity before this pump** | **332** |
| Capacity claim in the previous report | “146 free slots (next free 854)” |

**Correction of the prior claim.** 146 was the count of free ids *above the previous maximum
854 only*. The namespace is not compact: ids 256–471 were never allocated, so the actual free
capacity inside the validated `001–999` range was **344**, or **332** after excluding the 12
retired ids. The previous report's statement “needs either a shared-negative design or an
id-scheme owner decision” was therefore based on an undercount; no schema decision was ever
required for 150 cases.

### B.3 Capacity required

| Requirement | Count |
|---|---|
| Uncovered SAST rules | 75 |
| Rules that can carry a ≥4-character evidence token | 67 |
| Rules whose maximal regex match is 2–3 characters (cannot satisfy `mustContain >= 4`) | 8 |
| Cases authored | 67 positive + 75 negative = **142** |

The 8 structurally short patterns are listed in §E.3. They are a property of the detectors
(e.g. `<%=`, `{!!`, `#$`), not of the fixtures.

### B.4 Allocation actually used

| Band | Ids | Count |
|---|---|---|
| 854–899 | EVAL-SAST-854 … 899 | 46 |
| 901–996 | EVAL-SAST-901 … 996 | 96 |
| Reserved, unused | EVAL-SAST-900 | 1 (in-memory validator self-check in `test-eval.mjs`) |
| **Total allocated** | | **142** |

Remaining after this pump: **202 free numbers**, **190 usable** after exclusions, plus
997–999 still unused. No historical id was recycled; no retired id was used; no schema,
validator, manifest or generator change was required.

---

## C. Owner decision required before schema/namespace changes

**None for this pump.** The existing approved namespace absorbed the full requirement with
190 usable ids to spare.

The only schema-adjacent item discovered is **not** an id-capacity issue: 8 detectors match
2–3 characters, while the schema requires `expected.detections[].mustContain` to be **≥4
characters and a substring of the matched text**. Those 8 rules cannot be positively
evaluated without an approved change to the evidence contract (options: allow a 3-character
token when the full match is shorter, or add a longer contextual pattern to the detector).
Both options change validation or detection semantics and were **not** implemented; the
decision is recorded in §J (BLK-EVAL-01) and §M.

---

## D. Complete uncovered-rule inventory and prioritisation

Baseline uncovered set (75), reconciled against the rule files rather than filenames:
code-injection 12, XSS 8, SQL-injection 7, unsafe-deserialization 5, command-injection 4,
secure-configuration 4, transport-security 4, CI-security 3, permissions 3, path-traversal 3,
cleartext-transmission 3, deserialization 2, weak-cryptography 2, sensitive-logging 2, SSRF 2,
access-control 2, denial-of-service 2, memory-safety 1, CSRF 1, mass-assignment 1,
hardcoded-credential 1, template-injection 1, container-security 1, XXE 1.

All 75 were dispositioned:

| Disposition | Rules | Detail |
|---|---|---|
| Positive + negative cases added | **67** | §E.1 |
| Negative case added, positive blocked by the evidence contract | **8** | §E.3 |
| Unsupported / unreachable / untestable | **0** | no rule in the uncovered set was unreachable to the evaluator |

**Residual uncovered (8):** DPK-SAST-416, 417, 418, 423, 424, 731 (XSS template output),
678 (PowerShell `& $var`), 692 (Scala `#$` splice). Severity: 2 HIGH (678, 692), 6 MEDIUM.

---

## E. Evaluation cases added, executed, rejected or blocked

### E.1 Added and executed

| Cohort | Cases | Rule mapping |
|---|---|---|
| `sast-gap-closure-2026-10-19` | **142** | 67 positive (1 per newly covered rule, asserted at an exact line and evidence substring) + 75 negative (`forbiddenDetections` on the safe counterpart) |

Each positive fixture places the construct in 3–5 lines of context; the expected line is
computed from the actual regex match (never hand-numbered) and the evidence token is taken
from the matched text. Each negative fixture uses the safe API or hardened setting the rule
documents. Only the rules named by a case are executed for that case, so a fixture cannot
mask an unrelated detector.

Execution: `node scripts/run-eval.mjs` — **exit 0, 1,188/1,188 cases produced a report;
1,177 assessed; 1,176 PASS; 1 FAIL (the preserved EVAL-SAST-008 false positive); 11
UNASSESSED.**

Failure/fix log (all fixture defects, never expectation weakening):
1. `cohort` label exceeded 32 characters → renamed to `sast-gap-closure-2026-10-19`.
2. One `mustContain` was 3 characters (`@v4`) → replaced with `checkout@v4`.
3. 31 positive cases had off-by-one line numbers → recomputed from the actual regex match.
4. Two evidence tokens (`danger_accept_invalid_certs(true)`, `:erlang.binary_to_term(`) were
   not substrings of the matched text → corrected to the exact match text and line.
   No expected rule, severity or ground-truth class was changed to obtain a pass.

### E.2 Rejected

| Candidate | Reason |
|---|---|
| Splitting one case across several rules to save ids | Not needed (332 usable ids) and would couple unrelated ground truths |
| Reusing the 12 retired ids | Prohibited; uniqueness history preserved |
| Positive cases for the 8 short-pattern rules using a fabricated ≥4-char token | Would misreport evidence; blocked instead |

### E.3 Blocked — exact technical reason

| Rule | Pattern | Maximal match | Evidence requirement |
|---|---|---|---|
| DPK-SAST-416 | `\{!!` | 3 (`{!!`) | ≥4 |
| DPK-SAST-417 | `<%-` | 3 | ≥4 |
| DPK-SAST-418 | `\{\{\{` | 3 | ≥4 |
| DPK-SAST-423 | `<%=` | 3 | ≥4 |
| DPK-SAST-424 | `!=\s*[a-zA-Z_$]` | 3 | ≥4 |
| DPK-SAST-678 | `&\s+\$` | 3 | ≥4 |
| DPK-SAST-692 | `#\$` | 2 | ≥4 |
| DPK-SAST-731 | `<%=` | 3 | ≥4 |

These 8 keep **negative coverage only**; their positive coverage is blocked by the schema
constraint, not by missing fixtures.

---

## F. Rule-level and case-level coverage before and after

| Metric | Before | After | Δ |
|---|---|---|---|
| Cases total | 1,046 | **1,188** | +142 |
| Assessed | 1,035 | **1,177** | +142 |
| UNASSESSED (excluded from every rate) | 11 | **11** | 0 |
| Cases with positive expectations | 729 | **796** | +67 |
| Negative-control cases | 285 | **360** | +75 |
| Distinct rules with positive expectations (all domains) | 1,044 | **1,111** | +67 |
| SAST rules with positive coverage | 875 / 950 (92.1 %) | **942 / 950 (99.16 %)** | +67 |
| SAST rules with an explicit negative pair | 162 | **237** | +75 |
| SAST rules with **both** | 162 | **229** | +67 |
| SAST rules with negative-only coverage | 0 | **8** | +8 |
| SAST rules with positive-only coverage | 713 | **713** | 0 |
| SAST rules uncovered (no positive) | **75** | **8** | −67 |
| SAST rules *named* by some case (positive ∪ forbidden) | 875 | **950** | +75 |
| All-domain rule coverage (positive) | 1,044 / 1,119 (93.3 %) | **1,111 / 1,119 (99.3 %)** | +67 |

**Metric discipline.** `scripts/eval-coverage-report.mjs` prints `sast: 950/950 (100 %)`
because it counts rules named in `detections ∪ forbiddenDetections`. That is *named*
coverage, not positive coverage. The positive rule-level figure in this report is
**942/950 (99.16 %)**; the 8 gap rules are reported as uncovered, not as covered by their
negative cases. Case counts are never presented as rule coverage.

Per-severity coverage: HIGH 487/489 (2 uncovered), MEDIUM 370/376 (6 uncovered),
LOW 85/85. Per-family coverage after closure (exercised/total): weak-cryptography 105/105,
secure-configuration 90/90, code-injection 85/85, service-token 85/85, command-injection
74/74, SQL-injection 70/70.

---

## G. TP/FP/FN and precision/recall

| Metric | Value | Formula / denominator |
|---|---|---|
| True positives | **1,134** | expectations met across 1,177 assessed cases |
| False positives | **1** | detections at lines the ground truth declares clean (EVAL-SAST-008) |
| False negatives | **0** | declared detections not produced |
| Precision | **0.99912** | TP / (TP + FP) = 1,134 / 1,135 |
| Recall | **1.0** | TP / (TP + FN) = 1,134 / 1,134 |
| TN | not modelled | the evaluator scores expectations, not a full confusion matrix; negative-control cases act as the safe side (360 cases, 0 forbidden detections) |

Recall 1.0 is true only for this assessed synthetic population; it is **not** evidence of
universal detection and no such claim is made. The single false positive is the preserved
`EVAL-SAST-008` docstring trap (DPK-SAST-283); it was not relabelled, skipped or weakened.

---

## H. SAST additions, duplicate analysis and the remaining 1,000-rule gap

**Rules added this pump: 0. SAST remains 950.**

A structured probe was run before deciding, because the objective is capability coverage, not
a quota:

| Candidate | Result | Evidence |
|---|---|---|
| `InsecureSkipVerify`, `rejectUnauthorized`, `CURLOPT_SSL_VERIFYPEER`, `DEBUG =`, `csrf`, `android:exported`, `usesCleartextTraffic` | Already covered | DPK-SAST-353, 355, 357, 015/079/834, 073/074/278/437, 187, 188 |
| `exec.Command("sh","-c")` (Go) | Near-duplicate | DPK-SAST-914 already matches exactly; 042 covers the generic call |
| `NoopHostnameVerifier` / `setHostnameVerifier` (Java) | Near-duplicate | DPK-SAST-719 and 867 cover the trust/verifier family |
| `postMessage(..., "*")` (JS) | Already covered | DPK-SAST-558 |
| `text/template` HTML rendering (Go), `WKWebView.loadHTMLString` (Swift) | Rejected | No stable line-level signal; FP-heavy generic sinks, no distinguishable unsafe variant |
| sshd `PermitRootLogin`, `PasswordAuthentication`; Kubernetes `privileged`/`hostNetwork`; systemd `sh -c`; Terraform `acl = "public-read"`; nginx `autoindex`; Redis `protected-mode no`; MongoDB `bind_ip 0.0.0.0` | Not authored | All target families the Main App catalog does not analyse (`UNSUPPORTED` or absent). Adding them would raise the unreachable count (currently 239) without any runtime detection path — rejected under the pump's own reachability criterion |

Duplicate/near-duplicate checks: no new signal keys; `generate-assets` unchanged
(`quarantined: []`, `removed: 0`); `dedup-report` 0 conflicting tuples; `originality --check`
exit 0 with the pre-existing advisory review lines only.

**Residual gap: 950 / 1,000 — 50 rules.** This is a capability gap in *reachable* families,
not an authoring backlog that can be padded. It stays PARTIAL; the honest options are an App
catalog expansion (GAP-AEGIS-10) or an owner decision to accept config-family rules that the
runtime cannot consume.

---

## I. SCA contract regression (Pump D)

| Check | Result |
|---|---|
| `test-sca-fixtures` | **168 passed, 0 failed** across 8 synthetic corpora |
| `test-sca-engine` | **38 passed, 0 failed** |
| Coverage surface | **26 capabilities / 206 assertions**, 0 failed |
| Ecosystem identity | npm and pypi `shared-name` remain distinct nodes; edge keeps its declared ecosystem |
| Ambiguous aliases | unresolved, fail-closed; ecosystem-scoped resolution proven |
| Duplicate edges | collapse deterministically without erasing distinct versions/scopes |
| Conflict reporting | deterministic (`npm:shared-name [1.0.0, 2.0.0]`) |
| `packs/sca/` | still empty — no fabricated production content |
| Production data | 84 seed items, `verifiedProductionCount` 0; no network access in the engine |

---

## J. Remaining blockers and evidence

| ID | Blocker | Type | Evidence | Status |
|---|---|---|---|---|
| BLK-001 | No LICENSE | Legal | no `LICENSE`, no grant inferred | BLOCKED |
| GATE-1…4 | No rights-cleared advisory source | Rights | 84 seeds / 0 production, `BLOCKED_LICENSE_REVIEW` | BLOCKED |
| BLK-EVAL-01 | 8 rules match <4 characters; evidence contract requires ≥4 | Schema/design | §E.3 table; validator `mustContain >= 4` | **NEW — decision required** |
| GAP-AEGIS-02 | 8 SAST rules without positive eval | Technical (bounded by BLK-EVAL-01) | 942/950 positive; 950/950 named | PARTIAL |
| GAP-AEGIS-01 | SAST 950 vs 1,000 | Capability | §H probe; 0 genuine reachable candidates | PARTIAL |
| GAP-AEGIS-03 | SCA rule packs 0 | Owner schema | `packs/sca` empty; proposal unchanged | BLOCKED |
| GAP-AEGIS-06 | App loader absent | External workstream | Main App `c32c797` read-only; no loader observed | BLOCKED |
| GAP-AEGIS-07 | 11 UNASSESSED cases | Editorial | preserved unchanged; never scored | BLOCKED |
| GAP-AEGIS-08 | 40 legacy patterns without records; D-13 | Owner | `originality`: 40; D-13 inactive | BLOCKED |
| GAP-AEGIS-09 | DAST vocabulary closed at 7 check types | Schema | 72/72 evaluated, no new check type | BLOCKED |
| GAP-AEGIS-10 | 239 rules unreachable by the App catalog | App workstream | fully 671 / partial 29 / unreachable 239 / universal 11 | BLOCKED |

Tests passing does not resolve any blocked row; each has an owner, rights or integration
dependency named above.

---

## K. Commands, exit codes and test totals

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `node scripts/run-eval.mjs` | 0 | 1,188 cases · TP 1,134 · FP 1 · FN 0 · 11 UNASSESSED |
| 2 | `node scripts/test-eval.mjs` | 0 | 41 passed, 0 failed (TP pin updated 1067 → 1134 after recomputation) |
| 3 | `node scripts/validate-packs.mjs` | 0 | PASS (1,122 files, 0 errors) |
| 4 | `node scripts/validate-assets.mjs` | 0 | PASS (2,198 files, 0 errors) |
| 5 | `node scripts/validate-audiences.mjs` | 0 | PASS (1,130 files, 0 errors) |
| 6 | `node scripts/validate-cwe.mjs` | 0 | PASS (63 files, 0 errors) |
| 7 | `node scripts/test-packs.mjs` | 0 | 4,642 / 4,642 |
| 8 | `node scripts/test-sca-fixtures.mjs` | 0 | 168 passed, 0 failed |
| 9 | `node scripts/test-sca-engine.mjs` | 0 | 38 passed, 0 failed |
| 10 | `node scripts/test-consistency.mjs` | 0 | 222 / 222 |
| 11 | `node scripts/test-doc-drift.mjs` | 0 | 119 passed, 0 failed |
| 12 | `node scripts/test-current-state.mjs` | 0 | 153 passed, 0 failed |
| 13 | `node scripts/coverage-report.mjs --check` | 0 | PASS |
| 14 | `node scripts/inventory.mjs --check` | 0 | matches the tree |
| 15 | `node scripts/manifest.mjs --scope all` | 0 | written, no errors |
| 16 | `node scripts/originality-report.mjs --check` | 0 | PASS (1,188 cases / 1,119 rules named) |
| 17 | `node scripts/eval-coverage-report.mjs` | 0 | named coverage 1,119/1,119; positive 1,111 |
| 18 | `npm test` | **0** | **19,230 assertions**, 18 suites |

`npm test` suites: core 600 · packs 4,642 · audiences 3,401 · assets 8,844 · consistency 222 ·
rehearsal 78 · importers 49 · agent-policy 91 · agent-workflows 57 · finding-evidence 31 ·
secret-candidates 35 · sca-engine 38 · sca-fixtures 168 · eval 41 · doc-drift 119 ·
current-state 153 · capability-coverage 656 · determinism 5.

No test was skipped, deleted or weakened. The only test edit was the documented TP pin
(1067 → 1134), re-derived from the evaluator output before editing.

---

## L. Reconciled inventory and documentation

| Artifact | Change |
|---|---|
| `data/eval-cases/` | +142 cases (`EVAL-SAST-854…899`, `901…996`), cohort `sast-gap-closure-2026-10-19` |
| `docs/CAPABILITY_COVERAGE_MATRIX.md` | 1,046 → 1,188 cases; 1,044 → 1,111 rules; SAST 875 → 942 |
| `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md` | same reconciliation |
| `docs/CAPABILITY_COVERAGE.md` | re-rendered from the matrix |
| `docs/CURRENT_INVENTORY.json` | regenerated; `inventory --check` green |
| `docs/NEXT_MASTER_PUMP_…_2026-10-19.md` | **not modified** — historical; its 146-slot capacity statement is superseded and corrected in §B.2 of this report |
| Rule packs, patterns, records, remediation, CWE, SCA | unchanged (950 / 1,119 / 1,079 / 1,119 / 63 / 0 packs) |

All other historical reports are byte-for-byte preserved.

---

## M. Remaining risks and exact next authorised action

| Risk | Impact | Mitigation / next step |
|---|---|---|
| BLK-EVAL-01: 8 rules cannot meet the ≥4-char evidence contract | 0.84 % of SAST rules have no positive eval | Owner decision: (a) allow the full match as evidence when it is shorter than 4 chars, or (b) extend those 8 patterns with context, or (c) accept as a permanent documented limitation |
| Positive coverage is one fixture per rule for 1,097 rules | Breadth is proven; depth is not | Future pumps: second positive per high-impact rule, framework variants |
| 50-rule SAST gap | Target not met | App catalog expansion or explicit acceptance of config-family rules; do not pad |
| 239 unreachable rules | Dataset value not realised at runtime | App workstream; no Dataset-side fix |
| `eval-coverage-report` prints 100 % (named) | Could be misread as positive coverage | This report states both figures; tool text unchanged |

**Exact next authorised action:** obtain the owner decision on BLK-EVAL-01. If option (a) or
(b) is approved, author the 8 positive cases (ids available: EVAL-SAST-997 … 999 plus the
256–471 block) and re-run the evaluator. No other Dataset change is authorised by this
report.

---

## N. Release decision

**NO-GO.**

| Gate | Result |
|---|---|
| Executable suite | PASS (19,230 assertions, exit 0) |
| ID uniqueness / capacity | PASS (142 ids allocated; 0 duplicates; 190 usable free) |
| Evaluation coverage | PARTIAL (942/950 positive; 8 blocked by evidence contract) |
| SAST target 1,000 | NOT MET (950; 50 short, capability-bound) |
| Provenance / originality | PASS (0 production records; advisory review lines only) |
| SCA determinism / fail-closed | PASS |
| Licence / rights | BLOCKED (BLK-001, GATE-1…4) |
| Owner decisions (SCA packs, D-13, DAST vocabulary) | BLOCKED |
| App integration | BLOCKED (no loader; read-only inspection only) |

The pump is technically complete — the 75-rule gap is dispositioned with executed evidence —
while the product remains NO-GO for the reasons above.
