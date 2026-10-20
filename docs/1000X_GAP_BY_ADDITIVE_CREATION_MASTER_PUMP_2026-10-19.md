# Drobon Dataset — ULTIMATE MASTER PUMP (cumulative additive creation)

**Date:** 2026-10-19 · **Repository:** `mdraselislam0101-design/Drobon-Dataset` · **Branch:** `arena/a4caaeb8-drobon-dataset` · **HEAD:** `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged) · **Working tree:** uncommitted, preserved (no git write authorized) · **Node:** v22.22.3

This document is the final deliverable for the ULTIMATE master pump. It supersedes the presentation of `docs/1000X_GAP_BY_ADDITIVE_CREATION_MASTER_PUMP_2026-10-19.md` while **preserving the complete previous report as Appendix P** (its sections 1–16 and every table remain byte-for-byte below). Sections A–M below are the current, evidence-backed state.

No LICENSE exists. No production data, advisory feed, paid catalog, credential, or third-party rule corpus was added. The Main App repository was not modified.

---

## A. Executive summary

The pump continued from the real repository state and added two evidence-complete batches on top of the three 1000× batches:

| Family | Pump start | Final | Delta | Notes |
|---|---:|---:|---:|---|
| SAST rules | 841 | **853** | +12 | rules 852–857 (batch 4), 858–863 (batch 5) |
| DAST rules | 68 | **70** | +2 | rules 074–075 (batch 4) |
| Pack rules total | 1,006 | **1,020** | +14 | SAST + secrets 97 + DAST |
| Patterns / records / remediation | 1,006 / 966 / 1,006 | **1,020 / 980 / 1,020** | +14 each | one pattern, record and remediation entry per new rule |
| CWE knowledge entries | 61 | **61** | 0 | no new CWE ids were invented; CWE-693 already existed |
| Independent eval cases | 296 | **324** | +28 | 14 positive + 14 negative controls, all authored before first run |
| Assessed / UNASSESSED | 285 / 11 | **313 / 11** | +28 / 0 | UNASSESSED preserved, never relabelled |
| Eval TP / FP / FN | 199 / 1 / 0 | **213 / 1 / 0** | +14 | the single FP is the preserved `EVAL-SAST-008` case |
| Precision / recall | 0.995 / 1.0 | **0.9953 / 1.0** | — | synthetic population only; see §G denominators |
| SAST evaluated | 104 | **116** | +12 | 13.6% of 853 |
| DAST evaluated | 68 | **70** | +2 | 100% of 70 |
| Reachability FULL/PARTIAL/NONE/UNIVERSAL | 595/28/207/11 | **607/28/207/11** | +12 FULL | `docs/PACKS.md` tripwire recomputed |
| `validatedCount` corpus total | 2,184 | **2,212** | +28 | sast +12, dast +2, remediation +14 |
| Full suite assertions | 17,502 ok | **17,722 ok** | +220 | `npm test` EXIT 0 |
| Manifest files | 4,555 | **4,643** | +88 | report + 88 new asset files |
| Worktree | 2,313 M / 447 ?? / 0 D | **2,313 M / 534 ?? / 0 D** | +87 untracked entries | no deletions, no git write |

**Honest target status (detail in §M):** SAST breadth is **PARTIAL** (853 of the 1,000 planning target; 147 short and 737 rules not yet independently evaluated). DAST is **PASS** for complete evaluation of the existing closed capability set (70/70) and **NOT APPLICABLE** as a 1,000-count target. SCA contract/fixture work is **PASS**; SCA rule packs and production advisories are **BLOCKED** on owner and rights decisions. Supporting families at 1,000 each are **NOT JUSTIFIED**. Release remains **NO-GO**.

---

## B. Repository integrity

| Fact | Evidence |
|---|---|
| Repo identity | `git remote -v` → `github.com/mdraselislam0101-design/Drobon-Dataset`; `gh auth status` authenticated |
| Branch | `arena/a4caaeb8-drobon-dataset` (unchanged throughout) |
| HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` — identical at pump start and end; no commit, tag, push, PR or merge was performed |
| Staged / modified / untracked / deleted | **0 staged / 2,313 modified / 535 untracked / 0 deleted** at final recount (`git status --porcelain`; every modification and untracked file preserved) |
| LICENSE | absent; the no-LICENSE invariant is intact (BLK-001 remains open) |
| Main App | `mdraselislam0101-design/Drobon` read-only, HEAD `c32c797a549453802bd6d82c5673d2a1728457a3`; no file written; its pack loader is still unimplemented, so new Dataset packs are unreachable at runtime (documented, not a Dataset defect) |
| Generator safety | `node scripts/generate-assets.mjs` → `written: 3995, removed: 0, quarantined: []`; a quarantined cell would abort before writes |
| Determinism | `test-determinism` 5/5, including whole-tree digest reproducibility (`118b01c4f8d0de54a1c9e83d903f2e89e21bb2c341b841fc5b47a98b5650d1ea` at the recorded run) |
| D-13 | the 40 legacy record-less patterns stay **inactive**; `docs/OWNER_DECISIONS.json` was not edited |
| Production locks | production advisory count **0**, verified-production corpus **0**; ingestion gates BLOCKED 4/4 |

The working tree carries the entire cumulative pump history uncommitted because the standing authorization forbids git writes. This report therefore records the tree as the source of truth and reassures that nothing was discarded: 0 deletions, 0 renames, and every pre-existing modification preserved.

### Reconciliation of previously reported figures

Every figure asserted by the preceding 1000× report was reproduced at pump start with the same commands and matched exactly: SAST 841, DAST 68, pack total 1,006, patterns 1,006, records 966, remediation 1,006, CWE 61, eval 296 cases / 285 assessed / 11 UNASSESSED / TP 199 / FP 1 / FN 0, SCA 0 active packs, 84 advisory seed items, manifest 4,555 files, `npm test` EXIT 0 with 17,502 ok assertions, worktree 2,313 M / 447 ?? / 0 D. No discrepancy required correction. Two documentation clarifications were made and are recorded here rather than silently dropped:

1. `docs/COVERAGE_MAP.json` at HEAD still carries the pre-pump snapshot (792 SAST rules). The working-tree file was already reconciled to the then-current 841 and has now been recomputed to 853 by the same rules as `test-doc-drift`; HEAD is unchanged by design.
2. `docs/CAPABILITY_GAP_MATRIX.md` retains historical snapshot figures (954 rules etc.) in its dated audit narrative. Only the strings that `test-current-state` treats as *current* claims were re-pinned (breadth, linkage, remediation, audience validation count). Historical text is left labelled as history.

---

## C. Baseline-to-final metrics

Counting rules are stated per row so no two denominators are combined.

| Metric | Baseline | Final | Inclusion rule | Reproduce |
|---|---:|---:|---|---|
| Active SAST rules | 841 | 853 | every parsed `packs/sast/v1/rules/DPK-*.json` | `ls packs/sast/v1/rules \| wc -l` |
| Active DAST rules | 68 | 70 | every parsed `packs/dast/v1/rules/DPK-*.json` | `ls packs/dast/v1/rules \| wc -l` |
| Active secrets rules | 97 | 97 | every parsed secrets rule file | `ls packs/secrets/v1/rules \| wc -l` |
| Pack rules total | 1,006 | 1,020 | SAST + secrets + DAST only | `node scripts/gap-matrix.mjs` |
| Patterns | 1,006 | 1,020 | every `knowledge/patterns/DPK-PAT-*.json` | `ls knowledge/patterns \| wc -l` |
| Records | 966 | 980 | every `knowledge/records/DPK-REC-*.json` | `ls knowledge/records \| wc -l` |
| Remediation entries | 1,006 | 1,020 | every `knowledge/remediation/DPK-*.json` | `ls knowledge/remediation \| wc -l` |
| CWE entries | 61 | 61 | every `knowledge/cwe/*.json` | `ls knowledge/cwe \| wc -l` |
| Eval cases / assessed | 296 / 285 | 324 / 313 | case files; ASSESSED ground truth only | `node scripts/run-eval.mjs` |
| TP / FP / FN | 199 / 1 / 0 | 213 / 1 / 0 | exact ruleId + line + evidence match; unexpected detections on unexpected lines are FP | `node scripts/coverage-report.mjs --json out.json` |
| Precision / recall | 0.995 / 1.0 | 0.9953 / 1.0 | TP/(TP+FP) and TP/(TP+FN) over assessed cases only; **not** a rule-level recall over the corpus | same |
| Distinct rules exercised | 176 | 190 | distinct rule ids in `expected.detections` | same |
| Distinct rules named (incl. negative controls) | 179 | 193 | distinct ids in detections ∪ forbiddenDetections; pooled figure for reconciliation only | same |
| SAST/DAST/Secrets exercised | 104 / 68 / 4 | 116 / 70 / 4 | per-engine denominators 853 / 70 / 97 | same |
| Reachability FULL | 595 | 607 | rule `languages` all present in the 53-id analyzed catalog | `node scripts/test-consistency.mjs` |
| `validatedCount` total | 2,184 | 2,212 | sum of counted categories in `docs/CORPUS_TARGETS.json` | `node scripts/validate-corpus.mjs` |
| Manifest files | 4,555 | 4,643 | every repo file in the `all` scope, report included | `node scripts/manifest.mjs --scope all --check <file>` |
| Worktree | 2,313 M / 447 ?? / 0 D | 2,313 M / 534 ?? / 0 D | `git status --porcelain` classes | `git status --porcelain` |

---

## D. Batch-by-batch change log

### This pump — batch 4 (SAST 852–857, DAST 074–075, eval EVAL-SAST-100…111, EVAL-DAST-080…083)

| Rule | Title | Language | CWE | Sev | Eval |
|---|---|---|---|---|---|
| DPK-SAST-852 | Server-side fetch with a computed URL | go | CWE-918 | MEDIUM | 100 pos / 101 neg |
| DPK-SAST-853 | Cookie set without HttpOnly | javascript | CWE-1004 | MEDIUM | 102 pos / 103 neg |
| DPK-SAST-854 | Cookie set without Secure | javascript | CWE-614 | MEDIUM | 104 pos / 105 neg |
| DPK-SAST-855 | Cookie set with SameSite=None | javascript | CWE-1275 | MEDIUM | 106 pos / 107 neg |
| DPK-SAST-856 | Django/Flask cookie SameSite=None | python | CWE-1275 | MEDIUM | 108 pos / 109 neg |
| DPK-SAST-857 | Legacy keyed unarchiving | swift | CWE-502 | HIGH | 110 pos / 111 neg |
| DPK-DAST-074 | Content-Type header missing | http observation | CWE-693 | LOW | 080 pos / 081 neg |
| DPK-DAST-075 | CSP without object-src | http observation | CWE-693 | LOW | 082 pos / 083 neg |

### This pump — batch 5 (SAST 858–863, eval EVAL-SAST-112…123)

| Rule | Title | Language | CWE | Sev | Eval |
|---|---|---|---|---|---|
| DPK-SAST-858 | Synchronous OS command execution (`execSync`) | javascript | CWE-78 | HIGH | 112 pos / 113 neg |
| DPK-SAST-859 | Non-cryptographic random bytes as token (`pseudoRandomBytes`) | javascript | CWE-330 | MEDIUM | 116 pos / 117 neg |
| DPK-SAST-860 | WebView loads a computed URL | kotlin | CWE-749 | MEDIUM | 118 pos / 119 neg |
| DPK-SAST-861 | Include/require path built from a variable | php | CWE-829 | HIGH | 114 pos / 115 neg |
| DPK-SAST-862 | Subprocess with `shell=True` | python | CWE-78 | HIGH | 120 pos / 121 neg |
| DPK-SAST-863 | Dynamic method dispatch from a non-literal name | ruby | CWE-470 | MEDIUM | 122 pos / 123 neg |

Every rule followed the same mandatory chain: cell authored in `data/asset-cells` → `generate-assets.mjs` emitted pattern, rule, record, remediation and cell manifest → `validate-packs`/`test-packs` accepted pattern + positive + negative + boundary coverage → eval case authored **before** first execution → `run-eval` executed → count pins and matrices recomputed → full regression. No status-only or documentation-only change was counted as closure.

Earlier batches 1–3 (SAST 823–851, DAST 069–073, eval EVAL-SAST-058…099, EVAL-DAST-070…079, SCA fixture corpus) are preserved verbatim in Appendix P §2–§11.

---

## E. Coverage analysis

### E.1 SAST

- **Active rules:** 853 (denominator: every parsed rule document; no activity filter is applied or claimed).
- **Validated rules:** 853/853. `test-packs` executes 4,246 assertions: at least one positive and one negative example per rule, plus boundary/near-miss examples generated from the cell.
- **Independently evaluated:** **116/853 = 13.6%** (numerator: distinct rule ids named in `expected.detections`; negative-only references excluded). 737 active rules have no independent eval case yet.
- **Reachability against the Main App language catalog:** FULL 607, PARTIAL 28, NONE 207, UNIVERSAL 11 (no `languages` field, any-file convention) — 853 total. The engine's actual rate also depends on the unimplemented app-side loader (BLK/GAP below).
- **Distance to the 1,000 planning target:** **147 rules.** That is a distance, not a quality claim; padding with cosmetic or duplicate signals was refused.
- **Category concentration (rules):** weak-cryptography 94, secure-configuration 89, code-injection 80, sql-injection 66, command-injection 50, server-side-request-forgery 26 (SAST); evaluation density remains thin in the largest categories (see §G).

New batch coverage was deliberately spread across five languages (go, javascript ×3, python ×2, swift, kotlin, php, ruby) and three CWE families (injection, cookie/session, deserialization/reflection).

### E.2 DAST

- **Active rules:** 70; **evaluated:** 70/70 = **100%**, each with a synthetic observation case and a negative control. No request was sent; every observation is a fixture object.
- **Closed capability set:** the engine's check vocabulary remains the same **7 check types**; batches 4–5 added two observation classes inside the existing vocabulary (`missing-response-header`, `response-header-missing-directive`) and did not extend the schema.
- **1,000 DAST checks:** **NOT APPLICABLE** while the vocabulary is closed. Reaching it would require new observation classes (schema change, owner approval) and would be a count target, not a coverage goal. The gap matrix therefore reports 930 "remaining" only as arithmetic distance.
- Preserved severities and rationale: Expect-CT LOW, COEP/COOP MEDIUM, and all earlier decisions were left untouched.

### E.3 Secrets

- **Active rules:** 97; **independently exercised:** 4/97 = 4.12%; **named** (including negative controls): 7/97 = 7.22%. These two figures are never mixed. Denominator: all active secrets rules.
- No new secrets rule was added this pump: candidate classes were already covered or lacked a non-duplicative signal. The 40 record-less legacy patterns remain under D-13 and are not counted as production intelligence.

### E.4 SCA

- **Active SCA rule packs:** 0. The schema proposal is parked (`docs/SCA_RULE_SCHEMA_PROPOSAL.md`); no pack may be authored before the owner decision.
- **Contract surface:** 12 engine exports, 6 contract sections, **38/38** engine tests, **149/149** fixture assertions over a 6-file synthetic corpus (coordinates, ranges, dependencies, aliases, advisories, cycles).
- **Capabilities:** coverage-report counts **22/22** declared SCA capability strings as evidenced. The list is string-pinned to assertion titles; the denominator is the declared list, not a claim of completeness.
- **States implemented and tested:** `NO_DATA_LOADED`, `NOT_ASSESSED`, `ASSESSED`, no-match, duplicate/conflicting coordinates, unresolved edges, malformed-record rejection (fail-closed), deterministic ordering, range-mismatch handling, alias/canonical-name resolution.
- **Production advisories:** **0**. The 84 GHSA seed items remain rights-unresolved and are excluded from production counts.

---

## F. Quality and integrity

| Check | Result |
|---|---|
| Exact duplicate rule signals | **0** (`test-consistency` duplicate gate; rules are keyed by unique signal class + language) |
| Duplicate rule ids / pattern ids | **0** |
| Dangling `patternRefs` / linked rules | **0** — rule↔pattern linkage 1,020/1,020 both directions |
| Rules without remediation / orphan remediation | **0 / 0** — 1,020/1,020 |
| Malformed assets | **0** in `validate-packs` (1,023 files), `validate-assets` (2,000), `validate-audiences` (1,031) |
| Records without matching rules | 40 legacy patterns have no record (D-13, inactive); **not** counted as production and not backfilled |
| CWE integrity | every declared CWE resolves in `knowledge/cwe` (61 entries); no invented CWE ids; CWE-693 reused, not fabricated |
| Provenance | all new rules/patterns/records/remediation/cells are `original-authored`; all 324 eval cases are `original-authored`, `synthetic: true`, `testOnly: true` |
| Near-duplicate review | 1 flagged description pair, DPK-SAST-847 (JS `new RegExp`) vs DPK-SAST-849 (Python `re.compile`) — different languages and APIs, reviewed and retained; 1 repeated remediation template in the same family, intentional |
| Ground truth | `EVAL-SAST-008` FP preserved; 11 UNASSESSED cases preserved; no expected result, severity or rule id was altered to improve metrics |
| Production data | none added; production advisory records 0; D-13 untouched |
| Rights | no LICENSE, no source attribution fabricated, no advisory feed ingested |

Quarantine behaviour was exercised during authoring: five cells were rejected (two DAST expectation mismatches, three SAST pattern/test defects), fixed in new cell files, and only then emitted. The failed cell files were removed as authoring scratch; the generator reported `removed: 0` for repository assets.

---

## G. Evaluation metrics

Population: **324 synthetic cases, 313 ASSESSED, 11 UNASSESSED**, all original-authored. UNASSESSED cases contribute nothing to scoring and are never counted as passes.

| Engine | Cases | Assessed | TP | FP | FN | Rule denominator | Distinct rules exercised |
|---|---:|---:|---:|---:|---:|---:|---:|
| SAST | 123 | 118 | 75 | 1 | 0 | 853 | 116 |
| Secrets | 17 | 16 | 6 | 0 | 0 | 97 | 4 |
| DAST | 83 | 83 | 70 | 0 | 0 | 70 | 70 |
| Other (SQL/CI/CMD/ACL cohorts) | 101 | 96 | 62 | 0 | 0 | — | — |
| **Total** | **324** | **313** | **213** | **1** | **0** | 1,020 | 190 |

- **Precision** = 213/(213+1) = **0.9953**; **recall** = 213/(213+0) = **1.0**. These are exact-evidence metrics over the assessed synthetic population, **not** universal recall and **not** a claim about real-world code.
- **Variants:** positive 183, negative 101, boundary 21, mutation 9, near-miss 10.
- **Preserved failure:** `EVAL-SAST-008` (documented false positive: a docstring containing `.execute("SELECT " +`). Kept visible; outcome FAIL, suite exit remains 0 by design.
- **Rules without coverage:** 737 SAST rules and 93 secrets rules have no independent eval case. Largest category gaps (exercised/total): weak-cryptography 12/94, secure-configuration 1/89, service-token 1/85, code-injection 6/80, sql-injection 13/66, command-injection 13/50.
- Distinct rules named including negative controls is **193** (pooled 193/1,020 = 18.92%); that pooled figure exists only to reconcile older mixed-denominator claims and is not a per-engine coverage rate.

---

## H. SCA and rights

- **Implemented:** coordinate normalization, synthetic-record validation, synthetic provider, severity ordering, canonical package names, alias resolution, dependency-graph resolution, deterministic ordering, fail-closed validation. `packs/sca/` remains empty; nothing was promoted into rule packs.
- **Fixture corpus:** `data/sca-fixtures/{coordinates,ranges,dependencies,aliases,advisories,cycles}.json`; all records are marked synthetic (`DROBON-SAMPLE-*`), excluded from production counts; `scripts/test-sca-fixtures.mjs` = 149 assertions (including explicit cycle reporting).
- **Provider contract:** `assess(coordinates) → { providerId, datasetStatus, advisories[] }`; `NO_DATA_LOADED` when no records are loaded, `NOT_ASSESSED` for coordinates outside the loaded set, `ASSESSED` only with evidence.
- **Rights:** no real CVE/NVD/GHSA/OSV/KEV/EPSS/exploit data, no third-party catalog, no paid rules. The 84 GHSA seed items (100 files / 78 unique ids from the earlier seed batch) remain **rights-unresolved** and are not production intelligence.
- **Blockers:** SCA rule-pack schema (owner decision), production advisory feed rights (legal/owner), and the Main App's `VULN_INTEL_PROVIDER=none` Null provider.

---

## I. UserType mapping

One shared intelligence core serves DEVELOPER, STUDENT, SECURITY_PROFESSIONAL and PENTESTER. `UserType` is presentation/workflow only: no rule, pattern, record or remediation is duplicated per type, and no per-type counting is used in this report. Audience projections validate 1,031 files (`validate-audiences`), with lessons 6, assessment templates 3, engagement aids 2; audience content references rules but never forks them. FREE/PRO entitlement splits are Main App concerns and are not Dataset counts.

---

## J. Remaining gaps and owner decisions

| ID | Gap | Evidence | Why open | Required action | Category | Safe work continuable |
|---|---|---|---|---|---|---|
| UP-01 | SAST breadth 853/1,000 | gap-matrix: 147 remaining | Each rule needs a unique signal, full asset chain and eval case; remaining classes are increasingly thin or already covered | Author further batches from verified uncovered constructs | ENGINEERING | Yes |
| UP-02 | SAST eval depth 116/853 | coverage-report 13.6% | 737 rules have no independent case | Add eval cases per category, starting with weak-cryptography (12/94) and secure-configuration (1/89) | ENGINEERING | Yes |
| UP-03 | DAST count target 930 short | gap-matrix arithmetic | Closed 7-check vocabulary; new observation classes need schema approval | Owner decision on DAST observation schema | OWNER_DECISION | No (schema) |
| UP-04 | SCA rule packs 0 | `packs/sca/` empty; parked proposal | Owner has not approved the SCA pack schema/rights model | Decide the SCA schema proposal; then author packs from original logic | OWNER_DECISION | No (packs) |
| UP-05 | Production advisories 0 | 84 seed items rights-unresolved | No verified rights; no LICENSE | Legal/owner rights grant or continue synthetic-only | LEGAL | Yes (synthetic) |
| UP-06 | D-13: 40 legacy patterns without records | `docs/OWNER_DECISIONS.json` | Parked by owner; must stay inactive | Owner decides retain/retire/record | OWNER_DECISION | Yes (non-countable) |
| UP-07 | CWE vocabulary gaps (CWE-922/CWE-522/.npmrc) | prior batch notes | Terms absent from the 61-entry vocabulary | Owner/curator decision on vocabulary additions | OWNER_DECISION | Yes (other CWE families) |
| UP-08 | Main App loader unimplemented | app HEAD `c32c797a`; loader absent | App workstream, read-only here | App-side loader design and tests | APP_WORKSTREAM | No (Dataset-side) |
| UP-09 | Release gates | §K, §L | License, production lock, owner decisions, app integration | Resolve the four blocked gates | RELEASE | No |

All four pre-existing blockers (BLK-001 licensing, BLK-002 production data, BLK-003 owner decisions, BLK-004 app integration dependency) remain open with unchanged status.

---

## K. Final test evidence

| Command | Exit | Result |
|---|---:|---|
| `npm test` | **0** | 17,722 ok assertions: tests 600, packs 4,246, audiences 3,104, assets 8,052, consistency 218, rehearsal 78, importers 49, agent-policy 91, agent-workflows 57, finding-evidence 31, secret-candidates 35, sca-engine 38, **sca-fixtures 149**, eval 41, doc-drift 119, current-state 153, capability 656, determinism 5/5 |
| `node scripts/validate-packs.mjs` | 0 | PASS, 1,023 files, 0 errors |
| `node scripts/validate-assets.mjs` | 0 | PASS, 2,000 files, 0 errors |
| `node scripts/validate-audiences.mjs` | 0 | PASS, 1,031 files, 0 errors |
| `node scripts/validate-capability-coverage.mjs` | 0 | 656 passed, 0 failed |
| `node scripts/coverage-report.mjs --check` | 0 | PASS (separate denominators; SCA 22/22) |
| `node scripts/inventory.mjs --check` | 0 | `docs/CURRENT_INVENTORY.json` matches the tree |
| `node scripts/manifest.mjs --scope all --check /tmp/integrity-ultimate-final.json` | 0 | PASS, 4,643 files verified |
| `node scripts/run-eval.mjs` | 0 | 324 cases, 313 assessed, 11 UNASSESSED, TP 213 / FP 1 / FN 0 |
| `node scripts/test-determinism.mjs` | 0 | 5/5, regenerated tree byte-identical, tree digest reproducible |
| `node scripts/ingestion-gates.mjs` | **1** | **BLOCKED AS EXPECTED** — production ingestion blocked by 4/4 gates (GATE-1…GATE-4) |
| `git status --porcelain` | 0 | 2,313 M / 534 ?? / 0 D; HEAD `ed599c65`; branch unchanged |

The non-zero ingestion-gate exit is the designed fail-closed behaviour, not a regression. No test was skipped, weakened, deleted or relabelled.

---

## L. Release decision

**NO-GO.**

The Dataset is internally consistent, deterministic and fully green, but release is blocked by four independent gates that this pump may not resolve:

1. **Licensing** — no LICENSE, no rights grant (BLK-001, release gate G6).
2. **Production data** — production advisory/inventory corpus remains locked and empty by policy (BLK-002, G8).
3. **Owner decisions** — SCA pack schema, DAST observation schema, D-13 retention, CWE vocabulary (G16/G17).
4. **App integration** — the Main App pack loader is unimplemented; new packs are unreachable at runtime (BLK-004).

None of these is a Dataset defect; all require decisions or work outside this authorization.

---

## M. Honest completion statement

| Requirement | Status | Justification |
|---|---|---|
| SAST ≥1,000 unique useful rules | **PARTIAL** | 853 active and validated; 147 short; 116 independently evaluated |
| DAST complete verified coverage of the existing capability set | **PASS** | 70/70 rules evaluated over the closed 7-check vocabulary; no live requests |
| DAST 1,000-check count target | **NOT APPLICABLE** | Closed observation vocabulary; expanding it is a schema decision, not padding |
| SCA contract and fixture work | **PASS** | 38 engine tests + 149 fixture assertions; 22/22 declared capabilities; fail-closed states tested |
| SCA rule packs / production advisories | **BLOCKED** | Owner schema decision and rights grant required; 0 packs, 0 production records |
| Supporting families at 1,000 each | **NOT JUSTIFIED** | No non-duplicative content available; padding refused |
| Quality: duplicates, dangling, orphans, malformed | **PASS** | 0 each; 40 legacy record gaps documented as inactive D-13 |
| Evaluation layer (measured population) | **PASS** | 324 cases / 313 assessed, TP 213 / FP 1 / FN 0, precision 0.9953, recall 1.0 |
| Evaluation depth (all rules) | **PARTIAL** | 116/853 SAST and 4/97 secrets exercised; no universal-recall claim |
| Inventory / manifest / capability matrix consistency | **PASS** | All validators and `--check` gates green at 853/70/1,020/980/1,020 |
| Determinism | **PASS** | 5/5, byte-identical regeneration, reproducible tree digest |
| Production-data and rights locks | **PASS** | Untouched; 0 production advisories; no LICENSE |
| Main App read-only | **PASS** | No file modified; HEAD `c32c797a` unchanged |
| Git / release discipline | **PASS** | No commit, push, tag, PR, merge, reset or clean; HEAD `ed599c65` unchanged |
| **Overall** | **PARTIAL** | Additive work is real, integrated, tested and honestly counted; the 1,000-rule breadth target, SCA packs and release remain open or blocked |

No statement in this report claims 100% completion, universal recall, paid-tool parity, or production readiness.

---

## Appendix P — preserved 1000× pump report (sections 1–16, unchanged)

# 1000× GAP-FILL BY ADDITIVE CREATION — Master Pump (2026-10-19)

Status block (read this first):

- **PUMP: batches 1–3 COMPLETE, verified.** Batch 1 (verified SAST + DAST gaps), batch 2 (framework / dynamic-evaluation / ReDoS / deserialization gaps) and batch 3 (SCA synthetic data model + fixture corpus) are finished and fully verified. The 1,000-per-category rule target is **not met** and is not claimed.
- **SAST: 822 → 841 rules (+19), 0 updated, 0 deleted.** 12 rules in batch 1, 7 in batch 2. Every rule has an original scoped pattern, intelligence record, remediation entry, pack registration, positive + negative tests, and an independent eval case; all execute.
- **DAST: 65 → 68 rules (+3), 0 updated.** Synthetic observations only; no request was sent, no scan was run.
- **Supporting intelligence: two categories crossed 1,000.** Patterns 984 → **1,006**, remediation 984 → **1,006** (each mirrored 1:1 with a unique rule), records 944 → **966**.
- **SCA: new offline fixture corpus and dependency/identity logic** — 5 fixture files, 59 contract cases, 139 executed assertions, 21/21 declared contract capabilities verified. Production advisory data remains **0** (rights blocked).
- **Independent evaluation: 261 → 296 cases (+35); 285 assessed, 11 UNASSESSED (unchanged); TP 199 / FN 0 / FP 1** (the documented `EVAL-SAST-008` docstring false positive). Precision 199/200 = 0.995; recall 1.0 over assessed synthetic cases only.
- **Tests: `npm test` EXIT 0, 17,502 assertions** (17,033 before this pump; +469). No test was skipped, weakened, deleted, or relabelled.
- **Integrity: manifest PASS over 4,555 files; TRUE_DUPLICATE 0; dangling links 0; determinism 5/5; originality 1,006 rules / 1,006 patterns / 966 records / 1,006 remediation.**
- **Target reality: SAST 159 rules short of 1,000; DAST at its meaningful evaluation ceiling (68/68); SCA rule packs 0 (owner-blocked); no category is called 100% except where the denominator is the complete active set.**
- **Rights/owner: BLOCKED (BLK-001…004). Production: NO-GO. Main App: untouched. Git: no commit, push, tag, release or history write.**

---

## 1. What this pump did, and what it refused to do

The instruction was to turn identified gaps into working, tested, linked assets: *gap identified → new assets created → existing data integrated → tested → verified*. The unit of work was a bounded batch, not a report.

What was done:

1. A read-only construct probe over every SAST rule (40 constructs) and a census of the DAST rules located candidate gaps.
2. Every zero-hit candidate was reviewed by title **and** pattern before authoring; near-miss matches (`jsonp` hitting `jsonpickle`, `csrf_exempt` hitting an existing rule, `setTimeout` hitting DPK-SAST-567) were rejected as gaps rather than turned into duplicate rules.
3. Nineteen verified SAST gaps and three verified DAST gaps were closed with original assets, generated from cell sources so ID allocation stays deterministic.
4. Thirty-five independent eval cases were authored *before* first execution, so the expected outcomes are genuine predictions, not transcriptions of observed output.
5. A synthetic SCA fixture corpus and three original engine contracts (name canonicalisation, alias resolution, dependency-graph resolution) were added with 139 fail-closed assertions. No real advisory data was imported.
6. All count pins, matrices and inventories were re-derived and re-verified; the full suite was run to exit 0.

What was refused:

- No rule was authored to inflate a number. Categories where a 1,000 target is not technically meaningful (DAST's closed check vocabulary, SCA's owner-blocked schema) are reported as such instead of being padded with near-duplicate checks.
- No real advisory, CVE, GHSA, OSV, KEV, EPSS or CVSS identifier, score or severity was invented or imported.
- No test was edited to match a failure. The one failing case (`EVAL-SAST-008`) still fails and is still counted.
- No Main App file, production database, deployment configuration or Git history was touched.

## 2. Baseline and final inventory

Baseline is the tree as left by the closure pump (2026-10-19), measured by `scripts/inventory.mjs` and `scripts/coverage-report.mjs`.

| Asset family | Baseline | New this pump | Updated this pump | Deleted | Final active |
|---|---:|---:|---:|---:|---:|
| SAST rules (`packs/sast/v1/rules`) | 822 | 19 | 0 | 0 | **841** |
| Secrets rules (`packs/secrets/v1/rules`) | 97 | 0 | 0 | 0 | **97** |
| DAST rules (`packs/dast/v1/rules`) | 65 | 3 | 0 | 0 | **68** |
| Packs total | 984 | 22 | 0 | 0 | **1,006** |
| Patterns (`knowledge/patterns`) | 984 | 22 | 0 | 0 | **1,006** |
| Records (`knowledge/records`) | 944 | 22 | 0 | 0 | **966** |
| Remediation (`knowledge/remediation`) | 984 | 22 | 0 | 0 | **1,006** |
| CWE entries (`knowledge/cwe`) | 61 | 0 | 0 | 0 | **61** |
| Eval cases (`data/eval-cases`) | 261 | 35 | 0 | 0 | **296** |
| SCA fixture corpus (`data/sca-fixtures`) | 0 files | 5 files / 59 cases | — | 0 | **5 files** |
| SCA rule packs (`packs/sca`) | 0 | 0 | 0 | 0 | **0 (blocked)** |
| Verified production records | 0 | 0 | 0 | 0 | **0** |

Generation is cell-driven: cell sources are `data/asset-cells/sast-config-7.json` (12 cells), `sast-config-8.json` (7 cells) and `dast-4.json` (3 cells). Regeneration is idempotent: `node scripts/generate-assets.mjs` reports `written: 3939, removed: 0, quarantined: []`. Generated counts are not on-disk totals: 22 SAST, 8 secrets and 10 DAST files come from cells retired in earlier pumps and are retained by design (documented in `docs/ASSET_METHODOLOGY.md`), giving on-disk totals of 841 / 97 / 68.

## 3. Per-engine target matrices

Target = 1,000 **useful, validated, unique** assets per category. `Remaining to 1,000` is arithmetic (`max(0, 1000 − active)`), not a claim that 1,000 duplicates would be valuable. `Evaluated` means the rule id appears in `expected.detections` of at least one eval case; negative-only references do not count.

### SAST categories

| Category | Baseline | New (pump) | Updated | Final active | Validated | Evaluated | Remaining to 1,000 |
|---|---:|---:|---:|---:|---:|---:|---:|
| access-control | 37 | 2 | 0 | 39 | 39 | 7 | 961 |
| authentication | 4 | 1 | 0 | 5 | 5 | 1 | 995 |
| broken-auth | 4 | 0 | 0 | 4 | 4 | 0 | 996 |
| buffer-overflow | 5 | 0 | 0 | 5 | 5 | 1 | 995 |
| ci-security | 10 | 2 | 0 | 12 | 12 | 4 | 988 |
| cleartext-transmission | 13 | 1 | 0 | 14 | 14 | 1 | 986 |
| code-injection | 77 | 2 | 0 | 79 | 79 | 5 | 921 |
| command-injection | 48 | 0 | 0 | 48 | 48 | 11 | 952 |
| container-security | 37 | 3 | 0 | 40 | 40 | 8 | 960 |
| cookie-flags | 1 | 0 | 0 | 1 | 1 | 0 | 999 |
| cross-site-scripting | 26 | 0 | 0 | 26 | 26 | 1 | 974 |
| csrf-protection | 4 | 0 | 0 | 4 | 4 | 0 | 996 |
| debug-code | 1 | 1 | 0 | 2 | 2 | 1 | 998 |
| debug-exposure | 5 | 0 | 0 | 5 | 5 | 2 | 995 |
| denial-of-service | 5 | 2 | 0 | 7 | 7 | 3 | 993 |
| deserialization | 2 | 0 | 0 | 2 | 2 | 0 | 998 |
| error-handling | 1 | 0 | 0 | 1 | 1 | 0 | 999 |
| format-string | 2 | 0 | 0 | 2 | 2 | 1 | 998 |
| hardcoded-credential | 12 | 0 | 0 | 12 | 12 | 0 | 988 |
| html-injection | 1 | 0 | 0 | 1 | 1 | 0 | 999 |
| http-response-splitting | 3 | 0 | 0 | 3 | 3 | 1 | 997 |
| information-disclosure | 11 | 1 | 0 | 12 | 12 | 3 | 988 |
| insecure-temporary-file | 3 | 0 | 0 | 3 | 3 | 0 | 997 |
| integer-overflow | 2 | 0 | 0 | 2 | 2 | 0 | 998 |
| ldap-injection | 3 | 0 | 0 | 3 | 3 | 0 | 997 |
| log-forging | 5 | 1 | 0 | 6 | 6 | 2 | 994 |
| mass-assignment | 3 | 0 | 0 | 3 | 3 | 1 | 997 |
| memory-safety | 2 | 0 | 0 | 2 | 2 | 0 | 998 |
| mobile-security | 6 | 0 | 0 | 6 | 6 | 0 | 994 |
| open-redirect | 18 | 0 | 0 | 18 | 18 | 1 | 982 |
| path-traversal | 37 | 0 | 0 | 37 | 37 | 2 | 963 |
| permissions | 15 | 0 | 0 | 15 | 15 | 2 | 985 |
| privilege-management | 3 | 0 | 0 | 3 | 3 | 0 | 997 |
| race-condition | 4 | 0 | 0 | 4 | 4 | 0 | 996 |
| secure-configuration | 89 | 0 | 0 | 89 | 89 | 1 | 911 |
| sensitive-logging | 33 | 0 | 0 | 33 | 33 | 3 | 967 |
| server-side-request-forgery | 23 | 0 | 0 | 23 | 23 | 3 | 977 |
| session-security | 3 | 0 | 0 | 3 | 3 | 0 | 997 |
| sql-injection | 66 | 0 | 0 | 66 | 66 | 13 | 934 |
| template-injection | 2 | 0 | 0 | 2 | 2 | 0 | 998 |
| timing-side-channel | 5 | 0 | 0 | 5 | 5 | 0 | 995 |
| transport-security | 42 | 0 | 0 | 42 | 42 | 3 | 958 |
| unsafe-deserialization | 35 | 2 | 0 | 37 | 37 | 9 | 963 |
| unsafe-reflection | 8 | 0 | 0 | 8 | 8 | 1 | 992 |
| weak-cryptography | 92 | 1 | 0 | 93 | 93 | 11 | 907 |
| weak-policy | 2 | 0 | 0 | 2 | 2 | 0 | 998 |
| xml-external-entity | 4 | 0 | 0 | 4 | 4 | 0 | 996 |
| xpath-injection | 2 | 0 | 0 | 2 | 2 | 0 | 998 |
| xss | 2 | 0 | 0 | 2 | 2 | 2 | 998 |
| xxe | 4 | 0 | 0 | 4 | 4 | 0 | 996 |
| **total** | **822** | **19** | **0** | **841** | **841** | **104** | **159** |

### DAST check types

| Check type | Baseline | New (pump) | Updated | Final active | Validated | Evaluated | Remaining to 1,000 |
|---|---:|---:|---:|---:|---:|---:|---:|
| cookie-missing-flag | 3 | 0 | 0 | 3 | 3 | 3 | 997 |
| http-url | 1 | 0 | 0 | 1 | 1 | 1 | 999 |
| missing-response-header | 15 | 0 | 0 | 15 | 15 | 15 | 985 |
| response-body-matches | 10 | 0 | 0 | 10 | 10 | 10 | 990 |
| response-header-host-differs | 1 | 0 | 0 | 1 | 1 | 1 | 999 |
| response-header-matches | 25 | 3 | 0 | 28 | 28 | 28 | 972 |
| response-header-missing-directive | 10 | 0 | 0 | 10 | 10 | 10 | 990 |
| **total** | **65** | **3** | **0** | **68** | **68** | **68** | **932** |

### Construct probes (40)

| Construct | Pattern hits | Status |
|---|---:|---|
| log-crlf | 0 | verified gap, closed (DPK-SAST-842) |
| debug-true | 0 | verified gap, closed (DPK-SAST-834) |
| assert-auth | 1 | verified gap, closed (DPK-SAST-833) |
| settimeout-string | 0 | already covered — DPK-SAST-567 (no duplicate authored) |
| token-localstorage | 0 | unresolved — blocked on CWE/language vocabulary; next-batch candidate |
| uuid1 | 1 | verified gap, closed (DPK-SAST-844) |
| git-http | 0 | verified gap, closed (DPK-SAST-840) |
| npm-unsafe-perm | 0 | unresolved — blocked on CWE/language vocabulary; next-batch candidate |
| docker-latest | 0 | verified gap, closed (DPK-SAST-836) |
| docker-root-user | 0 | verified gap, closed (DPK-SAST-837) |
| docker-add-http | 0 | verified gap, closed (DPK-SAST-835) |
| gha-workflow-run | 1 | verified gap, closed (DPK-SAST-839) |
| gha-persist-creds | 0 | unresolved — blocked on CWE/language vocabulary; next-batch candidate |
| gha-secrets-inherit | 0 | verified gap, closed (DPK-SAST-838) |
| php-unserialize | 3 | verified gap, closed (DPK-SAST-843) |
| java-scriptengine | 1 | verified gap, closed (DPK-SAST-841) |
| spring-permitall | 1 | verified gap, closed (DPK-SAST-851) |
| express-error-stack | 0 | verified gap, closed (DPK-SAST-845) |
| ssrf-request | 0 | verified gap, closed (DPK-SAST-831) |
| ssrf-fetch | 0 | verified gap, closed (DPK-SAST-830) |
| prototype-pollution | 2 | verified gap, closed (DPK-SAST-827) |
| header-injection | 0 | verified gap, closed (DPK-SAST-825) |
| remote-pipe-shell | 0 | verified gap, closed (DPK-SAST-828) |
| shelve-open | 0 | verified gap, closed (DPK-SAST-829) |
| bcrypt-cost | 1 | verified gap, closed (DPK-SAST-832) |
| ci-secret-echo | 0 | verified gap, closed (DPK-SAST-823) |
| permissions-write-all | 0 | verified gap, closed (DPK-SAST-824) |
| csrf-exempt | 1 | already covered — DPK-SAST-073 (no duplicate authored) |
| django-allowed-hosts | 1 | already covered — DPK-SAST-089 (no duplicate authored) |
| graphql-introspection | 1 | already covered — DPK-SAST-407 (no duplicate authored) |
| jwt-no-expiry | 0 | already covered — DPK-SAST-570 (no duplicate authored) |
| trust-proxy | 1 | already covered — DPK-SAST-516 (no duplicate authored) |
| ssti | 1 | already covered — DPK-SAST-323 (no duplicate authored) |
| document-write | 0 | already covered — DPK-SAST-009 (no duplicate authored) |
| dangerous-html | 1 | already covered — DPK-SAST-414 (no duplicate authored) |
| js-function-constructor | 0 | verified gap, closed (DPK-SAST-846) |
| js-redos | 0 | verified gap, closed (DPK-SAST-847) |
| python-redos | 0 | verified gap, closed (DPK-SAST-849) |
| ruby-marshal | 0 | verified gap, closed (DPK-SAST-850) |
| jwt-verify-disabled | 1 | verified gap, closed (DPK-SAST-848) |

### 3.1 SAST reading

- Total: 841 active, 841 validated (100% carry a scoped pattern, resolvable CWE, remediation entry and executable positive + negative tests), 104 independently evaluated (12.37%), 159 remaining to the 1,000 planning target.
- Largest categories: `weak-cryptography` (93), `secure-configuration` (89), `code-injection` (79), `sql-injection` (66). None is close to 1,000, and no category is claimed complete.
- **Independently evaluated coverage is the real bottleneck, not rule count.** 104/841 = 12.37% is the honest breadth of independent evidence; the packs' own positive/negative tests cover 841/841 but are not independent evaluation and are not reported as such.

### 3.2 DAST reading — and why 1,000 DAST rules is not a meaningful target

- 68 active, 68 validated, **68/68 independently evaluated (100%)**, 932 short of the 1,000 arithmetic target.
- The check vocabulary is the closed evaluator set in `scripts/validate-packs.mjs` (7 types). Adding 932 further header checks would be pure duplication — the exact inflation the instructions forbid. The technically meaningful DAST target is *per-rule independent evaluation* and *observation capability breadth*, both at 68/68 today.
- New observation capability (TLS/certificate state, redirect chains, duplicate-header detection, decoded body inspection) requires a **new evaluator type**, which is a dataset schema change and an app-contract change. That is recorded as a next-step decision, not silently performed (§14).

### 3.3 SCA reading — contract breadth grown, production still blocked

| SCA item | Baseline | This pump | Final |
|---|---:|---:|---:|
| Rule packs (`packs/sca/`) | 0 | 0 | **0 (owner-blocked)** |
| Engine contract exports | 9 | +3 | **12** |
| Contract capabilities verified | 12/12 | +9 | **21/21** |
| Fixture corpus files | 0 | 5 | **5** |
| Contract fixture cases | 0 | 59 | **59** |
| Executed fixture assertions | 0 | 139 | **139** |
| Inline synthetic advisory records | 3 | 4 (corpus) | **7** |
| Advisory seed items (`vuln-intel`, GHSA) | 84 | 0 | **84 (rights unresolved)** |
| Production-authorized records | 0 | 0 | **0** |

SCA cannot be grown additively by authoring rule packs without the owner's schema approval, and cannot be grown with real advisories without redistribution rights. Authoring 1,000 synthetic advisories purely to hit a number would fabricate vuln-intel, so the SCA pack row stays at 0 with a documented blocker while the offline contract surface grows.

### 3.4 Supporting intelligence

| Asset | Baseline | New | Final | Linkage |
|---|---:|---:|---:|---|
| Patterns | 984 | 22 | **1,006** | 1,006/1,006 rules ↔ patterns both directions, 0 dangling |
| Records | 944 | 22 | **966** | 966 patterns covered; 40 legacy pattern-only records unchanged (D-13) |
| Remediation | 984 | 22 | **1,006** | 1,006/1,006 pack rules have exactly one entry keyed by `ruleId` |
| CWE entries | 61 | 0 | **61** | every rule CWE resolves; no new identifier invented |
| Eval cases | 261 | 35 | **296** | 179 distinct rules named; 176 exercised by positive expectations |

**Two supporting categories reached the 1,000 target without duplication:** every pattern is the compiled signal of exactly one rule, and every remediation entry is keyed to exactly one rule id. Their counts are 1,006 because the rule family grew to 1,006 across three families (841 SAST + 97 secrets + 68 DAST), not because any asset was multiplied.

## 4. Assets created this pump

### 4.1 SAST batch 1 — twelve rules

| ID | Title | CWE | Severity | Category | Language |
|---|---|---|---|---|---|
| DPK-SAST-833 | Authorization enforced with assert in python | CWE-284 | MEDIUM | access-control | python |
| DPK-SAST-834 | Debug mode enabled in python | CWE-489 | MEDIUM | debug-code | python |
| DPK-SAST-835 | Remote artifact added without integrity check in dockerfile | CWE-494 | HIGH | container-security | dockerfile |
| DPK-SAST-836 | Container base image is not pinned in dockerfile | CWE-829 | MEDIUM | container-security | dockerfile |
| DPK-SAST-837 | Container runs as root in dockerfile | CWE-250 | MEDIUM | container-security | dockerfile |
| DPK-SAST-838 | Reusable workflow inherits every secret in yaml | CWE-250 | MEDIUM | ci-security | yaml |
| DPK-SAST-839 | Privileged workflow triggered by workflow_run in yaml | CWE-829 | HIGH | ci-security | yaml |
| DPK-SAST-840 | Repository cloned over plaintext HTTP in shell | CWE-319 | MEDIUM | cleartext-transmission | shell |
| DPK-SAST-841 | Dynamic expression evaluation in java | CWE-94 | HIGH | code-injection | java |
| DPK-SAST-842 | Log line built with an explicit CRLF in javascript | CWE-117 | MEDIUM | log-forging | javascript |
| DPK-SAST-843 | Object injection via unserialize in php | CWE-502 | HIGH | unsafe-deserialization | php |
| DPK-SAST-844 | Time-based UUID used as a security value in python | CWE-330 | MEDIUM | weak-cryptography | python |

### 4.2 SAST batch 2 — seven rules (framework, dynamic evaluation, ReDoS, deserialization)

| ID | Title | CWE | Severity | Category | Language |
|---|---|---|---|---|---|
| DPK-SAST-845 | Stack trace returned to the client in javascript | CWE-209 | MEDIUM | information-disclosure | javascript |
| DPK-SAST-846 | Dynamic code compilation via Function constructor in javascript | CWE-95 | HIGH | code-injection | javascript |
| DPK-SAST-847 | Regular expression compiled from input in javascript | CWE-1333 | MEDIUM | denial-of-service | javascript |
| DPK-SAST-848 | JWT signature verification disabled in python | CWE-347 | HIGH | authentication | python |
| DPK-SAST-849 | Regular expression compiled from input in python | CWE-1333 | MEDIUM | denial-of-service | python |
| DPK-SAST-850 | Object injection via Marshal.load in ruby | CWE-502 | HIGH | unsafe-deserialization | ruby |
| DPK-SAST-851 | Spring Security permits every request in java | CWE-284 | HIGH | access-control | java |

Every rule in 4.1 and 4.2 ships with: one scoped regex pattern (mirrored in `knowledge/patterns` via `patternRefs`), two positive and two negative executable examples, a `knowledge/records` concept record with applicability/risk/why/fix, a context-specific remediation entry, explicit limitations, false-positive guidance, and a remediation verification line. All carry `languages`; none uses the any-file convention.

### 4.3 Three DAST rules (synthetic observations only)

| ID | Title | CWE | Severity | Check type |
|---|---|---|---|---|
| DPK-DAST-071 | Cookie sets SameSite=None without Secure | CWE-1275 | MEDIUM | `response-header-matches` on `Set-Cookie` (negative lookahead for `Secure`) |
| DPK-DAST-072 | Content-Security-Policy delivered in report-only mode | CWE-693 | MEDIUM | `response-header-matches` on `Content-Security-Policy-Report-Only` |
| DPK-DAST-073 | X-Content-Type-Options present with a non-nosniff value | CWE-693 | LOW | `response-header-matches` with a `nosniff`-anchored negative lookahead |

All three reuse existing, already-evaluated check types — no new evaluator, no schema change, no duplication of an existing header check. Every positive is paired with a negative control that proves the check does not fire on the safe value (SameSite=None **with** Secure; enforcing CSP; exactly `nosniff`).

### 4.4 Eval cases (35, authored before first execution)

| Batch | Cases | Variants | New positive rules exercised |
|---|---|---|---|
| Batch 1 | EVAL-SAST-071…085 (15), EVAL-DAST-074…079 (6) | 12 positive, 6 negative, 1 boundary, 2 pypi/npm boundary controls | 12 SAST + 3 DAST |
| Batch 2 | EVAL-SAST-086…099 (14) | 7 positive, 6 negative, 1 boundary | 7 SAST |

Variant totals across all 296 cases: positive 169, negative 87, boundary 21, mutation 9, near-miss 10. Provenance: 296/296 `original-authored`, 296/296 fully synthetic; 0 production records.

### 4.5 SCA fixture corpus and contract logic (batch 3)

| File | Contents | What it proves |
|---|---|---|
| `data/sca-fixtures/coordinates.json` | 14 coordinate cases (both ecosystems, invalid inputs) | PEP 503 / npm canonicalisation; scoped and empty names are refused rather than mangled |
| `data/sca-fixtures/ranges.json` | 18 boundary cases + 3 invalid ranges | Comparator sets, wildcards, hyphen and OR branches, PEP 440 `~=`, `==x.*`, `!=`; caret/tilde rejected as unsupported |
| `data/sca-fixtures/dependencies.json` | 10 dependency entries + expected graph | De-duplication, conflicting versions, unreachable nodes, unresolved edges, range mismatches, deterministic ordering |
| `data/sca-fixtures/aliases.json` | 4-entry synthetic alias table + 6 cases | Canonical identity through aliases; malformed table entries ignored, never guessed |
| `data/sca-fixtures/advisories.json` | 4 `DROBON-SAMPLE` records + 8 cases | Provider statuses (`ASSESSED` / `NOT_ASSESSED` / `NO_DATA_LOADED`), severity ordering, fail-closed refusals |

Three original engine contracts back the corpus (`scripts/sca-engine.mjs`): `canonicalPackageName`, `resolveAlias`, `resolveDependencyGraph`. All are pure, frozen, network-free, and return explicit reasons instead of coercing input. The corpus is labelled `synthetic: true, productionData: false` and is checked for the absence of `GHSA-`, `CVE-`, `OSV-`, `DSA-` and `RUSTSEC-` identifier shapes.

## 5. Existing assets updated this pump

**Content updates to pre-existing rules/patterns/records/remediation: 0.** No old rule was rewritten, retitled, re-scoped or re-severitied. The regression check confirms the pre-existing assets touched by the prior pump are byte-identical.

What *was* updated is measurement and contract surface, all re-derived from the tree rather than hand-edited:

- `docs/CURRENT_INVENTORY.json` — regenerated by `inventory.mjs --write`.
- `docs/REQUIREMENTS_MATRIX.json`, `docs/CORPUS_TARGETS.json` (including `totals.validated` 2,140 → 2,184), `docs/COVERAGE_MAP.json` (rules, patterns, per-category tallies, check types), `docs/CAPABILITY_COVERAGE_MATRIX.json` + `.md`, `docs/COMPLETION_MATRIX.json`, `docs/RELEASE_READINESS_MATRIX.json`.
- Prose count pins: `README.md`, `docs/PACKS.md` (reachability 577/27 → 595/28, sums 822 → 841), `docs/AUDIENCES.md`, `docs/CORPUS_GAP_REPORT.md`, `docs/CAPABILITY_COVERAGE.md`, `docs/SCA_RULE_SCHEMA_PROPOSAL.md` (887 → 909 rule packs), `docs/CAPABILITY_GAP_MATRIX.md`, `DROBON_REMAINING_WORK.csv`.
- Count tripwires: `scripts/test-doc-drift.mjs`, `scripts/test-current-state.mjs`, `scripts/test-eval.mjs` (TP 177 → 199, breadth 154 → 176). Tripwires moved **because the verified counts moved**, never to make a failure disappear; the one failing eval case and the 11 UNASSESSED cases are untouched.
- Contract surface: `scripts/coverage-report.mjs` now runs both SCA harnesses and declares 21 SCA capabilities (was 12); `package.json` runs `test-sca-fixtures.mjs` in the main chain.

## 6. Gap discovery evidence

Two independent probes were run read-only before authoring:

- **SAST constructs:** 40 named constructs searched across every rule's compiled pattern sources (`scripts/gap-matrix.mjs`, `constructs.rows`). 25 returned zero hits.
- **DAST census:** rule titles vs check types showed all 15 header checks already covered, so new DAST work had to use new *observations*, not duplicate headers.

A zero hit is a **candidate**, not proof: regexes are stored escaped, so probes can miss real coverage (e.g. `jwt-no-expiry` probes to 0 but `DPK-SAST-570` covers it; `setTimeout` probes to 0 but `DPK-SAST-567` covers it). Each candidate was therefore opened and read before authoring. Result:

- **19 verified gaps closed** across the two SAST batches, plus 3 DAST observations.
- **10 constructs verified as already covered** — `csrf_exempt` (073), `ALLOWED_HOSTS` (089), GraphQL introspection (407), JWT expiry (570), `trust proxy` (516), SSTI (323), `document.write` (009), `dangerouslySetInnerHTML` (414), `setTimeout(string)` (567), `v-html` (422). **No duplicate rule was authored for any of them.** The first draft of batch 1 contained a `csrf-exempt` cell; it was withdrawn after review.
- **3 candidates remain unresolved and are not claimed as gaps:** `token-localstorage` (no CWE-922 in the pinned catalog), `npm-unsafe-perm` (no `.npmrc` language id in the catalog schema) and `gha-persist-creds` (no CWE-522 in the catalog). Each needs an owner/schema decision before a rule can be authored honestly.
- Remaining probe-only candidates are labelled "inconclusive — manual review required".

## 7. Independent evaluation

| Engine family | Cases | Assessed | TP | FP | FN | Distinct rules exercised |
|---|---:|---:|---:|---:|---:|---:|
| SAST | 99 | 94 | 63 | 1 | 0 | 104 / 841 |
| Secrets | 17 | 16 | 6 | 0 | 0 | 4 / 97 |
| DAST | 79 | 79 | 68 | 0 | 0 | 68 / 68 |
| Other packs (SQL/CMD/…) | 101 | 96 | 62 | 0 | 0 | — |
| **Total** | **296** | **285** | **199** | **1** | **0** | **179 named / 176 exercised** |

- `EVAL-SAST-008` remains **FAIL**: 1 documented false positive on a docstring trap. It is counted in precision, not hidden.
- 11 cases remain **UNASSESSED** and contribute nothing to TP/FP/FN, by design.
- Eval-case breadth is a ratchet: 176 distinct rules are now exercised by positive expectations (169 before this pump), 179 are named once negative controls are included.

## 8. Verification results

`npm test` (EXIT 0) — actual assertion counts:

| Suite | Assertions |
|---|---:|
| core (`test.mjs`) | 600 |
| pack tests | 4,190 |
| audience tests | 3,062 |
| asset tests | 7,940 |
| consistency | 218 |
| rehearsal | 78 |
| importers | 49 |
| agent policy | 91 |
| agent workflows | 57 |
| finding evidence | 31 |
| secret candidates | 35 |
| SCA engine | 38 |
| **SCA fixture corpus (new)** | **139** |
| eval | 41 |
| doc drift | 119 |
| current state | 153 |
| capability coverage | 656 |
| determinism | 5 |
| **total `ok` assertions** | **17,502** |

Other gates:

- `inventory.mjs --check` → matches the tree.
- `coverage-report.mjs --check` → PASS, including 21/21 SCA contract capabilities.
- `manifest.mjs --scope all --write /tmp/integrity.json` then `--check` → PASS over **4,555 files**.
- `originality-report.mjs --check` → 1,006 rules / 1,006 patterns / 966 records / 1,006 remediation, 0 unresolved.
- Duplicate review: TRUE_DUPLICATE = 0; no SAST rule pair shares both a pattern and a language.
- Dangling links: 0 (rules ↔ patterns ↔ records ↔ remediation all resolve).
- Determinism: 5/5; regenerating from cells reproduces the checked-in tree byte-for-byte (tree digest printed by `npm run test:determinism`).

## 9. Four UserTypes on one shared core

- DEVELOPER, STUDENT, SECURITY_PROFESSIONAL and PENTESTER continue to read the **same** rules, patterns, records, remediation and eval corpus. No per-UserType dataset was created; no asset was duplicated to satisfy an audience.
- The audience layer is presentation only: 3,062 audience assertions and 1,017 validated audience files.
- Entitlements/quota are **not** dataset counts and are not used as such anywhere in this report.

## 10. SCA: synthetic vs production-authorized

- Synthetic fixtures: 7 records (3 inline in the engine harness + 4 in `data/sca-fixtures/advisories.json`), all `DROBON-SAMPLE` ids, all excluded from production counts.
- Contract coverage: 12 exports, 6 test sections, 38 engine assertions + 139 fixture assertions, covering normalization, aliases, dependency graph, matching, version boundaries, fail-closed paths, determinism and no-network behaviour.
- Advisory corpus: 84 GHSA seed items already present, **rights unresolved**; production-authorized = 0.
- No advisory identifier, severity, score or range was invented or imported during this pump.

## 11. Owner / legal / provenance blockers

| Blocker | Status | Effect on this pump |
|---|---|---|
| BLK-001 License grant for original content | BLOCKED_OWNER_DECISION | No LICENSE file created; no license claim added |
| BLK-002 Per-source redistribution authorization | BLOCKED_OWNER_DECISION | No real advisory imported; SCA stays synthetic |
| BLK-003 Production ingestion authorization (GATE-1/3/4) | BLOCKED_PRODUCTION_LOCK | No production counts, no ingestion, no publish |
| BLK-004 Approval expiry / refresh cadence | BLOCKED_OWNER_DECISION | Provenance recorded but not asserted as authorization |
| SCA rule-pack schema | OWNER DECISION PENDING | `packs/sca/` remains empty; no packs authored |
| CWE catalog additions (922, 522) and a `.npmrc` language id | SCHEMA DECISION PENDING | Three probe candidates stay unresolved rather than mis-mapped |
| D-13 (40 legacy records) | INACTIVE | Not reactivated, not counted as production |
| App pack loader | NOT IMPLEMENTED (Main App) | New packs have no runtime consumer yet; stated, not hidden |

## 12. Main App (read-only)

- Repository `mdraselislam0101-design/Drobon` was **not modified**. HEAD remains `c32c797a549453802bd6d82c5673d2a1728457a3`.
- No file, test, schema, dependency, database, deployment or documentation in the Main App was created, edited or deleted.
- Dataset content was **not** copied, embedded or bundled into the Main App.
- Relevant read-only finding carried forward: the SCA provider contract is `assess(coordinates) → {providerId, datasetStatus, advisories[]}`, and the app's pack loader for SAST/DAST packs is still not implemented. The 841 SAST / 68 DAST / 1,006 remediation assets therefore remain unreachable at runtime — recorded as an app-workstream gap, not a dataset defect.
- The new SCA contract functions mirror that provider seam (`ASSESSED` / `NOT_ASSESSED` / `NO_DATA_LOADED`), so future app wiring does not need a translation layer.

## 13. Worktree state

- Branch: `arena/a4caaeb8-drobon-dataset`; HEAD unchanged at `ed599c654e972cf517331bb504d65f3e8c2dbcf1`.
- Worktree: **2,313 modified, 447 untracked**, 0 deleted.
- This pump added untracked assets: 19 SAST rules, 3 DAST rules, 22 patterns, 22 records, 22 remediation, 35 eval cases, 3 cell sources, 5 SCA fixture files, 2 test/measurement scripts, and this report.
- Tracked modifications are count re-pins; no pre-existing payload asset was rewritten.
- **No Git write was performed**: no commit, push, PR, merge, tag, release, reset, clean or history rewrite. Nothing was deployed.

## 14. Remaining gaps and the next concrete batch

Honest distance to target: **SAST 841 / 1,000 (159 short)**, records 966 / 1,000 (34 short), DAST 68 / 1,000 arithmetically but 68/68 evaluated and structurally capped by the closed check vocabulary, SCA packs 0 with an owner blocker, and SAST independent-evaluation breadth at 104/841 (12.37%).

Next batch, in priority order:

1. **Batch 4 — DAST observation schema.** Add 2 new evaluator types (`response-header-crlf` for header-splitting, `response-header-duplicated` for multi-value confusion) with validator support, robustness tests, two new rules and eval cases. This is a schema change and must update every "closed 7-type" pin; it is taken as an explicit decision, not smuggled in as data.
2. **Batch 5 — SAST breadth in thin languages and remaining verified gaps.** Kotlin (9 rules), Swift (7) and Scala (11) are the thinnest language families; add only confirmed, CWE-mapped gaps, each with the full asset set and an independent eval case.
3. **Batch 6 — SAST evaluation depth.** Raise independently evaluated breadth from 104 toward the active set, prioritising `weak-cryptography` (93 rules, 11 evaluated), `secure-configuration` (89, 1) and `code-injection` (79, 4).
4. **Batch 7 — SCA packs.** Only after the owner schema decision; production data stays at 0 until BLK-001/BLK-002 clear.
5. **Vocabulary decision batch.** Resolve CWE-922, CWE-522 and the `.npmrc` language id, or record them as permanently out of scope so the three unresolved constructs can be closed honestly.

## 15. Confirmations

- No Main App source, test, config, schema, dependency, database or documentation was modified.
- No production database, VPS, deployment or configuration was touched.
- No dataset content was copied into the Main App.
- No Git write, release, tag, deploy or history rewrite occurred.
- No LICENSE file was created and no legal grant, permission, approval, signature or provenance was invented.
- No test was weakened, skipped, disabled, deleted, or relabelled to obtain a green run; the known failure and the UNASSESSED cases are preserved.
- No category is claimed at 100% except where the denominator is the complete active set and the inclusion rule says so (DAST evaluation 68/68; SCA contract capabilities 21/21; SAST validation 841/841 — **not** SAST coverage).

## 16. Reproduction

```bash
node scripts/gap-matrix.mjs --json /tmp/gap-matrix.json   # per-engine matrices + 40 construct probes
node scripts/test-sca-fixtures.mjs                        # SCA fixture corpus (139 assertions)
node scripts/inventory.mjs --check                        # current-state snapshot
node scripts/coverage-report.mjs --check                  # coverage accounting families
node scripts/run-eval.mjs > /tmp/eval.json                # independent evaluation report
node scripts/manifest.mjs --scope all --write /tmp/i.json && node scripts/manifest.mjs --scope all --check /tmp/i.json
npm test                                                  # full regression (17,502 assertions)
```

All percentages in this report carry numerator, denominator, inclusion rule and source in `scripts/coverage-report.mjs` output; no denominators are mixed.
