# ULTIMATE_MASTER_PUMP_2026-10-19.md — end-to-end Dataset engineering report

Dataset-only. Main App read-only at `c32c797`. No feed, credential, deployment,
database or Git operation was performed. This report supersedes nothing: it adds
to `ORIGINALITY_MASTER_PUMP_2026-10-19.md` (originality audit) and
`MAIN_APP_DATASET_COVERAGE_2026-10-18.md` (capability coverage), both preserved.

## 1. Baseline → final state

| | Baseline | Final |
|---|---|---|
| Branch / HEAD | `arena/a4caaeb8-drobon-dataset` / `ed599c6` (shallow, no upstream) | unchanged |
| Worktree | 31 M + 13 ?? | **32 M + 58 ??** (44 new eval cases + 6 report/tool files; 1 new modified file) |
| `npm test` | exit 0 — 16,539 assertions | exit 0 — **16,541 assertions** |
| Rules / patterns / records / remediation | 954 / 954 / 914 / 954 | **unchanged** |
| Eval cases | 89 (78 assessed, 11 UNASSESSED) | **132 (121 assessed, 11 UNASSESSED)** |
| Rules with independent eval | 28 | **58** |
| LICENSE | absent | absent |
| Owner decisions | 1 approved (D-ORIG) + 4 pending | unchanged |

## 2. What was implemented (not just proposed)

### 2.1 Evaluation breadth — 28 → 58 rules (+43 cases)

Two independently authored batches (23 + 20 cases) added **12 new cohorts**:

`path-and-ssrf`, `redirect-and-reflection`, `deserialization`,
`config-hardening`, `logging-and-output`, `crypto-misuse`, `transport`,
`access-control`, `container`, `disclosure`, `ci-security`,
`memory-and-permissions`.

Each case declares positive **and** negative or boundary counterparts where the
rule permits one (16 forbidden-detector cases), so a rule that fires on
everything cannot pass. Coverage moved per family: SAST 24 → 53, secrets 1 → 4,
DAST 1 → 1.

| Metric | Baseline | Final |
|---|---|---|
| Cases | 89 | **132** |
| Assessed / UNASSESSED | 78 / 11 | **121 / 11** |
| TP / FP / FN | 46 / 1 / 0 | **76 / 1 / 0** |
| Precision / recall | 0.9787 / 1.0 | **0.9868 / 1.0** |
| Preserved failure | `EVAL-SAST-008` | `EVAL-SAST-008` (unchanged) |

Two authoring defects were found and corrected during the batch — both were
**evidence-text** defects, not outcome changes: `EVAL-LOG-002` declared
`r.FormValue("val")` while the rule's match ends at the identifier, and
`EVAL-CONT-002` declared a closing bracket the regex does not consume. Rule
ids, line numbers and the issue-present ground truth were never altered; no
expected outcome was flipped to obtain a pass.

### 2.2 New tooling

| Script | Purpose | Wired |
|---|---|---|
| `scripts/eval-coverage-report.mjs` | measures independent evaluation breadth (rules exercised / rules shipped), per family and category | `npm run eval:coverage`, CI |
| `scripts/originality-report.mjs` (extended) | now also checks eval-case duplication, case provenance and case→rule references | `npm run originality:check`, `npm test` + CI |
| `scripts/test-eval.mjs` (extended) | breadth ratchet (≥58 rules) + every named rule exercised | `npm test` |

### 2.3 Pinned counts moved with the change, deliberately

`test-eval` expectations (132 cases, 76/0/1, ≥58 rules), the
`CAPABILITY_GAP_MATRIX` `test-eval` total (39/39 → 41/41), the generated
`docs/CURRENT_INVENTORY.json` (eval 132/121/11), the capability matrix's SAST /
Secrets / DAST evaluation evidence, and `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md`.
No count was changed to hide a gap; every change tracks a real artifact.

## 3. Four-UserType results (shared core, no duplicate packs)

| UserType | Engines exercised by evidence | Dataset-relevant coverage | Specific gap |
|---|---|---|---|
| DEVELOPER | SAST, Secrets, SCA-inventory, findings, remediation, reports | SAST 792 / Secrets 97 / remediation 954 / CWE 61 all validated | packs not loadable by the App (`APP_INTEGRATION_BLOCKED`) |
| STUDENT | SAST, Secrets, lessons | 6 lessons validated, practice executed against target rules | App ships its own 4-lesson catalog; no Dataset lesson loader |
| SECURITY_PROFESSIONAL | SAST, Secrets, DAST, SCA-intel, assessments | 3 templates, 2 engagements validated | SCA matching rights-blocked; templates not loadable |
| PENTESTER | passive DAST, engagement aids | 65 DAST rules, 2 passive-only engagement aids | no offensive/exploit data — prohibited boundary by design |

No UserType received a duplicated rule, pack or record. Entitlement (FREE/PRO)
remains separate from UserType classification and from Dataset coverage.

## 4. Rule → Pattern → Record → Remediation integrity

| Chain element | Result |
|---|---|
| Rules with ≥1 pattern | 954 / 954 |
| Rules with a remediation entry | 954 / 954 (0 missing, 0 extra) |
| Rules with a concept record | **914 / 954** (40 legacy rules; D-13 owner decision) |
| Rules with ≥1 positive and ≥1 negative bundled test | 954 / 954 |
| Pattern → rule references dangling | 0 |
| Record → pattern/rule references dangling | 0 |
| Rules with a resolvable CWE | 954 / 954 |
| Rules sharing a regex with an overlapping language set | **0** (32 regexes are reused across *disjoint* language sets — not duplicates) |

Quality scan (new, this pump): 0 rules missing limitation/CWE/category, 0
patterns missing `fpNotes`, 0 patterns with fewer than 2 examples, 0 remediation
entries with empty `actions`. 113 records have descriptions under 80 characters
(e.g. `In matlab, eval evaluates strings. The remedy is function handles.`);
they remain accurate but terse. **Disposition: recorded, not rewritten** — the
records carry mechanism, applicability and risk fields, are not App-consumed,
and 72 scattered cell templates would have to change for a cosmetic gain.

## 5. D-13 disposition — BLOCKED, unchanged

`patterns 954 / records 914`. The 40 pre-generator rules still have no concept
record. The validated proposal at `docs/proposals/D13-legacy-records/` remains
**inactive**: no `data/legacy-records.json`, no generator patch applied, no
`recId` in the manifest, no count moved. Owner decision D-13 is
`BLOCKED_OWNER_DECISION`; activating it without a recorded owner answer would be
an owner action.

## 6. Originality and provenance

| Check | Result |
|---|---|
| Hard defects (ids, exact bodies, references, origins, eval-case duplicates) | **0** |
| Duplicate rule/pattern/record ids | 0 |
| Duplicate eval cases | 0 |
| Eval cases with non-original origin | 0 |
| Near-duplicate record wording ≥ 0.85 | 0 of 417,233 pairs (max 0.714) |
| Near-duplicate remediation ≥ 0.90 | 8 of 386,038 (sibling-language class text) |
| Third-party provenance fields on authored content | 0 |

Limitations unchanged: lexical similarity cannot prove independent creation, and
no public catalog was consulted (production lock), so absence of derivation from
an external source cannot be demonstrated either way.

## 7. Rights and production status

- No LICENSE file; no licence inferred or added. All 1,969 provenance-bearing
  artifacts remain production-ineligible.
- `OWNER_DECISIONS.json` untouched: GHSA/OSV/NVD/CWE still
  `OWNER_DECISION_REQUIRED`; D-ORIG `APPROVED` (authorship only, not a licence).
- Ingestion gates 4/4 BLOCKED; `ingestion-gates.mjs` exits 1 by design.
- No real feed, advisory, exploit or signature data was fetched or imported.
  All new fixtures are synthetic, labelled `testOnly` + `synthetic`, and live
  outside every counted directory.

## 8. Verification (final run, after the last edit)

| Command | Result |
|---|---|
| `npm test` | **exit 0 — 16,541 assertions** (17 suite steps) |
| `validate` / `validate:sources` / `validate:corpus` / `validate:packs` / `validate:assets` / `validate:audiences` / `validate:cwe` / `validate:matrix` | 0 errors each (957 pack files, 1,908 asset files, 965 audience files) |
| `test:vectors` | 16/16 |
| `inventory:check` | up to date |
| `validate:capability-coverage` | 656 assertions, 0 failed |
| `originality:check` | 0 hard defects |
| `eval:coverage` | 58/954 rules (6.08%) |
| `render-capability-coverage --check` | up to date |
| `manifest --check` | PASS (4,119 files) |
| `test:determinism` | 5/5 |
| `ingestion-gates` | 4/4 BLOCKED — **expected fail-closed block, not a test failure** |

Preserved and not counted as pass: 1 evaluation FAIL (`EVAL-SAST-008`), 11
UNASSESSED cases, 40 record-less patterns (owner-blocked), 0 production-eligible
assets.

## 9. Completion calculation (separate dimensions, stated denominators)

| # | Dimension | Numerator / denominator | Result |
|---|---|---|---|
| 1 | UserType workflow coverage | 4 / 4 workflows mapped to the shared core | 100% (mapping) |
| 2 | Engine capability coverage | 2 / 10 dataset-relevant capabilities `COVERED_VERIFIED` | **20%** |
| 3 | Rule/pattern/record/remediation integrity | 954/954 rules × (pattern + remediation + CWE); 914/954 records | 100% / **95.8%** |
| 4 | Evaluation coverage | assessed 121/132; rules exercised 58/954 | 91.7% / **6.1%** |
| 5 | Originality/provenance | 0 hard defects; 1,969/1,969 provenance metadata | 100% metadata |
| 6 | Legal/rights eligibility | 0 / 1,969 granted | **0%** |
| 7 | Main App integration | 0 / 10 integrated; 9 / 10 contract-ready | **0% / 90%** |
| 8 | Production data readiness | 0 / 100,000 verified advisories | **0%** |
| 9 | Release readiness | 13 / 17 gates PASS (3 owner, 1 production-lock) | 76.5% |

No pooled score is given: the dimensions measure different things and a single
number would misrepresent at least six of them.

## 10. Remaining gaps and exact blockers

| Gap | Blocker class | Exact unblock condition |
|---|---|---|
| 40 records for legacy rules (D-13) | OWNER | recorded D-13 answer; proposal ready |
| Advisory breadth 0/100,000 | OWNER + PRODUCTION | GHSA/OSV/NVD decisions; GATE-1/3/4 |
| Redistribution / publication | LEGAL | LICENSE grant or documented per-source terms |
| Pack/audience/vector loaders | APP WORKSTREAM | loader shipped in the Main App repo |
| Evaluation breadth 58/954 | DATASET ENGINEERING | further original cases (safe, ongoing) |
| 11 UNASSESSED cases | ANALYSIS LIMIT | requires data-flow analysis or a policy decision |
| 113 terse records | QUALITY | per-cell authoring, cosmetic today |
| 8 class-level remediation near-duplicates | QUALITY | per-language authoring |

## 11. Git and scope confirmation

**No Git operation was performed** — no commit, push, PR, tag, release, deploy or
history rewrite. The Main App repository was not modified and contains no Dataset
asset; its worktree is clean. No production database, VPS or deployed system was
touched. All changes are uncommitted working-tree edits (32 M + 58 ??), with all
prior user work, proposals, known failures and historical reports preserved.
`docs/proposals/` remains untracked and inactive.

## 12. Status

```
DATASET ENGINEERING: COMPLETE FOR AUTHORIZED SCOPE
EXTERNAL BLOCKERS: OPEN  (owner D-13, GHSA/OSV/NVD/CWE, LICENSE, App loaders)
PRODUCTION READINESS: NO-GO
```

`COMPLETE FOR AUTHORIZED SCOPE` means every gap that Dataset-only work can close
without an owner, legal, production or App-repo action has been closed and
verified. It does **not** mean the Dataset is 100% complete for the Main App:
2 of 10 dataset-relevant capabilities are `COVERED_VERIFIED`, 7 await the App
consumer, 1 is rights-blocked, and production eligibility is 0.
