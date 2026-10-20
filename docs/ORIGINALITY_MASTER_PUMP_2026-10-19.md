# ORIGINALITY_MASTER_PUMP_2026-10-19.md — original-intelligence pump report

Dataset-only. Main App read-only at `c32c797`. No feed, credential, deployment,
database or Git operation was performed.

## 1. Baseline and final repository state

| | Baseline (before work) | Final |
|---|---|---|
| Branch / HEAD | `arena/a4caaeb8-drobon-dataset` / `ed599c6` (shallow, no upstream) | unchanged |
| Worktree | 23 M + 9 ?? | **31 M + 13 ??** |
| Tracked files | 4,217 | 4,217 |
| `npm test` | exit 0 — 16,539 assertions | exit 0 — **16,539 assertions** |
| Validators / vectors / inventory / manifest | all green; ingestion 4/4 BLOCKED | unchanged |
| Asset counts | 954 rules / 954 patterns / 914 records / 954 remediation / 61 CWE | **unchanged** |
| LICENSE | absent | absent (no licence added or implied) |

Counts, IDs and relationships were recorded before editing. No file was deleted
and no historical report was rewritten.

## 2. Existing assets preserved, improved or corrected

- **Preserved:** all 954 rules, 954 patterns, 914 records, 954 remediation
  entries, 61 CWE entries, 6 lessons, 3 templates, 2 engagements, 16 vectors,
  100 advisory files. Rules, patterns and records are byte-identical
  (`git status` shows no change under `packs/`, `knowledge/patterns`,
  `knowledge/records`).
- **Improved:** 7 remediation entries (`DPK-SAST-782/783/792/793/794/795/796`)
  were regenerated from their cell class so each names its language instead of
  repeating an identical sentence. This fixes the exact-duplicate remediation
  body and five exact `whyItMatters` repeats found by the new tool.
- **Corrected:** `data/asset-cells/sast-calls-5.json` — two class `why` strings
  now interpolate `{lang}` (the only content change; no IDs, severities, CWEs or
  detection logic changed).

## 3. New original assets created (and why)

| Asset | What | Why | Status |
|---|---|---|---|
| `scripts/originality-report.mjs` | deterministic duplication/provenance auditor (ids, exact bodies, shingle similarity, provenance, references) | the repo had no originality/duplication gate; only advisory identity grouping existed | **active**, wired into `npm test` + CI |
| `docs/ORIGINALITY_REPORT_2026-10-19.md` | findings, dispositions, limitations | evidence record | active |
| `docs/proposals/D13-legacy-records/` | 40 authored concept records + generator patch + activation checklist | closes the last structural knowledge gap **if the owner chooses** | **proposal only — not applied, not counted** |

The 40 proposed records are original DROBON wording derived from each rule's
documented mechanism; they are not copied from any catalog and reuse no text
from another record. They were **not** activated because D-13 is
`BLOCKED_OWNER_DECISION`; activating it in this pump would have been an owner
action. A throwaway validation run (generator + validators) passed and was
reverted; the tree is back at 914 records.

## 4. Capability matrix before/after

No capability status changed, because nothing was activated and no count was
inflated. `docs/CAPABILITY_COVERAGE_MATRIX.json` (33 rows) remains:

| Status | Before | After |
|---|---|---|
| COVERED_VERIFIED | 2 | 2 |
| APP_INTEGRATION_BLOCKED | 7 | 7 |
| RIGHTS_BLOCKED | 1 | 1 |
| NOT_APPLICABLE (evidence-backed) | 23 | 23 |

## 5. Duplicate / near-duplicate findings and disposition

| Finding | Count | Disposition |
|---|---|---|
| Duplicate canonical ids | 0 | — |
| Exact duplicate record bodies | 0 | — |
| Exact duplicate remediation bodies | 1 → **0** | fixed by regenerating 7 files |
| Exact repeated `whyItMatters` | 5 pairs → **0** | fixed by the same change |
| Record wording ≥ 0.85 | 0 of 417,233 (max 0.714) | — |
| Rule wording ≥ 0.90 | 1 of 454,581 | sibling rules; artifact of ≤2-char tokens (`c` vs `r`) being ignored |
| Remediation ≥ 0.90 / 0.85 | 8 / 19 of 386,038 | class-level guidance shared by sibling languages; accepted with caveat |

Similarity output is a review flag only; it is not evidence of copying.

## 6. Provenance and originality verification limits

`origin: "original-authored"` is a declaration backed by
`docs/ASSET_METHODOLOGY.md`, not an external attestation. No public catalog was
consulted, so the tool can prove internal uniqueness and provenance hygiene but
**cannot** prove the absence of derivation from an unseen external source.
Paraphrase and translation are invisible to shingles.

## 7. Synthetic evaluation (unchanged, re-run)

| Measure | Value |
|---|---|
| Cases | 89 (78 assessed + 11 UNASSESSED) |
| Outcomes | PASS 77, **FAIL 1** (`EVAL-SAST-008`, 1 FP in core) |
| TP / FP / FN | 46 / 1 / 0 → precision 0.9787, recall 1.0 |
| UNASSESSED preserved | `EVAL-CMD-023/024/025`, `EVAL-SAST-004/007/014/015/016`, `EVAL-SEC-111`, `EVAL-SQL-027/028` |
| Rules exercised | 28 of 954 (2.9%) |

No evaluation case was added, deleted, relabelled or weakened in this pump.

## 8. Actual test and validator results

`npm test` exit 0 — 16,539 assertions across 17 suite steps, including the new
`originality:check`. Validators: `validate` 0, `validate:sources` 0,
`validate:corpus` 0, `validate:packs` 0 (957 files), `validate:assets` 0
(1,908 files), `validate:audiences` 0 (965 files), `validate:cwe` 0 (61),
`validate:matrix` 0, `test:vectors` 16/16, `inventory:check` current,
`manifest --check` PASS, `ingestion-gates` 4/4 BLOCKED (exit 1, fail-closed —
reported separately from test failures, not as one).

## 9. Rights-blocked, integration-blocked and production-ineligible items

- **Rights-blocked:** all 1,969 provenance-bearing artifacts remain
  production-ineligible; no LICENSE exists; GHSA/OSV/NVD/CWE decisions are
  `OWNER_DECISION_REQUIRED`; ingestion gates 4/4 BLOCKED.
- **App-integration-blocked:** the seven pack/audience/vector capabilities
  (0 of 10 dataset-relevant capabilities are consumed by the App).
- **Production-ineligible by design:** 40 legacy rules remain without concept
  records until D-13 is answered; they are valid rules and remain fully usable.

## 10. Remaining gaps, risks and owner decisions

1. **D-13** — create the 40 concept records (proposal ready) or keep the exception.
2. **D-GHSA / D-OSV / D-NVD / D-CWE** — source-rights decisions (blocking).
3. **LICENSE grant** — G6/G16/G17; release and redistribution remain blocked.
4. **App contract** — pack/audience/provider loaders (App workstream, class E).
5. **Evaluation breadth** — 28/954 rules exercised; 11 UNASSESSED need real ground truth.
6. **Remediation diversification** — class-level text flagged at 8 pairs ≥0.90.
7. Risk: similarity tooling cannot prove external independence (documented).

## 11. Dataset-side completion (method stated, not pooled)

Scope: the 33-row capability matrix. Excluded: `NOT_APPLICABLE` rows (23) with
evidence-backed reasons, because no Dataset requirement exists for them.

| Dimension | Numerator / denominator | Result |
|---|---|---|
| A. Capability mapping | 33 / 33 rows mapped to App evidence | 100% |
| B. Verified coverage | 2 / 10 dataset-relevant capabilities COVERED_VERIFIED | **20%** |
| C. Asset integrity | rules with pattern + remediation + resolvable CWE: 954 / 954; patterns with record: 914 / 954 | 100% / **95.8%** |
| D. Evaluation | assessed 78 / 89; PASS 77 / 89; UNASSESSED 11 | 87.6% / 86.5% (precision 0.9787, recall 1.0) |
| E. Provenance metadata | 1,969 / 1,969; legal grant 0 / 1,969 | 100% metadata / **0% grant** |
| F. Production eligibility | 0 / 100,000 target; publish-ready 0 | **0%** |

No single aggregate is reported: B, C, D, E and F measure different things.

## 12. Main App integration status (separate)

0 of 10 dataset-relevant capabilities integrated; 9 of 10 contract-ready;
1 (SCA advisory matching) blocked by the null provider and rights. The Main App
was not modified; no Dataset asset was copied into it; its worktree is clean.

## 13. Publish readiness: **NO-GO**

Reasons: no LICENSE or redistribution grant (G6/G16/G17), production lock G8,
0 verified production records against the 100,000 target, and 0 integrated
App capabilities. Technical validity of the corpus does not confer eligibility.

## 14. Git operations

**None.** No commit, push, PR, tag, release, deploy or history rewrite. All
changes are uncommitted working-tree changes (31 M + 13 ??), and the Main App
and production systems were not touched.
