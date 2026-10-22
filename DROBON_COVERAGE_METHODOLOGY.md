# DROBON_COVERAGE_METHODOLOGY — how every percentage in this audit is computed

Audit date 2026-10-16. This document defines denominators, status vocabulary,
scoring, and exclusions for `DROBON_MASTER_COVERAGE_AUDIT.md` and the
`DROBON_*_COVERAGE.csv` / `DROBON_COVERAGE_EVIDENCE.json` artifacts. The
machine-readable ledger (`DROBON_COVERAGE_EVIDENCE.json`,
`schemas: drobon.coverage.evidence/v1`) is the single source of truth; CSVs are
projections of it; `scripts/test-doc-drift.mjs` section 8 re-derives its file
counts from the tree on every test run, so the ledger cannot go stale silently.

## 1. Source revisions

| Input | Revision | Access |
|---|---|---|
| Main App (`Drobon`) | `c32c797a549453802bd6d82c5673d2a1728457a3` (main, merge PR#4) | read-only clone at `/home/user/Drobon-app-ref`; NEVER modified |
| Dataset (`Drobon-Dataset`) | `arena/9fe99288-drobon-dataset` @ `fca2c39d1553bb76613d0821bf76e91ee5e8e868` | this repository |
| App capability audit | `docs/USER_TYPE_CAPABILITY_AUDIT.md` (Pump 22, revalidated 2026-09-29) | authoritative requirement source |
| App engine docs | `docs/SAST.md` `SCA.md` `SECRETS.md` `DAST.md` `FINDINGS.md` `REPORTS.md` `ASSISTANT.md` `USERTYPES.md` `SECURITY.md` | requirement detail |
| Dataset seam inventory | `docs/SCOPE.md` (21-row seam table), `docs/PROVIDER_MAPPING.md`, `docs/CAPABILITY_COVERAGE.md` | dataset-dependency classification |

## 2. Requirement ledger

Each unique requirement carries: stable ID (`R-<AREA>-<nn>`), source repo +
commit + doc location, description, feature, engine, applicable UserTypes,
dataset-dependency class, concrete dataset items, tests, platform, status,
explicit subrequirement counts (for partials), gap, blocker, next action, work
class (A–G), priority (P0–P3). Semantic duplicates were merged (e.g. the two
"100-record seed" claims in different docs are one requirement).

**Dataset-dependency classes** (used to decide what enters the Dataset score):

- `REQUIRED` — the capability needs dataset intelligence (SCOPE.md seam rows
  1, 15, 19 and the advisory records themselves).
- `SUPPLEMENTAL` — the app is self-contained today; the dataset holds
  loader-future intelligence (SCOPE.md rows 12–18) that extends the capability.
- `NONE` — app-code/UI/infra/entitlement requirements with **no dataset
  consumption** (SCOPE.md rows 2–11, 20–21). Excluded from Dataset coverage
  denominators with the justification recorded per row
  (`NOT_APPLICABLE_WITH_JUSTIFICATION`); still listed so nothing is silently
  dropped.

## 3. Status vocabulary (mutually exclusive)

`VERIFIED_FULL` · `VERIFIED_PARTIAL` · `IMPLEMENTED_NOT_VERIFIED` ·
`MISSING_DATASET` · `MISSING_ENGINE_OR_INTEGRATION` · `NOT_IMPLEMENTED` ·
`BLOCKED_OWNER_DECISION` · `BLOCKED_LICENSE` · `BLOCKED_PRODUCTION_LOCK` ·
`BLOCKED_EXTERNAL_DEPENDENCY` · `NOT_ASSESSED` · `NOT_APPLICABLE_WITH_JUSTIFICATION`.

## 4. Scoring (per Phase I of the pump brief)

Verified completion points per requirement: `VERIFIED_FULL = 1.0`;
`VERIFIED_PARTIAL = passing/total` from **explicit named subrequirements** (e.g.
R-SCA-01: shape-valid + vector-matched proven, breadth 0/100k unproven → 2/3);
everything else = 0, including all `BLOCKED_*` (blocked work earns no verified
credit until its gate clears) and `NOT_ASSESSED`.

```
Verified Coverage % = 100 × Σ verified points / count(applicable requirements)
```

- **No weighting** is used: every requirement counts 1. Weighted variants were
  rejected because no defensible cross-domain weight exists; unweighted counts
  are always reported alongside percentages.
- `IMPLEMENTED_NOT_VERIFIED` contributes 0 verified points but is counted in
  the separate **Technical implementation completion** figure
  (FULL + PARTIAL + IMPLEMENTED_NOT_VERIFIED) / applicable.
- Each percentage is published as a `(numerator points, denominator count)`
  pair. Where a trustworthy denominator cannot be established the value is
  `NOT_ASSESSED`, never an estimate.

## 5. Denominators (fixed, disclosed)

1. **Main App-to-Dataset verified coverage** — all `REQUIRED`+`SUPPLEMENTAL`
   rows (52 of 64 ledger rows).
2. **Dataset-required-only coverage** — `REQUIRED` rows (23) — the strict
   runtime-seam score.
3. **Per-engine coverage** — subset of (1) by engine (SAST, SCA-intel, Secrets,
   DAST, Remediation, Findings, Audience, Reports).
4. **Per-UserType coverage** — subset of (1) tagged with that UserType (`ALL`
   counts for every type). UserType is workflow/presentation over shared
   engines (app `USERTYPES.md`), so rows are shared, not duplicated engines.
5. **Report-outcome coverage** — the 13 `R-REP-*` rows, each with 7 subreqs
   (A contract · B fields/mappings · C dataset intel · D engine execution ·
   E evidence traceability · F e2e test · G production-intelligence
   authorization); fraction = passing/7, G marked N/A (excluded from that row's
   denominator) for reports that need no production intelligence.
6. **End-to-end verified** — share of (1) at `VERIFIED_FULL` (evidence chain
   complete to tests).
7. **Paid-tool comparable documented capability coverage** — fixed 22-dimension
   list (CSV header documents all 22); per tool, denominator = dimensions that
   tool **documents** (vendor "No" or `UNKNOWN` excluded per tool);
   DROBON score per dimension = 1.0 / 0.5 / 0 against **documented** app+dataset
   capability (0.5 = present but narrower scope). `UNKNOWN` vendor details are
   never scored as absent. No cross-tool blended percentage is reported.

## 6. Evidence rules

- A rule file / doc entry / schema validation alone is **not** end-to-end
  coverage; `VERIFIED_FULL` requires executed tests naming that artifact
  (counts in `DROBON_COVERAGE_EVIDENCE.json` `items`/`tests` fields).
- Duplicate records never count as independent capability (84 identity items,
  not 100 files).
- An untested pattern is not a proven detection (all 950 patterns carry
  executed positive+negative tests — pack-tests 3,966).
- High rule count ≠ broad real-world coverage (reachability is reported
  separately: 560/792 reachable in the app engine (549 catalog-gated + 11 any-file), 25 partial, 207 unreachable).
- The 1,000-rule-per-pack figure is a **planning target**; current counts are
  evidence-gated and are never padded.
- Vendor claims come only from public documentation accessed 2026-10-16
  (sources cited per row in `DROBON_PAID_TOOL_BENCHMARK.csv`); proprietary
  rule counts and database sizes are never asserted.

## 7. Known limitations of this methodology

1. App-side test evidence is cited from the app's own documents and tests at
   `c32c797` (read-only). The app suite was **not re-executed** in this
   workspace (would require installing app dependencies in the app checkout;
   out of Dataset scope) — app test counts are reported as *documented at
   c32c797*, marked `NOT_RUN` where execution proof is claimed only by the app
   docs.
2. Paid-tool comparison covers **documented comparable capability only**; it is
   not a detection-quality bake-off and must never be read as "% of a paid
   tool's proprietary database".
3. Shallow clone of the Dataset repo: pre-`12edda1` history unverifiable
   locally (unchanged limitation).
