# MAIN_APP_DATASET_COVERAGE_2026-10-18.md — Main App ↔ Dataset capability coverage audit

Scope: the **Dataset repository only**. The Main App (`mdraselislam0101-design/Drobon`)
was read read-only; no App file, test, config, document, migration or history was
changed, and no Dataset asset was copied into it. No production data, feed,
network intelligence or deployment was touched.

Question answered: *does this Dataset contain every required, legally usable,
sufficiently tested intelligence asset for each implemented/approved Main App
capability, shared engine and all four UserType workflows?*

**Answer: NO — 2 of 10 dataset-relevant capabilities are COVERED_VERIFIED, 7 are
APP_INTEGRATION_BLOCKED, 1 is RIGHTS_BLOCKED; production eligibility is 0.**
The assets mostly exist and validate; they are not consumable by the App and not
licensed for production use. See §12 and §14.

## Deliverable map (the 14 required artifacts)

| # | Required deliverable | Where in this repository |
|---|---|---|
| 1 | Baseline report | §1 |
| 2 | Main App capability inventory | §2 + `docs/CAPABILITY_COVERAGE_MATRIX.json` (`appInventoryCoverage`, 17 entries) |
| 3 | Dataset inventory and counts with counting rules | §3 |
| 4 | Canonical Capability ↔ Dataset matrix | `docs/CAPABILITY_COVERAGE_MATRIX.json` (machine) + `.md` (rendered) |
| 5 | UserType × Capability × Dataset view | §5 + rendered matrix §3 |
| 6 | Asset-class coverage and quality | §6 |
| 7 | Relationship / integrity report | §7 |
| 8 | Evaluation report (failures and UNASSESSED kept) | §8 |
| 9 | App integration register | §9 |
| 10 | Owner / legal register | §10 |
| 11 | Regression and validator report | §11 |
| 12 | Percentage worksheet (A–H, separate) | §12 |
| 13 | Remaining-work register, dependency-sorted | §13 |
| 14 | Release-gate matrix + recommendation | §14 |

## 1. Baseline (recovered before any analysis)

| Fact | Value |
|---|---|
| Repository | `mdraselislam0101-design/Drobon-Dataset` |
| Branch | `arena/a4caaeb8-drobon-dataset` |
| HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (= `main`, no upstream, shallow clone) |
| Tracked files | 4,217; worktree carried 22 modified + 4 untracked files before this audit. This audit adds 1 modified file (`README.md`) and 5 new files (matrix JSON + MD, this report, validator, renderer) → 23 M + 9 ?? at completion; no asset tree changed |
| LICENSE | absent (invariant preserved; no licence inferred or added) |
| Baseline suite | `npm test` exit 0 — **15,883** assertions; all eight validators exit 0; `inventory:check` up to date; ingestion gates 4/4 BLOCKED by design |
| Main App reference | `c32c797a549453802bd6d82c5673d2a1728457a3`, read-only probe; App `apps/api` depends only on `@drobon/shared` — no Dataset package, path or feed reference exists |

## 2. Main App capability inventory (read-only, `c32c797`)

Evidence read: `USER_TYPE_CAPABILITY_AUDIT.md` (Pump 22), `USERTYPES.md` (Phase 20
feature matrices), `SAST.md`, `SCA.md`, `SECRETS.md`, `DAST.md`, `FINDINGS.md`,
`REPORTS.md`, `ASSISTANT.md`, `DEVELOPER.md`, `STUDENT.md`,
`SECURITY_PROFESSIONAL.md`, `PARTNERS.md`, `ADMIN.md`, plus the rule catalogs in
`apps/api/src/scans/{sast,secrets,dast}/rules.ts` and the single provider seam
`apps/api/src/scans/sca/provider.ts`.

- Shared engines: SAST (50 inline `DG-SAST` rules), Secrets (6 `DG-SEC` rules),
  passive DAST (8 `DG-DA*T` rules), SCA inventory + CycloneDX SBOM, findings
  lifecycle, reports (JSON/Markdown; Phase 22 adds SARIF 2.1.0 and a standalone
  SBOM export), deterministic assistant (`provider: NONE`), projects/scans/jobs/
  quotas, assessments, admin/payments/partners.
- There is **exactly one Dataset seam**: `assess(coordinates) →
  { providerId, datasetStatus, advisories[] }`. Under `VULN_INTEL_PROVIDER=none`
  the Null provider returns `NO_DATA_LOADED` and the scan honestly reports
  `NOT_ASSESSED`. No pack, pattern, record, remediation, lesson, template or
  engagement loader exists anywhere in `apps/api/src` (no `readFile`/path/env
  reference to Dataset content outside uploaded sources).
- App test evidence (read-only, 68 files / 748 `test(`/`it(` cases in
  `apps/api/test`) pins the seam: `scaEngine.test.ts` asserts the Null provider
  yields `NOT_ASSESSED` / `NO_DATA_LOADED` / `providerId: none` with zero
  advisories and intact inventory, and exercises a stub provider that round-trips
  one synthetic advisory end-to-end. No App test loads a Dataset file.
- Classification used: A implemented+verified, B approved-not-implemented,
  C proposed/undocumented, D app-blocked, E owner/legal-required. A missing App
  implementation is recorded as a Dataset defect **only** where a documented
  Dataset requirement exists; none of the B/C/D capabilities has one.

## 3. Dataset inventory and counting rules

| Asset class | Count | Counting rule / source | Production-eligible |
|---|---|---|---|
| SAST rules | 792 | `*.json` in `packs/sast/v1/rules`, ids `DPK-SAST-###`, unique | 0 (no licence) |
| Secrets rules | 97 | `*.json` in `packs/secrets/v1/rules` (includes `DPK-SEC-108`) | 0 |
| DAST rules | 65 | `*.json` in `packs/dast/v1/rules`, 7 closed check types | 0 |
| Rules, total | **954** | 792 + 97 + 65; ids unique | 0 |
| Patterns | 954 | `knowledge/patterns/*.json`, 1:1 with rules | 0 |
| Records | 914 | `knowledge/records/*.json`; 40 legacy patterns intentionally have none (BLK-013) | 0 |
| Remediation | 954 | `knowledge/remediation/*.json`, keyed `ruleId`, exactly 1:1 | 0 |
| CWE entries | 61 | `knowledge/cwe/*.json`, version pinned 4.20 | 0 |
| Lessons / templates / engagements | 6 / 3 / 2 | `learning/lessons/`, `assessments/templates/`, `engagements/` | 0 |
| Provider vectors | 16 | `interop/provider-vectors.json` cases | 0 |
| Advisory records | 100 files = 78 ids = 84 items | real records only; 3 further files are labelled fixtures and excluded from production counts | 0 verified (target 100,000) |
| Evaluation cases | 89 | `data/eval-cases/*.json`; 78 assessed + 11 UNASSESSED | synthetic only |

Classes kept apart: **total** (above), **unique ids** (equal to file counts,
verified), **eligible-production** (0), **synthetic-only** (89 eval cases +
3 advisory fixtures), **rights-blocked** (all 1,969 provenance-bearing artifacts,
since no licence grant exists), **unconnected** (3,803 artifacts with no App
consumer: 954 rules + 954 patterns + 914 records + 954 remediation + 6 lessons +
3 templates + 2 engagements + 16 vectors), **unresolved-quality** (40 patterns
without records; 1 false positive; 11 UNASSESSED cases).

## 4. Capability ↔ Dataset matrix

Canonical file: `docs/CAPABILITY_COVERAGE_MATRIX.json` (schema
`drobon.capability-coverage/v1`, 33 stable `DCC-*` rows, rendered to
`docs/CAPABILITY_COVERAGE_MATRIX.md`). Each row carries: capability id/name,
App inventory refs and source files, engines and UserTypes, required data
contract, required asset classes, dataset asset paths with counts and counting
rules, required relationships, evaluation evidence, production eligibility,
rights status, App integration dependency, coverage status, verification
commands, exact remaining work and the owner/legal decision.

| Status | Rows | Capabilities |
|---|---|---|
| COVERED_VERIFIED | 2 | `DCC-REMEDIATION`, `DCC-CWE` |
| APP_INTEGRATION_BLOCKED | 7 | `DCC-SAST`, `DCC-SECRETS`, `DCC-DAST`, `DCC-LESSONS`, `DCC-ASSESSMENT-TEMPLATES`, `DCC-ENGAGEMENTS`, `DCC-INTEROP` |
| RIGHTS_BLOCKED | 1 | `DCC-SCA-VULN` |
| NOT_APPLICABLE | 23 | platform, commercial, report, assistant, App-product gaps, prohibited boundaries |
| PARTIAL / MISSING / OWNER_DECISION_BLOCKED / NOT_ASSESSED | 0 | — |

Decision rules are stored in the matrix (`decisionRules`). A row is never
COVERED_VERIFIED from rule counts alone: it needs a documented requirement, the
assets, validated relationships, executable evidence and a verification basis
that does not depend on a missing loader.

## 5. UserType view

The four profiles are presentation/workflow layers over **one** engine set and
**one** Dataset. No profile owns a rule pack and none may add one; the matrix
enforces `userTypeSpecificDatasetAssets: []` for all four.

| UserType | Mapped capabilities | Dataset-specific assets | Dataset-relevant outcome |
|---|---|---|---|
| DEVELOPER | 16 | 0 | SAST/Secrets DAST-free map: packs blocked on loader; no Developer asset exists or is required |
| STUDENT | 17 | 0 | Lessons/templates present (6/3) but unused by the App's own 4-lesson catalog → integration gap, not an asset gap |
| SECURITY_PROFESSIONAL | 18 | 0 | Assessment templates (3) contract-ready; assessment state is App-owned; SCA intel rights-blocked |
| PENTESTER | 18 | 0 | Passive DAST shared; exploit/payload/chaining explicitly RESERVED and absent by design |

Entitlement/access restriction (plan, quota, role) is recorded separately from
intelligence coverage: `DCC-PLAN-ENTITLEMENT` is NOT_APPLICABLE because no
Dataset asset participates, not because access is restricted.

## 6. Asset-class quality (quality, not quantity)

- **IDs/canonicalisation:** all 954 rule ids, 954 pattern ids and 914 record ids
  are unique and follow `DPK-*`; there are no duplicates or id collisions with
  the App's `DG-*` catalog (so packs could be merged without renaming).
- **Required fields:** every rule has id, severity (rule-fixed), category, CWE,
  pattern refs, executable positive/negative examples; every secrets rule has
  `redact: true` (97/97), 96 a `denylist` veto and 1 `matchOnlyEvidence`.
- **Severity/confidence:** rules are HIGH 519 / MEDIUM 323 / LOW 112 (no
  CRITICAL in rule packs by design); secrets confidence HIGH 84 / MEDIUM 12 /
  LOW 1 — confidence is only present where the rule justifies it.
- **Applicability:** 111 language tags across SAST (11 rules universal); secrets
  and DAST rules are language-agnostic. The contract's hyphenated-tag limitation
  (`github-actions`, `shell-posix`) is documented in `docs/PACKS.md`.
- **Domain coverage:** SAST 49 categories (injection, memory safety, crypto,
  deserialization, access control, transport, CI, IaC via terraform/yaml tags);
  secrets 6 categories (cloud/service/generic/private-key/hardcoded); DAST 12
  categories over the closed 7-check passive vocabulary. No active/exploit,
  CVSS/KEV/EPSS, compliance-mapping or attestation data exists — each is a
  documented non-requirement (matrix rows `DCC-CVSS-KEV-EPSS`,
  `DCC-COMPLIANCE-MAPPING`, `DCC-SUPPLY-CHAIN`, `DCC-EXPLOIT-RESERVED`).
- **False positives / limitations:** one synthetic false positive is preserved
  (`EVAL-SAST-008`); 11 cases remain UNASSESSED rather than guessed; every rule
  states its lexical limits and every pattern carries `limitations`/`fpNotes`.
- **Presence ≠ detection:** the only executed detection evidence is the
  per-rule positive/negative pack tests (954/954) and 89 synthetic eval cases
  (28 distinct rules exercised = 2.9% of the pack). No claim of real-world
  effectiveness is made anywhere in this audit.

## 7. Relationship integrity (recomputed this audit)

| Relationship | Result |
|---|---|
| rule → pattern (`patternRefs` ↔ `linkedRules`) | 954/954 rules have ≥1 pattern; 0 dangling refs |
| pattern → record | 914 patterns have a record; 40 legacy patterns have none (BLK-013, documented); 0 dangling refs |
| rule → remediation | 954/954 exactly one entry, 0 missing, 0 extra |
| rule/remediation → CWE | every declared CWE resolves in `knowledge/cwe`; App-used ids 16/16 resolve |
| advisory identity | 100 files → 78 ids → 84 items, 9 multi-file shards, 0 conflict tuples |
| vectors → advisories | 16/16 vectors resolve (including explicit zero-hit cases) |

The App-rule CWE subset had never been counted (`CAPABILITY_COVERAGE.md` said
"app-referenced subset NOT re-counted"); this audit resolves it: 16 distinct
`DG-*` CWE ids, all present; 45 Dataset CWE entries are not referenced by the
App and remain general reference material.

## 8. Evaluation report

Source: `npm run eval` (deterministic, synthetic, no network), re-run 2026-10-18.

| Measure | Value |
|---|---|
| Cases total | 89 (cohorts: core 23, cmd-injection 26, sql-concat-xlang 28, secret-userinfo 12) |
| Assessed / UNASSESSED | 78 / 11 (UNASSESSED excluded from metrics, never counted as pass) |
| Outcomes | PASS 77, FAIL 1 |
| TP / FP / FN | 46 / 1 / 0 → precision 0.9787, recall 1.0 |
| Cohort precision | core 0.9231; other three cohorts 1.0 |
| Preserved failure | `EVAL-SAST-008` (1 FP, core cohort) — not deleted or weakened |
| UNASSESSED (11) | `EVAL-CMD-023/024/025`, `EVAL-SAST-004/007/014/015/016`, `EVAL-SEC-111`, `EVAL-SQL-027/028` |
| Rules exercised | 28 distinct rules (23 SAST, 4 secrets, 1 DAST) = 2.9% of 954 |
| Pack-level detection evidence | 954/954 rules execute ≥1 positive and ≥1 negative example |

## 9. App integration register

| Capability | Dataset side | App side | Integration status |
|---|---|---|---|
| SAST / Secrets / DAST packs | complete, validated | no loader; 50 + 6 + 8 inline `DG-*` rules | CONTRACT_READY_NOT_INTEGRATED |
| SCA vulnerability matching | 100 seed records, 16 vectors | `VULN_INTEL_PROVIDER=none`, Null provider, no real provider; App tests pin Null → `NOT_ASSESSED` and a stub-provider round-trip | BLOCKED_PROVIDER_LOCKED |
| Remediation / CWE | complete, 1:1, resolvable | App computes its own guidance and CWE ids | DATASET_SIDE_EXECUTABLE (verified against App contract shapes) |
| Lessons / templates / engagements | 6 / 3 / 2 validated | no loader; App ships its own 4-lesson catalog and assessment store | CONTRACT_READY_NOT_INTEGRATED |
| Provider vectors | 16/16 | shape accepted by the App stub-provider test, but no Dataset file is loaded by it | CONTRACT_READY_NOT_INTEGRATED |

**Documented App drift (read-only finding, not fixed here):** `USERTYPES.md`
(Phase 20) still marks the learning path, `FALSE_POSITIVE` triage and SARIF
export as NOT_IMPLEMENTED, while `STUDENT.md`/`DEVELOPER.md` (Phase 22) document
all three as implemented. This audit follows the newer Phase 22 evidence and
records the discrepancy; it does not change any Dataset requirement or status.
App tests were read (not executed) from the read-only probe; they confirm the
null-provider contract and the stub-provider path, but no test links a Dataset
asset to the App, so they support the contract statement only — not Dataset
coverage.

## 10. Owner / legal register

| Decision | Status | What it gates |
|---|---|---|
| `ORIGINAL_CONTENT` (D-ORIG) | APPROVED 2026-10-17 | Approves original authorship only; **not** a licence, not redistribution rights |
| `GHSA` | OWNER_DECISION_REQUIRED | importing/redistributing GHSA records |
| `OSV` | OWNER_DECISION_REQUIRED | importing/redistributing OSV records |
| `NVD` | OWNER_DECISION_REQUIRED | importing/redistributing NVD records |
| `CWE` | OWNER_DECISION_REQUIRED | confirming MITRE CWE attribution/usage terms |
| LICENSE grant | absent | any production publication; G6/G16/G17 remain BLOCKED |
| Ingestion gates | 4/4 BLOCKED | importer execution is fail-closed (exit 1 by design) |

Rights, provenance metadata, engineering completeness and production
eligibility are reported in separate fields everywhere in this audit; no record
is marked production-eligible because it validates.

## 11. Regression and validator report

New this audit (both wired into `npm test` and CI):

- `scripts/validate-capability-coverage.mjs` — **656 assertions**: closed
  status/requirement/integration vocabularies; unique stable ids; every
  NON-N/A row has a contract, assets, counting rules and remaining work;
  `NOT_APPLICABLE` requires an evidence-backed reason; COVERED_VERIFIED requires
  relationships, evaluation evidence and re-runnable commands; declared asset
  counts recompute from the tree; every row maps to and from the App inventory;
  UserType view references existing ids and declares zero per-profile assets;
  no row claims production eligibility; and the matrix cannot assert blanket
  100% coverage while any dataset-relevant row is blocked.
- `scripts/render-capability-coverage.mjs` — the Markdown view is a pure
  function of the JSON (`--check` fails when stale), so the human and machine
  matrices cannot diverge.

Existing gates re-run unmodified and passing: full suite plus

| Gate | Result |
|---|---|
| `npm test` (15 runners, incl. the new gate) | exit 0 — **16,539 assertions** (prior 15,883 + 656 matrix assertions) |
| `validate` / `validate:sources` / `validate:corpus` / `validate:packs` / `validate:assets` / `validate:audiences` / `validate:cwe` / `validate:matrix` | 0 errors each |
| `test:vectors` | 16/16 |
| `inventory:check` | up to date |
| `manifest --check` | PASS (4,119 files verified) |
| `ingestion-gates` | 4/4 BLOCKED, exit 1 (fail-closed, expected) |

## 12. Percentage worksheet (A–H are separate; never pooled)

| # | Measure | Numerator / denominator | % | Inclusion rules |
|---|---|---|---|---|
| A | Approved capability mapping | 33 / 33 | 100% | every App capability in the closed inventory has a row with App evidence |
| B | Verified Dataset coverage | 2 / 33 overall; **2 / 10** dataset-relevant | 6.1% / **20.0%** | only COVERED_VERIFIED; blocked/partial/unassessed excluded from numerator |
| C | Asset integrity | 954 / 954 linked (rules with pattern + remediation + resolvable CWE); records 914 / 954 | 100% / 95.8% | two distinct measures, not averaged |
| D | Evaluation assessment | assessed 78 / 89; PASS 77 / 89 | 87.6% / 86.5% | UNASSESSED excluded from precision/recall; 1 FAIL kept |
| E | Provenance metadata | 1,969 / 1,969 | 100% | metadata presence only; **legal grant 0 / 1,969** reported separately |
| F | Production eligibility (authorized scope) | 0 / 100,000 verified advisories; publish-ready 0 | 0% | technical validity never implies eligibility |
| G | App integration | 0 / 10 integrated; 9 / 10 contract-ready | 0% / 90% | integration measured only where a Dataset requirement exists |
| H | Release gates | 13 / 17 PASS | 76.5% | 3 OWNER, 1 PRODUCTION-LOCK; BLOCKED ≠ PASS |

## 13. Remaining work (dependency-sorted)

1. **Owner/legal (blocks F and any release):** GHSA, OSV, NVD, CWE decisions;
   a LICENSE/redistribution grant; then unblock GATE-1/3/4. No Dataset-side work
   can substitute for these.
2. **Main App contract (blocks B and G):** a pack loader (SAST/Secrets/DAST), an
   audience loader (lessons/templates/engagements), and a real SCA provider
   replacing the Null provider. Dataset contracts exist (`DATASET_APP_CONTRACT.md`,
   `PACKS.md`, `AUDIENCES.md`, `PROVIDER_MAPPING.md`); the App has no consumer.
3. **Dataset-side accuracy of the coverage claim (blocks part of B):** extend
   synthetic evaluation from 28 to a representative share of 954 rules, and
   resolve the 11 UNASSESSED cases only with real ground truth (never by
   guessing). This is engineering work, not padding.
4. **Documented legacy gap:** 40 patterns without records (BLK-013) — keep the
   documented exception or record an owner decision; do not pad.
5. **App documentation drift:** Phase 20 `USERTYPES.md` contradicts Phase 22
   evidence (learning path, FALSE_POSITIVE, SARIF). Read-only; flagged to the App
   workstream, with zero Dataset impact.

## 14. Release-gate matrix and recommendation

| Gate | Status |
|---|---|
| G1–G5 (integrity, schema, rule tests, dedup, provenance) | PASS |
| G6 license | BLOCKED — owner/legal |
| G7 source attribution | PASS |
| G8 production lock | BLOCKED — production |
| G9–G15 (consistency, drift, injection, determinism, suite, scope, CI least-privilege) | PASS |
| G16 owner paperwork | BLOCKED — owner |
| G17 production breadth | BLOCKED — 0 / 100,000 |

**Completeness answer: NO.** The Dataset does not yet contain *legally usable*
and *App-consumable* coverage for every approved capability: 2/10 dataset-
relevant capabilities are covered and verified, 7 are blocked only by the
missing App consumer, 1 is blocked by rights, and production eligibility is 0.
The assets themselves are present, unique, linked and validated — the gap is
contract/legal, not a missing corpus.

**Verdict: WAIT FOR MAIN APP CONTRACT / INTEGRATION EVIDENCE.**

Rationale: the binding constraint on *coverage* is that the App consumes none of
this Dataset (0/10 integrated), so no further Dataset-side authoring can raise
verified coverage. This verdict does **not** clear release: the owner/legal gate
(G6/G16/G17, no LICENSE) and production lock (G8) remain open, and the answer to
"may this be published?" stays NO-GO regardless of integration.

## 15. Verification of this audit's own boundary

- Dataset changes: the matrix JSON/Markdown, one validator, one renderer,
  `package.json`/CI wiring, a pointer and CWE recount in
  `CAPABILITY_COVERAGE.md`, a CWE-split correction in `README.md`, a
  cross-reference line in the historical completion audit, and this report. No asset, schema, pack, knowledge,
  vuln-intel or `data/asset-cells` file was modified; no licence file was added.
- Main App: unchanged (read-only clone; no writes, no copies, no history change).
- Production: untouched — no feed, credential, deployment or database access.
- No commit, push, PR, tag, publish or release action was performed.
- Limitations: App tests were read, not executed (read-only probe; no App build
  or run); no App test loads a Dataset asset, so no end-to-end integration
  measurement exists; coverage statuses are contract-level, not runtime
  measurements; percentages describe the audited populations only and are not
  extrapolations.
