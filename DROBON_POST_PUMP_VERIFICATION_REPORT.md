# DROBON POST-PUMP VERIFICATION REPORT

**Date:** 2026-10-16 (Asia/Dhaka) · **Type:** cumulative verification, blocker
classification, and release-governance pass (no new dataset construction)

---

## 1. Exact repository / branch / HEAD

| Field | Value | How verified |
|---|---|---|
| Repository | `mdraselislam0101-design/Drobon-Dataset` | `git remote -v`, `gh api` |
| Remote URL | `https://github.com/mdraselislam0101-design/Drobon-Dataset.git` | `git remote -v` |
| Working branch | `arena/9fe99288-drobon-dataset` | `git branch --show-current` |
| HEAD | `792bf3353ff7c4d35758b0484c40da9ef775fc31` | `git rev-parse HEAD` |
| Remote head (same branch) | `792bf3353ff7c4d35758b0484c40da9ef775fc31` | `git ls-remote origin`, `gh api …/branches/…` — **synchronized** |
| `main` head | `12edda11017b67c4e6f1c6eb1673fcd2b52d909d` | `git rev-parse main` |
| Relationship | working branch = `main` + 8 commits (0 behind) | `git merge-base`, `git rev-list --count` |
| Working tree | **clean** | `git status --porcelain` (empty) |
| Shallow clone | **yes** (`is-shallow-repository: true`) | `git rev-parse --is-shallow-repository` |

**Session-start anomaly (important):** this session's local clone was *fresh*
(reflog shows only `clone` → `checkout`) and stood at `12edda1` with the
previous pump's file changes present only as uncommitted/untracked content.
The 8 commits existed on `origin` but not locally. Recovery was
non-destructive and identity-preserving: `git fetch --depth=20` → staged-tree
diff against `FETCH_HEAD` = **0 files different** (working content byte-identical
to the pushed commits) → `git merge --ff-only FETCH_HEAD`. No commit was
recreated; the original hashes are intact; nothing was reset or rewritten.

Machine-readable companion: `docs/REPO_STATE_VERIFICATION.json`.

## 2. Commit verification results

All 8 previously reported commits verified present on the branch in the
reported order, each with change scope matching the prior report:

| # | Hash | Subject (abbrev.) | Scope | Matches report |
|---|---|---|---|---|
| 1 | `7655ba9` | Batch B — doc drift + matrices | 12 files, +921 | yes |
| 2 | `f8bd024` | Batch C — importer hardening | 4 files, +612 | yes |
| 3 | `772a7b7` | Batch D — rule metadata semantics | 4 files, +61 | yes |
| 4 | `44b43c6` | Batch E — coverage map + tests | 7 files, +558 | yes |
| 5 | `dfb8b68` | Batch F — reordered-input determinism | 1 file, +31 | yes |
| 6 | `76864a7` | Batch G — toolchain security + CI | 3 files, +29 | yes |
| 7 | `007cb8c` | Batch H (1) — determinism gate + matrices | 4 files, +311 | yes |
| 8 | `792bf33` | Batch H (2) — CI F-09 closure | 1 file, +4 | yes |

**Missing/unavailable commits: none.** Total range `12edda1..792bf33`:
26 changed paths, +2,477/−73 (recomputed via `git diff --stat`).

## 3. Files checked (Phase B artifacts)

| Artifact | Exists | Structure verified |
|---|---|---|
| `docs/RELEASE_READINESS_MATRIX.json` | yes | JSON valid; `drobon.release.readiness/v1`; 17 gates, IDs unique; every PASS has evidence; every BLOCKED has findings + ownerAction; vocabulary clean |
| `docs/COMPLETION_MATRIX.json` | yes | JSON valid; `drobon.completion.matrix/v1`; 22 items, IDs unique |
| `docs/COVERAGE_MAP.json` | yes | JSON valid; all tallies recomputed from rule files by `scripts/test-doc-drift.mjs` (16 staleness gates) |
| `scripts/test-determinism.mjs` | yes | runs; 5/5 |
| `scripts/test-doc-drift.mjs` | yes | runs; 88/88 |
| `docs/SCOPE.md` | yes | **unchanged** vs baseline (separation contract intact) |
| `docs/OWNER_ACTION_REQUIRED.md` | yes | **unchanged** (owner-maintained) |
| `docs/LICENSE_DECISION_RECORD.md` | yes | **unchanged** (owner-maintained) |
| `docs/DESIGN_DECISIONS*` | **ABSENT** | no file of this name exists anywhere in the repository; the design-decision text lives in `docs/OWNER_ACTION_REQUIRED.md` §6–§7 and `docs/PACKS.md` (a dangling `DESIGN_DECISIONS.md` citation in COVERAGE_MAP BE-4 was repaired this session — see §8) |
| `vuln-intel/sources.json` (canonical path of "sources.json") | yes | **unchanged**; redistribution UNVERIFIED for all sources |
| `docs/OWNER_DECISIONS.json` (canonical path of "OWNER_DECISIONS.json") | yes | **unchanged**; 5/5 decisions `OWNER_DECISION_REQUIRED`, `decidedAt/decider` null |

Existing verification scripts re-used as-is (no competing matrix created):
`test-doc-drift`, `test-consistency`, `validate-matrix`, `validate-corpus`.

## 4. Claims independently verified (Phase C)

### C1 — Commit/change claims
Docs drift corrections ✓ (Batch B files + 88-assert drift gate). Importer
pagination/cursor guards/retry/dry-run/structured metrics ✓ (`import-ghsa.mjs`
exports `runImport`, `SAFE_NEXT_PREFIX`, `parseLinkNext`; summary fields
fetched/accepted/rejected/duplicate/skipped/failed with `productionApproved: 0`).
Rule-metadata contract tests ✓ (`denylist` required unless
`matchOnlyEvidence:true`; `languages`-omission contract). Duplicate-affected
rejection ✓ (`validate.mjs` rejects same range+fixed; fixture
`test/invalid/duplicate-affected.json`). Coverage map ✓. CI asset validation +
integrity manifest ✓ (`ci.yml` runs `validate:assets` + read-only manifest
compute/check). Determinism + doc-drift tests ✓.

### C2 — Test claims (historical figures vs current run)
Current run on `792bf33` (command: `npm test`, exit **0**):

| Runner | Current | Historical claim | Match |
|---|---|---|---|
| tests | 600 | 600 | ✓ |
| pack-tests | 3966 | 3966 | ✓ |
| audience-tests | 2891 | 2891 | ✓ |
| asset-tests | 7490 | 7490 | ✓ |
| consistency-tests | 208 | 208 | ✓ |
| rehearsal-tests | 78 | 78 | ✓ |
| importer-tests | 49 | 49 | ✓ |
| doc-drift | 88 | 88 | ✓ |
| determinism | 5 | 5 | ✓ |
| **sum** | **15,363** | **15,363** | ✓ |

*Counting meaning:* each figure is that runner's own executed checks
(assert-helper calls or `node:assert` calls). The nine runners execute
disjoint test files, so no assertion is counted twice; the sum 15,363 is a
simple total of nine separate counters, not a deduplicated global metric.
Validators (each `npm run …`, all exit **0**): `validate` 103 files ·
`validate:sources` 1 · `validate:corpus` 3 · `validate:packs` 953 ·
`validate:assets` 1860 · `validate:audiences` 960 · `validate:cwe` 61 ·
`validate:matrix` (inventory recomputed) · `test:vectors` 16/16 — all match
the historical figures.

### C3 — Determinism
- Fresh-copy generation+validation: `node scripts/test-determinism.mjs` →
  **5/5 PASS** (two isolated copies: logs byte-identical, file trees
  byte-identical, regenerated tree == checked-in tree).
- Reordered-input importer output: deterministic (asserted in
  `test-importers.mjs`, passing).
- **Digest scope resolution (required by the brief):** the previously reported
  whole-tree digest `b676e109e81d240d6bec4ef687a84128b1f4536961aee5d49a6011ccc8105dfe`
  does **not** match the current tree's digest
  `6e7dbcd565d6d42b406134e2f6943b0b3f89fcb952bb70e734aee412c415318e`.
  Scope = whole-tree (every file except `.git`/`node_modules`/`.arena`, hashed
  as sorted path + content-sha256 stream). Root cause = the tree legitimately
  advanced after the old digest was taken (4 files: `package.json`,
  `docs/RELEASE_READINESS_MATRIX.json`, `docs/COMPLETION_MATRIX.json`,
  `.github/workflows/ci.yml`). **Proof:** reconstructing the digest-time tree
  (commit `76864a7` content + `scripts/test-determinism.mjs`) reproduces
  `b676e109…` **exactly** (byte-for-byte match of the digest). Determinism
  itself is not in question — each run pair is self-consistent and reproducible
  within its tree state. No expected-hash exists in code (the digest is computed
  at runtime), so nothing was "updated to hide a mismatch".

### C4 — Production lock
- No new real advisory data: `git diff 12edda1..HEAD --stat -- vuln-intel` =
  **empty** (advisory corpus untouched by all 8 commits).
- No fixture promoted: sample records still `"fixture": true` with
  `DROBON-SAMPLE-###` ids; consistency suite rejects fixture impostors.
- Production verification count: `verifiedProductionCount = 0` in **every**
  `docs/CORPUS_TARGETS.json` category (recomputed), 0/100,000.
- Importer tests: 100% injected `fetchImpl` mocks; no bare `fetch(` in
  `test-importers.mjs`; tmpdir sandboxes only.
- Release gate enforcement: G8 = `BLOCKED_PRODUCTION_LOCK` (drift test pins
  this status; flipping it fails the suite).

## 5. Verified vs unverified historical claims

**Verified:** the 8 commits and their scopes; all test/validator counts;
determinism behavior and the old digest (via reconstruction); production-lock
invariants; owner files untouched; separation contract intact.

**Corrected this session (safe documentation fixes, §8):** dangling
`DESIGN_DECISIONS.md Q19-22` citation; wrong `§7.x` citations in COVERAGE_MAP
BE-1/BE-2/BE-5 and gap notes; an unverifiable "13 quarantined records
(counted=false)" phrase (no such mechanism exists in the tree — replaced with
the reproducible 950-vs-910 figure); G16's "18 open decision items" refined to
its honest derivation (18 numbered §6+§7 items = 2 resolved + 16 open, plus
5/5 per-source decisions open).

**Unverifiable / not claimed:** pre-`12edda1` git history (shallow clone); the
previous pump's **outside-repository** artifacts (`/home/user/drobon-audit-artifacts/…`)
— that directory **no longer exists** in this environment and is explicitly
NOT claimed as available. This report and its companions are stored **in-repo**
for that reason.

## 6. Technical defects fixed (Phase E — safe only)

| ID | Defect | Fix | Regression |
|---|---|---|---|
| V-1 | COVERAGE_MAP cited nonexistent `DESIGN_DECISIONS.md Q19-22` | citation → `docs/PACKS.md` id-regex notes + `docs/OWNER_ACTION_REQUIRED.md` §6.7/§7.3 | doc-drift 88/88 |
| V-2 | COVERAGE_MAP BE-1/BE-2/BE-5 cited wrong §7.x sections; BE-3 repeated an unreproducible quarantine claim | all reasons rewritten to verifiable in-repo anchors (PACKS.md Batch 6; §6.5/§6.6; §6.11 + 950/910; SCA proposal) | doc-drift 88/88 |
| V-3 | G16 overstated open-decision accounting | precise derivation recorded (2 resolved + 16 open + 5/5 sources) | doc-drift + full suite |

No rules, counts, tests, or owner documents were changed. No test was
disabled. Full suite re-run after fixes: 15,363 checks, exit 0.

## 7. Remaining blockers (summary)

Machine-readable: `docs/BLOCKER_REGISTER.json` (BLK-001…BLK-020 + 2 resolved
for record). Owner-actionable packet: `docs/OWNER_DECISION_PACKET.md`
(D-1…D-20). Highlights:

- **BLK-001/002** license grant + per-source redistribution (G6) — owner only.
- **BLK-003/004** production stage authorization + cadence (G8) — owner only.
- **BLK-005…018** 14 rule-policy decisions (`OWNER_ACTION_REQUIRED.md` §6–§7).
- **BLK-019** SCA rule-pack schema authorization; **BLK-020** Shopify `shpat_`
  source evidence (BLOCKED_SOURCE_EVIDENCE).

## 8. Release readiness matrix summary

`docs/RELEASE_READINESS_MATRIX.json` (canonical; 17 gates) at report time:

| Gates | Status |
|---|---|
| G1–G5, G7, G9–G15 | **PASS** (each with evidence + command) |
| G6 licensing/redistribution | **BLOCKED_OWNER_DECISION** |
| G8 production-data authorization | **BLOCKED_PRODUCTION_LOCK** |
| G16 owner decisions | **BLOCKED_OWNER_DECISION** |
| G17 final production eligibility | **BLOCKED_OWNER_DECISION** |

Technical completeness (all technical gates green, 15,363 checks) and
production release authorization are separate: the first is done, the second
is not granted.

## 9. Final verdict (exactly one)

> ## BLOCKED — OWNER/PRODUCTION AUTHORIZATION REQUIRED

Rationale: every technical gate is PASS with reproducible evidence, but the
mandatory owner decisions (license grant, per-source redistribution, the
rule-policy cluster) and the production-data authorization are open by policy
(G6/G16/G17 `BLOCKED_OWNER_DECISION`, G8 `BLOCKED_PRODUCTION_LOCK`;
corpus 0/100,000 verified-production). No tag, release, or PR was created.

## 10. Verification limitations

1. Shallow clone: pre-baseline history unverifiable locally (the 8-commit
   range itself is fully fetched and verified).
2. Prior outside-repo evidence (`/home/user/drobon-audit-artifacts/`) is gone;
   claims were re-derived from the repository instead of citing it.
3. CI runtime (GitHub Actions on push) was not observed from this environment;
   `ci.yml` content is verified by inspection and its commands were executed
   locally, all green.
4. No live third-party probes were made (production lock); importer behavior
   beyond mocked fixtures remains dry-run-ready, not live-verified.
