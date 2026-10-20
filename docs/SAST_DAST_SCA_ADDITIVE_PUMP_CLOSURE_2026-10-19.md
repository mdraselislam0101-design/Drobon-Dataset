# DROBON AEGIS — CLOSURE MASTER PUMP (2026-10-19)

**Repository:** `mdraselislam0101-design/Drobon-Dataset`
**Branch:** `arena/a4caaeb8-drobon-dataset` (authorized working branch)
**Scope:** Dataset repository only. No Main App edit, no production/VPS/DB action, no git write.

**Gate summary**

```
RECOVERY INTEGRITY: PASS
CANONICAL COVERAGE METRICS: PASS
SAST ADDITIVE EXPANSION: VERIFIED FOR TESTED SCOPE
DAST EVALUATION: VERIFIED FOR TESTED SCOPE (synthetic observations only)
SCA CONTRACT LOGIC: VERIFIED FOR TESTED SCOPE (original logic + synthetic fixtures)
OWNER/LEGAL GATES: OPEN
MAIN APP INTEGRATION: BLOCKED
PRODUCTION READINESS: NO-GO
```

---

## 1. Initial state, final state, HEAD

| Item | Initial (pump start) | Final (after this pump) |
|---|---|---|
| Branch | `arena/a4caaeb8-drobon-dataset` | unchanged |
| HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` | **unchanged** `ed599c654e972cf517331bb504d65f3e8c2dbcf1` |
| `git status` | 2,305 modified / 256 untracked / 0 deleted | 2,313 modified / 317 untracked / **0 deleted** |
| Tracked files with content vs HEAD | preserved | preserved (no reset/clean/checkout of user work) |

The delta is exactly the intended work: `+8` modified files (7 recovered remediation files and the recovered cell `sast-calls-5.json`, all of which were already tracked but had been left at their pre-fix bytes) and `+61` new untracked files (2 cell files, 40 generated assets, 17 eval cases, 1 analysis script, 1 closure report). No tracked file was deleted and no file outside the Dataset repository was touched.

## 2. Recovery forensics (Gate A)

### 2.1 Method

The checkpoint used for recovery was the 4,193-file SHA-256 manifest captured during the previous pump (`/tmp/integrity4.json`, a session artifact). The working tree was walked with the identical scope and every path re-hashed (`/tmp/forensics2.mjs`). Results:

| Measurement | Result |
|---|---|
| Baseline entries | 4,193 |
| Removed (baseline path now missing) | **0** |
| Changed content | 21 |
| Added paths | 332 |
| Affected assets (`DPK-SAST-782…797` rules + remediation, `DPK-PAT-0938…0953`, `DPK-REC-0898…0913`, 4 CWE entries) matching baseline | **68 / 68** |

The 21 changed paths are accounted for and intentional: 2 cell files, **5 remediation files deliberately reworded in this pump** (`DPK-SAST-677…681`, §2.5), and 14 documentation/inventory files whose counts were re-pinned to the recomputed tree (§3). No unexplained difference remains.

### 2.2 The baseline was recoverable, not assumed

The previous report claimed that 7 remediation files and `data/asset-cells/sast-calls-5.json` had been regenerated to remove exact-duplicate text. The working tree at pump start did **not** contain that fix (those files were byte-identical to HEAD), while the checkpoint hashes did not match. Rather than guess which side was correct, the repository's object database was scanned (`git cat-file --batch-all-objects`, 6,830 blobs under 400 KB). **All eight baseline contents exist as unreachable blobs** — content-addressed evidence that the fix had been written and staged at some point without being committed.

| File | Baseline `sha256` (first 16) | Recovered blob | Current `sha256` |
|---|---|---|---|
| `data/asset-cells/sast-calls-5.json` | `cb5f6626a299ea7e` | `a364107918a7` | `cb5f6626a299ea7e` ✅ |
| `knowledge/remediation/DPK-SAST-782.json` | `b2db3edc49d6e4be` | `299df56ec145` | `b2db3edc49d6e4be` ✅ |
| `knowledge/remediation/DPK-SAST-783.json` | `8905895a467a85c3` | `1671bad3212f` | `8905895a467a85c3` ✅ |
| `knowledge/remediation/DPK-SAST-792.json` | `baff8c8bc92c6bce` | `f1f16cd9e166` | `baff8c8bc92c6bce` ✅ |
| `knowledge/remediation/DPK-SAST-793.json` | `0eb4f1ba58ee0edd` | `7076ca872268` | `0eb4f1ba58ee0edd` ✅ |
| `knowledge/remediation/DPK-SAST-794.json` | `60bace9262260fcd` | `3bfb62383451` | `60bace9262260fcd` ✅ |
| `knowledge/remediation/DPK-SAST-795.json` | `9ca29d6534aeaab6` | `7b559dc4960d` | `9ca29d6534aeaab6` ✅ |
| `knowledge/remediation/DPK-SAST-796.json` | `78d4079e324aa2e6` | `fae829883015` | `78d4079e324aa2e6` ✅ |

### 2.3 Round-trip proof (baseline → generator → files)

The recovered cell was placed in an isolated copy of `scripts/`, `data/`, `packs/`, `knowledge/` and `node scripts/generate-assets.mjs` was executed there.

* All **64** generated affected assets were reproduced **byte-for-byte** from the recovered cell (`gen == baseline` 64/64).
* Across the whole generated set, **4,019 of 4,020** files matched the checkpoint; the single difference is `data/asset-cells/.manifest.json`, whose file list post-dates the checkpoint (it includes the later `sast-calls-7.json` / `sast-config-5.json` cells).
* Re-running the generator in the repository after restoring the eight files produced **zero byte changes** (`diff` over the pre/post hash lists of `packs/`, `knowledge/` and `data/asset-cells/` reported zero changed paths), proving the restored content is exactly the generator's output for the restored cell.

### 2.4 What was actually wrong

The committed (HEAD) text for the seven remediation files was language-agnostic, so `DPK-SAST-782/783` and `DPK-SAST-792…796` carried identical `whyItMatters` strings across sibling languages — a regression against the documented "0 exact repeats" invariant, not a content loss. Restoring the recovered cell and remediation bodies removed the duplicates and names the language. `git cat-file` reads only; no `git checkout`, `reset`, `clean`, or restore command was used, and the pre-change bytes were copied to `/tmp/gateA-current/` before writing.

### 2.5 Additional evidence-backed repair (exact duplicate remediation)

The originality audit still flagged `DPK-SAST-677` (perl) and `DPK-SAST-679` (ruby) as sharing a remediation body (`backtick executes variables (`$cmd`).`). Root cause: the shared `shell-risk` cell used the framework variant only. The cell's `why` template now includes `{lang}` (`{fw} in {lang} executes variables ({sink}).`), regenerated deterministically; 5 remediation entries changed (`677…681`), and the originality audit now reports **0 exact repeated remediation bodies** (only the accepted near-duplicate pairs remain).

### 2.6 UNVERIFIABLE items

**None.** Every affected asset is either byte-identical to the recovered baseline or a documented, intentional rewrite. One caveat is recorded for honesty: the 4,193-file baseline is a session artifact rather than a committed manifest, so future re-verification must use the per-file hashes in §2.2 and the new 4,423-file manifest (`/tmp/integrity_final.json`, reproducible with `node scripts/manifest.mjs --scope all --write <file>`).

## 3. Before/after counts with sources

| Asset | Before | After | Delta | Before source | After source (recomputation) |
|---|---|---|---|---|---|
| SAST rules | 812 | **822** | +10 | `docs/SAST_DAST_SCA_ADDITIVE_PUMP_2026-10-19.md`; checkpoint manifest | `ls packs/sast/v1/rules` |
| Secrets rules | 97 | **97** | 0 | same | `ls packs/secrets/v1/rules` |
| DAST rules | 65 | **65** | 0 | same | `ls packs/dast/v1/rules` |
| Patterns | 974 | **984** | +10 | same | `ls knowledge/patterns` |
| Records | 934 | **944** | +10 | same | `ls knowledge/records` |
| Remediation | 974 | **984** | +10 | same | `ls knowledge/remediation` |
| CWE entries | 61 | **61** | 0 | same | `ls knowledge/cwe` |
| Eval cases | 244 | **261** | +17 | same | `ls data/eval-cases` |
| — assessed / UNASSESSED | 233 / 11 | **250 / 11** | +17 / 0 | same | `node scripts/run-eval.mjs` |
| TP / FP / FN | 165 / 1 / 0 | **177 / 1 / 0** | +12 / 0 / 0 | arithmetic from the 12 new positive cases | same |
| Precision / recall | 0.9940 / 1.0 | **0.9944 / 1.0** | +0.0004 / 0 | same | same |
| DAST eval cases | 69 | **73** | +4 | 73 − 4 new files | `ls data/eval-cases` |
| Distinct rules named (any role) | 147 | **157** | +10 | prior report | `scripts/coverage-report.mjs` |
| Manifested files | 4,363 | **4,423** | +60 | `/tmp/integrity10.json` | `scripts/manifest.mjs --scope all` |

The counts were re-pinned in the gate documents that guard drift (`README.md`, `docs/AUDIENCES.md`, `docs/PACKS.md`, `docs/CORPUS_GAP_REPORT.md`, `docs/CORPUS_TARGETS.json`, `docs/REQUIREMENTS_MATRIX.json`, `docs/COVERAGE_MAP.json`, `docs/CAPABILITY_COVERAGE*.{md,json}`, `docs/CAPABILITY_GAP_MATRIX.md`, `docs/COMPLETION_MATRIX.json`, `docs/RELEASE_READINESS_MATRIX.json`, `docs/CURRENT_INVENTORY.json`). Every pin was updated to the recomputed value, never the reverse.

## 4. New assets

### 4.1 SAST rules (10, stable unused IDs)

Each rule was added only after a corpus probe showed **zero** existing detection for the construct (probe matched rule titles and pattern sources across all 812 pre-existing SAST rules).

| Rule | Language | CWE / category | Construct | Prior rules for construct |
|---|---|---|---|---|
| `DPK-SAST-823` | yaml | CWE-532 / sensitive-logging | secret expression interpolated into a `run:` step | 0 |
| `DPK-SAST-824` | yaml | CWE-250 / ci-security | `permissions: write-all` | 0 |
| `DPK-SAST-825` | javascript | CWE-113 / http-response-splitting | `setHeader` with a non-literal value | 0 |
| `DPK-SAST-826` | python | CWE-502 / unsafe-deserialization | `jsonpickle.decode` | 0 |
| `DPK-SAST-827` | javascript | CWE-915 / mass-assignment | `__proto__` / `constructor.prototype` mutation | 0 |
| `DPK-SAST-828` | shell (bash family) | CWE-494 / command-injection | `curl … \| sh` | 0 |
| `DPK-SAST-829` | python | CWE-502 / unsafe-deserialization | `shelve.open` | 0 |
| `DPK-SAST-830` | javascript | CWE-918 / server-side-request-forgery | `fetch`/`axios`/`got` computed URL | 0 |
| `DPK-SAST-831` | python | CWE-918 / server-side-request-forgery | `requests`/`httpx`/`urlopen` computed URL | 0 |
| `DPK-SAST-832` | javascript | CWE-916 / weak-cryptography | bcrypt work factor < 12 | 0 (only Go/PHP analogues existed) |

Registration is complete for all ten: stable rule id, one pattern (`DPK-PAT-1001…1010`), one record (`DPK-REC-0961…0970`), one remediation document keyed by rule id, pack entry under `packs/sast/v1/rules`, **4 executable tests each (2 positive, 2 negative)**, and independent eval cases (§4.3). The generator's own gates passed with `quarantined: []`.

### 4.2 Data files

* `data/asset-cells/sast-calls-8.json` — 2 call-framed classes (`shelve.open`, `jsonpickle.decode`).
* `data/asset-cells/sast-config-6.json` — 8 flag-framed classes (CI secret echo, `write-all`, header injection, prototype pollution, `curl|sh`, SSRF ×2, bcrypt cost).

### 4.3 Evaluation cases

* `EVAL-SAST-058…067` — positive cases, one per new rule (10/10 rules independently exercised).
* `EVAL-SAST-068…070` — negative and boundary controls: literal header value (825), constant-URL fetch (830), bcrypt cost 12 (832).
* `EVAL-DAST-070…073` — closes the only two uncovered DAST rules: `DPK-DAST-005` (nosniff) positive + negative, `DPK-DAST-007` (X-Frame-Options) positive + negative.

### 4.4 Tooling

* `scripts/coverage-report.mjs` — read-only canonical coverage and integrity report. `--check` exits 1 on any duplicate id, dangling reference, or changed documented failure; `--json <file>` emits the machine-readable ledger used in §5/§7.

## 5. Per-engine canonical coverage (numerator / denominator / method)

All values below are produced by `node scripts/coverage-report.mjs --json /tmp/coverage-final.json` from the working tree. No percentage exists without its denominator and inclusion rule.

| Metric | Numerator | Denominator | % | Inclusion rule |
|---|---|---|---|---|
| Active SAST rules | 822 | 822 | 100% | every parsed rule document vs every rule file (no activity filter claimed) |
| SAST rules exercised by independent eval | 85 | 822 | **10.34%** | distinct `DPK-SAST-*` ids named in `expected.detections` |
| Secrets rules exercised | 4 | 97 | **4.12%** | same rule, secrets pack only |
| DAST rules exercised | 65 | 65 | **100%** | distinct `DPK-DAST-*` ids named in observation cases |
| Rules named by any case (positive **or** negative control) | 157 | 984 | **15.96%** | pooled reconciliation figure only — **not** a per-engine rate |
| SAST rules with resolvable pattern refs | 822 | 822 | 100% | every `patternRefs` entry exists |
| Rules with same-id remediation document | 984 | 984 | 100% | all three packs |
| Patterns linked to a rule | 984 | 984 | 100% | `linkedRules` resolves |
| Records linked to a pattern | 944 | 944 | 100% | `relatedPatterns` resolves |
| Eval cases with authored ground truth | 250 | 261 | **95.79%** | ASSESSED only; UNASSESSED stays in the denominator |
| Cases declaring synthetic + testOnly | 261 | 261 | 100% | production-authorized records are reported separately (0) |
| SCA contract capabilities tested | 15 | 15 | 100% | capability counts only when every named assertion line prints `ok` |

### 5.1 Reconciliation of the historical figures

| Historical claim | Canonical reading |
|---|---|
| `84/954 = 8.81%` (157 cases) | mixed SAST + secrets + DAST numerator over a mixed rule denominator; kept only as history |
| `75/812 = 9.24%` | **SAST-only**, exercised by `expected.detections`; matches today's 85/822 minus the 10 new rules |
| `147/974 = 15.09%` | **named-any-role pooled** (75 SAST + 7 secrets + 65 DAST); the secrets count included 3 rules that appear only as `forbiddenDetections`, so it is not an "exercised detection" rate |
| `147 → 157` | +10 because each new SAST rule is named by its own case; DAST 65/65 and secrets named 7/97 are unchanged |
| `7/97` vs `4/97` | `7` = named (4 detected + 3 negative-control); `4` = detected. Both are reported, labelled differently, never mixed |

No denominator was reduced to raise a percentage: inactive/blocked/legacy assets remain in every denominator (the 40 legacy patterns without records are still counted as patterns, and the 11 UNASSESSED cases remain in the case denominator).

## 6. Evaluation results

`node scripts/run-eval.mjs` over **261 cases**:

| Population | Count |
|---|---|
| positive | 147 |
| negative | 76 |
| boundary | 19 |
| mutation | 9 |
| near-miss | 10 |
| **ASSESSED** | **250** |
| **UNASSESSED** (excluded from scoring) | **11** |
| synthetic + testOnly | 261 |
| production-authorized records | 0 |
| original-authored provenance | 261 |
| third-party provenance | 0 |

UNASSESSED ids (unchanged): `EVAL-CMD-023`, `EVAL-CMD-024`, `EVAL-CMD-025`, `EVAL-SAST-004`, `EVAL-SAST-007`, `EVAL-SAST-014`, `EVAL-SAST-015`, `EVAL-SAST-016`, `EVAL-SEC-111`, `EVAL-SQL-027`, `EVAL-SQL-028`.

All 17 new cases pass on their authored expectations. `EVAL-SAST-008` remains a **FAIL by design** (1 false positive on a docstring line) and was not touched, relabelled, or removed; `test-eval` asserts that failure explicitly.

## 7. False positives / false negatives and corpus limits

* **TP 177, FP 1, FN 0** over 250 assessed synthetic cases → precision **0.9944**, recall **1.0**.
* The single FP is the documented `EVAL-SAST-008` keyword trap. It is reported, not suppressed.
* These numbers describe a **synthetic, line-regex corpus**, not real-world effectiveness; they are not a 100% recall or precision claim.
* Limits: no taint/dataflow, no runtime observation of real targets, no exploitability proof; 11 UNASSESSED cases contribute nothing; DAST cases are synthetic observation objects (no request was sent, no host was contacted — all URLs use `.test`).
* Coverage breadth is deliberately split: 85/822 SAST rules (10.34%) have independent eval cases; the remaining 737 rely on the pack's own 4 tests (2 positive / 2 negative), which is a weaker form of evidence and is not counted as independent evaluation.

## 8. Commands and actual results

| Command | Result |
|---|---|
| `git rev-parse HEAD` | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged at the end) |
| `git status --porcelain` | 2,313 `M`, 317 `??`, **0 `D`** |
| `node scripts/generate-assets.mjs` | `written 3851, removed 0, quarantined []` |
| `node scripts/run-eval.mjs` | 261 cases, TP 177 / FP 1 / FN 0, 250 assessed, 11 UNASSESSED |
| `node scripts/test-eval.mjs` | `eval-tests: 41 passed, 0 failed` |
| `node scripts/test-sca-engine.mjs` | `sca-engine tests: 38 passed, 0 failed` |
| `node scripts/coverage-report.mjs --check` | `coverage-report: PASS` (0 integrity defects) |
| `node scripts/manifest.mjs --scope all --check /tmp/integrity_final.json` | `manifest: PASS (4423 files verified)` |
| `node scripts/inventory.mjs --check` | `docs/CURRENT_INVENTORY.json matches the tree` |
| `node scripts/test-doc-drift.mjs` | `doc-drift: 119 passed, 0 failed` |
| `node scripts/test-current-state.mjs` | `current-state: 153 passed, 0 failed` |
| `node scripts/validate-capability-coverage.mjs` | `656 passed, 0 failed` |
| `node scripts/test-determinism.mjs` | `5 passed, 0 failed` (whole-tree digest reproducible within a run; no digest value is pinned in this report because editing the report changes the tree that the digest covers) |
| **`npm test`** | **EXIT 0 — 17,033 `ok` assertions, 0 failures** (pack 4,102; assets 7,764; audiences 2,996; core 600; consistency 218; rehearsal 78; importers 49; agent-policy 91; agent-workflows 57; finding-evidence 31; secret-candidates 35; SCA 38; eval 41; doc-drift 119; current-state 153; capability 656; determinism 5) |
| `node scripts/test-consistency.mjs` | `218/218` |
| Ingestion gates (`node scripts/test-consistency.mjs` gate section) | 4/4 **BLOCKED** (expected fail-closed) |

## 9. Provenance, rights, owner and Main App blockers

* **Provenance:** all 261 eval cases are `original-authored` / synthetic / test-only; 0 third-party cases; 0 real advisory records were ingested. `vuln-intel/` remains the frozen 100-file seed (84 identity items) and was not modified.
* **Rights:** `docs/OWNER_DECISIONS.json` still holds 5 entries — **4 × `OWNER_DECISION_REQUIRED`** (GHSA, OSV, NVD, CWE) and 1 `APPROVED` (ORIGINAL_CONTENT). No decision was edited, invented, or implied.
* **Owner retention decision:** D-13 ("Records for the 40 legacy patterns") remains **decided (keep)**; the 40 record-less legacy patterns stay inactive and are not counted as production records.
* **No LICENSE:** the repository still has no LICENSE file; no grant is claimed. `productionEligibility` stays `NOT_ELIGIBLE_NO_LICENSE`.
* **Main App:** the seam `assess(coordinates) → {providerId, datasetStatus, advisories[]}` is documented, but the app runs `VULN_INTEL_PROVIDER=none` and no Dataset provider is wired. Main App was inspected read-only in earlier pumps; nothing was copied into it and nothing in it was modified.
* **SCA data:** synthetic records only (`DROBON-SAMPLE-*`); construction refuses non-synthetic ids, `fixture:false`, foreign schemas, foreign provenance, malformed ranges and invented severities. `NO_DATA_LOADED` / `NOT_ASSESSED` / `ASSESSED` are mutually exclusive; `NOT_ASSESSED` never carries advisories.

## 10. Worktree modifications, new files, deletions

| Category | Count | Detail |
|---|---|---|
| Modified vs HEAD | 2,313 | includes the pre-existing 2,305 plus the 8 recovered files |
| New (untracked) | 317 | includes 61 files created by this pump |
| Deleted | **0** | `git status` reports no `D`; the generator reported `removed: 0` |

Changed **relative to the recovery checkpoint** (21 paths): 2 cell files, 14 documentation/inventory files (count re-pins), 5 remediation files (`677…681`, duplicate-text repair). Everything else added is new content, not a replacement.

## 11. Confirmation: no git write, no app modification, no import, no deploy

* No commit, push, PR, merge, tag, release, force-push, history rewrite, `git reset --hard`, or `git clean` was executed. HEAD is still `ed599c65…`.
* File restorations used `git cat-file` (read) followed by ordinary file writes; the pre-change bytes were preserved in `/tmp/gateA-current/` and remain recoverable from git objects.
* No file in the Main App repository was read or written by this pump; no Dataset asset was embedded in it.
* No network ingestion, feed download, advisory import, production database write, VPS change, or deployment action occurred. The SCA engine test proves the engine imports no HTTP/DNS/socket module and calls no `fetch()`.
* No secret value is printed anywhere in this report; the only credential-shaped strings are synthetic fixtures already governed by the secrets-fixture policy.

## 12. Final gate statuses

```
RECOVERY INTEGRITY: PASS
CANONICAL COVERAGE METRICS: PASS
SAST ADDITIVE EXPANSION: VERIFIED FOR TESTED SCOPE
DAST EVALUATION: VERIFIED FOR TESTED SCOPE (synthetic observations only)
SCA CONTRACT LOGIC: VERIFIED FOR TESTED SCOPE (original logic + synthetic fixtures)
OWNER/LEGAL GATES: OPEN
MAIN APP INTEGRATION: BLOCKED
PRODUCTION READINESS: NO-GO
```

| Gate | Status | Basis |
|---|---|---|
| Recovery integrity | **PASS** | 68/68 affected assets match the recovered baseline; 8/8 contents recovered from unreachable git blobs and proven by generator round-trip; 0 removed; no UNVERIFIABLE asset remains |
| Canonical coverage | **PASS** | one reproducible script; separate denominators per engine; historical figures reconciled; 0 integrity defects |
| SAST additive | **VERIFIED FOR TESTED SCOPE** | 10 real-gap rules, each with pattern/record/remediation/pack entry/4 tests/eval case; 10/10 pass; independent breadth only 85/822 |
| DAST evaluation | **VERIFIED FOR TESTED SCOPE** | 65/65 rules have independent observation cases (73 cases, 17 negative controls); no request sent; no exploitability claimed |
| SCA contract logic | **VERIFIED FOR TESTED SCOPE** | 38/38 contract assertions; 15/15 capabilities; fail-closed statuses; synthetic records only |
| Owner/legal | **OPEN** | 4 decisions still `OWNER_DECISION_REQUIRED`; no LICENSE; production ineligible |
| Main App integration | **BLOCKED** | app provider disabled (`VULN_INTEL_PROVIDER=none`); loader absent; app workstream owns the change |
| Production readiness | **NO-GO** | no authorized records, no rights grant, no integration, no license |

### Reproducibility appendix

```bash
node scripts/coverage-report.mjs --json /tmp/coverage-final.json   # §5, §7
node scripts/manifest.mjs --scope all --write /tmp/integrity_final.json
node scripts/manifest.mjs --scope all --check /tmp/integrity_final.json
node scripts/run-eval.mjs                                          # §6
node scripts/test-eval.mjs && node scripts/test-sca-engine.mjs     # §6, §9
npm test                                                           # §8
```

The recovery evidence of §2.2 can be re-checked with `sha256sum` against the eight recorded values; the generator round-trip is reproducible with `node scripts/generate-assets.mjs` (it must produce zero byte changes on a clean tree).
