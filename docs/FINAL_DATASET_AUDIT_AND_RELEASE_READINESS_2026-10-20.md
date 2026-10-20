# Final Dataset audit and release readiness — 2026-10-20

**Repository:** `mdraselislam0101-design/Drobon-Dataset`
**Branch:** `arena/a4caaeb8-drobon-dataset`
**Content commit audited here:** `55c9e2a88c7bcae3737d7a31211263a8bb230637` (parent `ed599c6`)
**Scope:** Dataset repository only. The Main App (`mdraselislam0101-design/Drobon`) and the
production database were not read, modified or bundled in this pump.

> This report is committed *after* the content it describes, in a child commit that carries
> nothing but this file. A report cannot contain the hash of the commit that contains it, so
> the tip SHA is recorded in the pull-request description instead of here. Every other number
> below is reproducible from the tree and the commands in §9.

---

## 1. Verified baseline and final inventory

Both ends were counted from the filesystem and from `git ls-tree`, never from a previous
report.

| Asset | HEAD `ed599c6` | Final | Delta |
|---|---|---|---|
| DAST rules | 65 | **263** | +198 |
| SAST rules | 792 | **950** | +158 |
| Secrets rules | 97 | **97** | 0 |
| **Pack rules total** | **954** | **1,310** | **+356** |
| `knowledge/patterns` | 954 | **1,310** | +356 |
| `knowledge/records` | 914 | **1,310** | +396 |
| `knowledge/remediation` | 954 | **1,310** | +356 |
| `knowledge/cwe` | 61 | **68** | +7 |
| Eval cases | 89 | **1,610** | +1,521 |
| — of which DAST observation cases | 0 | **509** | +509 |
| Tracked files | 4,217 | **7,301** | +3,084 |
| Repository size | — | **12.27 MB** | no file over 1 MB |

`docs/CURRENT_INVENTORY.json` (recomputed from the tree) agrees on every count:
`dastRules 263`, `sastRules 950`, `secretsRules 97`, `packRules 1310`, `patterns 1310`,
`records 1310`, `remediation 1310`, `cweEntries 68`, `evalCasesTotal 1610`,
`evalCasesAssessed 1599`, `evalCasesUnassessed 11`.

The DAST baseline of 263 reported by the previous pump was therefore **verified against the
live tree**, not assumed: `packs/dast/v1/rules` holds exactly 263 JSON files, IDs run
1…270 with 151 and 154 absent as historical gaps, and no ID is duplicated.

## 2. Changes in the audited commit

`55c9e2a` — 5,581 files, +179,120 / −8,739.

**Rule packs and knowledge (all generated from `data/asset-cells/*.json`):**

- DAST 65 → 263 over the seven closed check types; 1,292 executable tests
  (582 positive / 710 negative). Seven rules now carry array-valued headers, which is the
  only way the evaluator's "present but every value blank" and duplicate-directive branches
  can be exercised at corpus level.
- SAST 792 → 950; Secrets unchanged at 97; patterns/records/remediation brought to a strict
  1:1:1 mapping with the 1,310 rules.
- CWE reference 61 → 68, with every rule's `cwe` resolving to an entry that exists.
- Remediation deepened in the **cell definitions**, not in generated JSON, so regeneration
  reproduces it: 258 / 263 DAST rules carry two or more actions, 24 carry an
  Immediate → Durable → Trade-off structure plus a verification step, and rule remediation
  shorter than 60 characters is down to a single rule (`DPK-DAST-050`, frozen by OD-1).

**Evaluation:** 1,610 synthetic cases across all 1,310 rules; 1,599 assessed.

**Tooling:** adds `validate-dast-overlaps`, `validate-capability-coverage`,
`test-current-state`, `test-csp-semantics`, `test-cookie-semantics`, `test-sca-engine`,
`test-sca-fixtures`, `inventory`, `manifest`, `coverage-report`, `eval-coverage-report`,
`originality-report`, `gap-matrix`, `render-capability-coverage`, plus `scripts/lib/`.
`npm test` now chains every gate, and CI runs the additional steps in `.github/workflows/ci.yml`.

**Docs:** new pump reports and generated matrices (capability coverage, current inventory),
updated README / PACKS / corpus targets / requirements matrix. Historical reports are
preserved as history and were not rewritten to look current.

**What did not change:** no rule was retired, renamed, merged or rescoped; no permanent ID was
created from a rejected candidate or reused; `docs/OWNER_DECISIONS.json` is byte-identical to
`ed599c6`; no `LICENSE` file was added; no third-party rule text, catalogue or remediation was
imported.

## 3. Integrity audit

| Check | Result |
|---|---|
| Duplicate rule IDs across DAST + SAST + Secrets | **0** |
| Dangling `patternRefs` | **0** |
| Patterns whose `linkedRules` do not exist | **0** |
| Records whose `relatedPatterns` / `relatedRules` do not exist | **0** |
| Rules without a remediation entry | **0** |
| Patterns / records / remediation without a rule (orphans) | **0 / 0 / 0** |
| Rules whose `cwe` has no entry in `knowledge/cwe` | **0** |
| DAST rules carrying `line` / `lineFrom` / `sourceFile` fields | **0** |

**Source-location honesty.** No DAST artefact claims a source file or line. Runtime evidence
is described as runtime evidence: the rule model has no field that could carry a source span,
`scripts/finding-evidence.mjs` requires real source text plus an exact span and is therefore
not usable for an HTTP observation, and no rule, pattern or record fabricates one. The
finding-evidence ceiling for a DAST detection remains: runtime location, `SHAPE_MATCH`
confidence, `UNVERIFIED` state, `dataFlowEvidence` / `callChainEvidence` `NOT_ASSESSED`, CVSS
absent, source file and line explicitly unavailable.

**Unsupported capabilities are still reported as unsupported.**
`docs/CAPABILITY_COVERAGE_MATRIX.json` keeps `RIGHTS_BLOCKED` for SCA production matching and
seven `APP_INTEGRATION_BLOCKED` rows; no blocked capability was re-labelled as covered.

**Known exceptions preserved, not hidden:**

- 11 UNASSESSED cases: `EVAL-CMD-023/024/025`, `EVAL-SAST-004/007/014/015/016`,
  `EVAL-SEC-111`, `EVAL-SQL-027/028`.
- `EVAL-SAST-008` remains **FAIL** — a real false positive (`DPK-SAST-283` on line 2), kept
  visible exactly as before.
- One false positive in the whole corpus (`precision 0.9993`), zero false negatives.

## 4. Test results and exit codes

Every command was run in the final tree. No command was skipped, piped into a masking
construct, or re-run until green.

| Command | Exit | Result |
|---|---|---|
| `npm test` | **0** | 22,302 `ok`; determinism 5/5; tree digest reproducible |
| `npm run verify` | **n/a** | no such script exists in `package.json`; not reported as passing |
| `node scripts/validate-packs.mjs packs` | 0 | PASS — 1,313 files, 0 errors |
| `node scripts/validate-assets.mjs` | 0 | PASS — 2,620 files, 0 errors |
| `node scripts/validate-audiences.mjs` | 0 | PASS — 1,321 files, 0 errors |
| `node scripts/validate-cwe.mjs knowledge/cwe` | 0 | PASS — 68 files |
| `node scripts/validate-matrix.mjs docs/REQUIREMENTS_MATRIX.json` | 0 | PASS — inventory recomputed, no licence file |
| `node scripts/validate-sources.mjs vuln-intel/sources.json` | 0 | PASS — 1 file |
| `node scripts/validate-corpus.mjs` | 0 | PASS — validated 2,799, verifiedProduction 0 |
| `node scripts/coverage-report.mjs --check` | 0 | PASS |
| `node scripts/inventory.mjs --check` | 0 | matches the tree |
| `node scripts/manifest.mjs --scope all` + `--check` | 0 / 0 | 7,181 files verified |
| `node scripts/originality-report.mjs --check` | 0 | hard defects 0 |
| `node scripts/dedup-report.mjs` | 0 | 84 items, 9 multi-file tuples, **0 conflicts** |
| `node scripts/provenance-report.mjs --check` | 0 | **2,688 / 2,688 recorded** (see §6) |
| `node scripts/check-vectors.mjs` | 0 | 16 / 16 vectors |
| `node scripts/test-packs.mjs` | 0 | 5,422 / 5,422 |
| `node scripts/test-assets.mjs` | 0 | 10,500 / 10,500 |
| `node scripts/test-csp-semantics.mjs` | 0 | 22,983 assertions |
| `node scripts/test-cookie-semantics.mjs` | 0 | 1,666 assertions |
| `node scripts/test-eval.mjs` | 0 | 43 / 43 |
| `node scripts/test-finding-evidence.mjs` | 0 | 31 / 31 |
| `node scripts/test-secret-candidates.mjs` | 0 | 35 / 35 |
| `node scripts/test-sca-engine.mjs` | 0 | 38 / 38 |
| `node scripts/test-sca-fixtures.mjs` | 0 | 177 / 177 |
| `node scripts/test-agent-policy.mjs` | 0 | 91 / 91 |
| `node scripts/test-agent-workflows.mjs` | 0 | 57 / 57 |
| `node scripts/test-rehearsal.mjs` | 0 | 78 / 78 |
| `node scripts/test-importers.mjs` | 0 | 49 / 49 |
| `node scripts/test-consistency.mjs` | 0 | 232 / 232 |
| `node scripts/test-doc-drift.mjs` | 0 | 120 / 120 |
| `node scripts/test-current-state.mjs` | 0 | 155 / 155 |
| `node scripts/validate-capability-coverage.mjs` | 0 | 695 / 695 |
| `node scripts/validate-dast-overlaps.mjs` | 0 | 332 checks, 128 subset pairs (123 expected absence, 5 reviewed) |
| `node scripts/eval-coverage-report.mjs` | 0 | 1,310 / 1,310 rules exercised |
| `node scripts/test-determinism.mjs` | 0 | 5 / 5, whole-tree digest reproducible |
| `node scripts/run-eval.mjs` | 0 | 1,610 cases; 1,599 assessed; 11 UNASSESSED; TP 1,336 / FN 0 / FP 1 |
| `node scripts/generate-assets.mjs` | 0 | 5,195 written, 0 removed, 0 quarantined |

**One real finding, one known exception.** The only non-PASS eval outcomes are the eleven
UNASSESSED cases and `EVAL-SAST-008`, both pre-existing and deliberately preserved. No
assertion, `groundTruth`, `forbiddenDetections`, threshold or expectation was weakened,
skipped or deleted to make this list green.

## 5. `git diff --check`

Exit 2, three hits, all in `docs/proposals/D13-legacy-records/generator.patch`, each on a line
that begins with `+ ` — a unified-diff context line whose payload is a single space. Removing
that byte would change the meaning of the patch, so it was left intact and is reported here
instead of being "fixed" into a different artefact. No other whitespace defect exists in the
staged set.

## 6. Secret, sensitive-data and provenance audit

**Scanned:** every one of the 5,567 changed/added files (full contents, not a sample), before
staging and again on the staged set.

| Pattern class | Hits | Nature |
|---|---|---|
| PEM private key | 1 | `-----BEGIN RSA PRIVATE KEY----- EXAMPLE` — a labelled `synthetic: true, testOnly: true` eval fixture for `DPK-SEC-004` |
| AWS access key id | 1 | `AKIA1234567890ABCDEF` — synthetic placeholder for `DPK-SEC-001` |
| GitHub tokens | 9 | `ghp_/gho_/ghs_/ghu_/github_pat_` + `AAAA…` placeholders |
| Slack / Google / Twilio / Stripe / JWT | 14 | placeholder bodies (`AAAA…`, `EXAMPLE`, sequential hex) in `EVAL-SEC-*` fixtures |
| Real-looking high-entropy credential | **0** | — |

Every hit is inside `data/eval-cases/EVAL-SEC-*.json` (or the guard list in
`scripts/test-consistency.mjs`) and every one carries `"synthetic": true` and
`"testOnly": true` with an `origin: original-authored` provenance block. They are the
detection fixtures the Secrets rules are tested against, they are excluded from production
counts, and the repository's own leak guard already whitelists these exact markers
(`FIXTURE_SAFE_MARKERS`).

**Other preflight results:** no `.env` file, no key material, no credential file, no database
dump, no binary blob, no file above 1 MB, no `node_modules`, no log, no artefact outside
`packs/ knowledge/ data/ docs/ scripts/` plus `.github/workflows/ci.yml`, `README.md`,
`package.json` and four `DROBON_*` tracking files. The staged set is exactly that allowlist —
`git add .` was not used.

**Provenance is now commit-verified.** Before `55c9e2a`, `provenance-report.mjs` reported
1,969 / 2,688 recorded and 719 `PENDING`, which is expected for files that exist only in the
working tree — the report derives evidence from commit history. After the commit the same
command reports **2,688 / 2,688 recorded**, with exactly those 719 files carrying
`55c9e2a / 2026-10-20 / mdraselislam0101-design`, and `--check` exits 0. That is independent
confirmation that the commit contains what this report says it contains.

## 7. Rights, licensing and owner decisions

| Gate | State | Effect |
|---|---|---|
| `LICENSE` | absent | all rights reserved by default; redistribution is not granted |
| `docs/OWNER_DECISIONS.json` | unchanged, 5 entries, `ORIGINAL_CONTENT = APPROVED`, four `OWNER_DECISION_REQUIRED` | no decision was inferred or fabricated |
| BLK-001 | `BLOCKED_OWNER_DECISION` | no licence grant for original content |
| BLK-002 | `BLOCKED_OWNER_DECISION` | per-source redistribution (GHSA / OSV / NVD / CWE / original) |
| BLK-003 | `BLOCKED_PRODUCTION_LOCK` | production ingestion authorization |
| BLK-004 | `BLOCKED_OWNER_DECISION` | approval expiry and refresh cadence |
| OD-1 (`DPK-DAST-050`) | `BLOCKED_PENDING_OWNER_DECISION` | rule left untouched, including its 45-character remediation |
| D-13 (legacy record exception) | inactive | unchanged |
| SCA production matching | `RIGHTS_BLOCKED` | no real advisory import, no paid API |

**Originality:** 0 hard defects. The report lists 16 review-flagged near-duplicate
remediation texts (15 of them SAST) and 1 review-flagged rule-description pair
(`DPK-SAST-038` / `DPK-SAST-049`); these are review prompts, not copied material, and are
unchanged by this commit.

**Rights verdict: BLOCKED.** Passing tests are not a legal conclusion, and this pump adds no
rights evidence.

## 8. Separate verdicts

| Dimension | Verdict | Reason |
|---|---|---|
| Dataset tests | **PASS** | every applicable gate ran and exited 0 |
| Dataset content completion | **PARTIAL** | 263 / 500 DAST rules; every remaining family inside the closed contract is either represented or rejected on evidence |
| Git commit | **COMPLETE** | `55c9e2a`, worktree clean, allowlist only |
| GitHub push | see §10 | verified or blocked, never assumed |
| Dataset rights | **BLOCKED** | no licence, four owner decisions open |
| Dataset publication | **NO-GO** | rights blocked; technical readiness and publication readiness are different questions |
| Main App integration | **NOT VERIFIED** | static contracts only; the App has no loader for `packs/dast`, and no App runtime test was performed |

## 9. Reproduce this audit

```
node scripts/generate-assets.mjs
node scripts/validate-packs.mjs packs
node scripts/validate-assets.mjs
node scripts/validate-dast-overlaps.mjs
node scripts/inventory.mjs --check
node scripts/manifest.mjs --scope all --check <manifest.json>
node scripts/provenance-report.mjs --check
node scripts/originality-report.mjs --check
node scripts/coverage-report.mjs --check
npm test
node scripts/run-eval.mjs
```

Expected: exit 0 for every command; 22,302 `ok` in `npm test`; 1,336 / 0 / 1 in `run-eval`;
263 DAST rules; 1,310 pack rules; 2,688 / 2,688 provenance records.

## 10. Push, and what was not done

The push result is deliberately **not** written in this file, because the file is part of the
commit that is pushed. It is reported in the pull-request description and in the pump
summary, with the remote tip SHA fetched back with `git ls-remote` and compared against the
local commit.

Not done, by instruction and by policy: no force push, no branch other than
`arena/a4caaeb8-drobon-dataset`, no tag, no release, no deployment, no Main App change, no
`git reset --hard`, no `git clean`, no file deleted or renamed, no rule retired, no ID reused,
no `LICENSE` added, no owner decision assumed.
