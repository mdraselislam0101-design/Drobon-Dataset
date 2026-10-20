# DROBON AEGIS — SAST + DAST + SCA additive dataset expansion pump (2026-10-19)

Branch: `arena/a4caaeb8-drobon-dataset` (HEAD `ed599c6`, no git write performed).
Workstream: Dataset repository only. Main App read-only. No production, VPS, legal
or release action was taken.

This was an **implementation** pump: assets were created, wired, regenerated,
validated and evaluated. Nothing below is a plan; every count is recomputed from
the tree by the command named next to it.

---

## 1. Scope, authorization and invariants preserved

| Invariant | Result |
|---|---|
| Dataset repo only; Main App unmodified | PASS — Main App probe `/tmp/app-probe` stayed at `c32c797a…`; no file written there |
| No git/PR/tag/release/deploy operation | PASS — zero commits, pushes or tags |
| No `LICENSE` file, no license change | PASS — `LICENSE*`/`COPYING*` absent |
| `docs/OWNER_DECISIONS.json` untouched | PASS — no edit |
| D-13 (40 legacy records) not activated | PASS — 40 legacy ids stay inactive, excluded from active counts |
| No real intelligence feed (CVE/NVD/GHSA/OSV/KEV/EPSS) imported | PASS — this pump added **0** real records; the 100 frozen seed files were not modified |
| No paid API / subscription | PASS — zero network calls in the new engine and evaluation paths |
| No fabricated evidence, provenance or metrics | PASS — every new asset is `origin: original-authored`; severities are rule-fixed labels, not CVSS |
| Existing valid assets preserved | PASS after repair — one accidental overwrite of a cell file was restored (see §7), 0 net deletions (`git status` deletions = 0) |

Credentials: no secret value was collected, stored or printed; the synthetic
fixtures use placeholder shapes only.

---

## 2. Method (gap → authorized scope → asset → relationships → tests → coverage)

1. Capability census from the live tree: rule/pattern/record/remediation counts,
   language and category histograms, DAST check types, eval coverage.
2. Gap probing with a real detector harness (`/tmp/gapcheck.mjs`) that compiles
   every SAST/secrets pattern and tests candidate sinks against them, so a
   "missing" sink was only accepted after the whole pack stayed silent.
3. Cell authoring (original prose + regex + positive/negative/boundary lines),
   then regeneration through `scripts/generate-assets.mjs` (stable ids, CWE
   linkage, schema gate, ReDoS gate, leak gate, deterministic output).
4. Per-rule evaluation cases authored before the first run of the rule, with
   declared ground truth.
5. DAST: one synthetic observation per previously-unevaluated check, plus
   negative controls; observation mode only, no request sent.
6. SCA: original matching logic + synthetic fixtures + fail-closed contract
   tests, with the production data lock enforced in code.
7. Full re-validation: packs, assets, audiences, consistency, evaluation,
   documentation drift, current-state, determinism, integrity manifest.

---

## 3. SAST — before / after

| Metric | Before | After | Delta |
|---|---|---|---|
| SAST rules (`packs/sast/v1/rules`) | 792 | **812** | +20 |
| Patterns (`knowledge/patterns`) | 954 | **974** | +20 |
| Records (`knowledge/records`) | 914 | **934** | +20 |
| Remediation (`knowledge/remediation`) | 954 | **974** | +20 |
| Distinct SAST rules exercised by an independent eval case | 55 | **75** | +20 |
| SAST rules with executable positive+negative pack tests | 792/792 | **812/812** | +20 |
| SAST rules reachable by an analyzed app language (full) | 549 | **568** | +19 |
| Partially reachable (`shell`/`bash`) | 25 | **26** | +1 |
| No analyzed language tag | 207 | 207 | 0 |
| Any-file rules (omitted `languages`) | 11 | 11 | 0 |
| Distinct language ids across SAST rules | 111 | 111 | 0 |

New languages carried by this batch already existed in the catalog; no new
language id was invented, and no rule was widened to make it reachable.

### New SAST rules (all original-authored, one pattern + one record + one remediation each)

| Rule | Language(s) | CWE | Severity | Category | Concept |
|---|---|---|---|---|---|
| DPK-SAST-803 | java | CWE-749 | MEDIUM | access-control | WebView `setJavaScriptEnabled(true)` |
| DPK-SAST-804 | java | CWE-749 | MEDIUM | access-control | WebView `setAllowFileAccess(true)` |
| DPK-SAST-805 | java | CWE-749 | MEDIUM | access-control | `setAllowUniversalAccessFromFileURLs(true)` |
| DPK-SAST-806 | kotlin | CWE-749 | MEDIUM | access-control | Kotlin `javaScriptEnabled = true` |
| DPK-SAST-807 | csharp | CWE-502 | HIGH | unsafe-deserialization | `Assembly.Load`/`LoadFrom`/`LoadFile` |
| DPK-SAST-808 | python | CWE-502 | HIGH | unsafe-deserialization | `dill.loads` |
| DPK-SAST-809 | ruby | CWE-502 | HIGH | unsafe-deserialization | `YAML.unsafe_load` |
| DPK-SAST-810 | dockerfile | CWE-798 | MEDIUM | container-security | credential-shaped `ARG` |
| DPK-SAST-811 | javascript | CWE-79 | MEDIUM | xss | `.outerHTML =` |
| DPK-SAST-812 | javascript | CWE-79 | MEDIUM | xss | `insertAdjacentHTML` |
| DPK-SAST-813 | yaml (GitHub Actions) | CWE-94 | HIGH | code-injection | `${{ github.event.* }}` interpolation |
| DPK-SAST-814 | java | CWE-330 | MEDIUM | weak-cryptography | `new Random()` |
| DPK-SAST-815 | kotlin | CWE-330 | MEDIUM | weak-cryptography | `Random()` |
| DPK-SAST-816 | yaml (Kubernetes) | CWE-284 | MEDIUM | container-security | `automountServiceAccountToken: true` |
| DPK-SAST-817 | dockerfile | CWE-327 | MEDIUM | weak-cryptography | `openssl enc -des` family |
| DPK-SAST-818 | shell, bash | CWE-327 | MEDIUM | weak-cryptography | `openssl enc -des` family |
| DPK-SAST-819 | javascript | CWE-295 | HIGH | transport-security | `NODE_TLS_REJECT_UNAUTHORIZED = "0"` |
| DPK-SAST-820 | javascript | CWE-327 | MEDIUM | weak-cryptography | `crypto.createDecipher` (no IV) |
| DPK-SAST-821 | php | CWE-330 | LOW | weak-cryptography | `uniqid` |
| DPK-SAST-822 | python | CWE-502 | HIGH | unsafe-deserialization | `yaml.load_all` |

Each rule ships: unique stable id, bounded lexical pattern, language/comment
context, severity rationale in the record’s `risk` + remediation `whyItMatters`,
CWE mapping that resolves in `knowledge/cwe`, limitation + false-positive notes,
four executable example tests (two positive, two negative), one remediation entry
with actions and a verification step, and an independent evaluation case.

Honesty notes carried by the rules themselves: lexical only, no taint/semantic
claim; `github.event.*` matches safe `env:` usage too (documented limitation and
an explicit `match: true` example for that usage); reflection/deserialization
rules state that attacker control is a review question, not a detection claim.

---

## 4. DAST — before / after

| Metric | Before | After | Delta |
|---|---|---|---|
| DAST rules | 65 | 65 | 0 |
| DAST rules with an independent observation case | 22 | **65** | +43 |
| New DAST cases authored this pump | — | **50** | 43 positive + 7 negative |
| DAST eval cases (synthetic observations) | 19 | **60** | +41 |
| Positive observation cases | 22 | **65** | +43 |
| Negative controls / boundary cases | 3 | **10** | +7 |
| Requests sent | 0 | **0** | 0 |

Breadth added per check family: missing-header (8 rules), missing-directive
(7), header-value disclosure/weakness (21), response-body disclosure and
mixed-content (7). Each case declares `mode: observation`, `synthetic: true`,
`testOnly: true`, a no-request limitation, and a rationale separating a missing
control (hardening gap) from exploitability.

Revalidated decisions (recorded, not changed):

* **Expect-CT** (DPK-DAST-040) stays LOW/informational: the header is
  deprecated and its absence proves nothing about a live target.
* **COEP / COOP** (DPK-DAST-046/047) stay MEDIUM: `unsafe-none` is a conditional
  isolation gap that a reviewer must connect to an actual cross-origin policy;
  the observation does not prove exploitability.
* No DAST rule claims semantic detection; all are passive response checks.

---

## 5. SCA — original logic, contracts and the seven required dimensions

New: `scripts/sca-engine.mjs` (original, zero-dependency) + `scripts/test-sca-engine.mjs`
(38 assertions), wired into `npm test`.

Logic implemented:

* coordinate normalisation (ecosystem allowlist, bounded package name, plain
  release version) — invalid input throws `INVALID_COORDINATE`;
* synthetic record validation (own schema `drobon.sca.synthetic-advisory/v1`,
  `fixture: true`, `DROBON-SAMPLE-NNN` id, fixture provenance, parseable ranges);
* **production data lock enforced in code**: a record with `fixture: false` or a
  third-party id (e.g. `GHSA-…`) refuses provider construction
  (`REAL_RECORD_REFUSED` / `INVALID_RECORD`);
* fail-closed assessment using the validated local range evaluator:
  `NO_DATA_LOADED` for an empty set, `NOT_ASSESSED` when a version/range cannot
  be proven, `ASSESSED` otherwise — never a guessed match, never a confident
  empty answer on an unevaluable input;
* deterministic severity-then-id ordering, frozen outputs, no scoring invented;
* no HTTP/DNS/socket import and no `fetch` call (asserted by test).

Seven dimensions (reported separately, as required):

| # | Dimension | Result |
|---|---|---|
| 1 | Original logic implemented | **1 engine module**; coordinate/record/matching/fail-closed/ordering logic all original |
| 2 | Synthetic tests passed | **38 / 38** (`node scripts/test-sca-engine.mjs`, exit 0) |
| 3 | Authorized real records | **0** — the 100 frozen seed records (84 identity items) are preserved read-only and refused by the synthetic provider |
| 4 | Matching evaluated | **0 real matches** (production lock); synthetic matching exercised, including fixed-version and branch boundaries |
| 5 | Rights verified | **0** — GHSA seed terms reviewed (`VERIFIED_ALLOWED`) but redistribution is `UNVERIFIED`; owner batch authorization absent |
| 6 | Main App integration | **BLOCKED** — app seam `assess(coordinates) → {providerId, datasetStatus, advisories[]}` is documented; app runs `VULN_INTEL_PROVIDER=none`; no Dataset provider is wired |
| 7 | Production eligibility | **NOT ELIGIBLE** — ingestion gates 4/4 BLOCKED; breadth 0/100,000 |

---

## 6. Evaluation coverage

| Population | Before | After |
|---|---|---|
| Cases | 157 | **244** |
| Assessed | 146 | **233** |
| UNASSESSED (excluded from scoring) | 11 | 11 |
| True positives | 98 | **165** |
| False negatives | 0 | **0** |
| False positives (documented) | 1 | **1** |
| Precision / recall (assessed synthetic) | 0.9899 / 1.0000 | **0.9940 / 1.0000** |
| Distinct rules exercised | 84 / 954 (8.81%) | **147 / 974 (15.09%)** |
| SAST / secrets / DAST distinct rules | 55 / 7 / 22 | **75 / 7 / 65** |

New cases: 37 SAST (20 positive, 13 negative-control, 4 boundary) and 50 DAST
(43 positive, 7 negative). `EVAL-SAST-008` remains the single preserved failure
(1 documented false positive, docstring trap) — it was not weakened or relabelled.
The 11 UNASSESSED cases (`EVAL-CMD-023/024/025`, `EVAL-SAST-004/007/014/015/016`,
`EVAL-SEC-111`, `EVAL-SQL-027/028`) are still unassessed and contribute no true
positives.

---

## 7. Defects found and repaired

1. **Evaluation report truncation (real, user-visible).** `scripts/run-eval.mjs`
   wrote the report and immediately called `process.exit(0)`; on a pipe the
   pending write was truncated at ~146 KB once the corpus passed 240 cases.
   `test-eval` then parsed invalid JSON. Fixed by setting `process.exitCode`
   without forcing termination, and the harness now reads with a 64 MiB buffer.
2. **Cell-file overwrite during authoring.** The new calls cell file initially
   reused the name `sast-calls-5.json`, clobbering an existing tracked fixture
   set; regeneration consequently removed 68 tracked generated files (16 rules,
   patterns, records, remediation and 4 CWE pages). All 68 were restored from
   HEAD; the new cells now live in `sast-calls-7.json`; regeneration is
   byte-identical (determinism PASS) and the prior DAST cases that had been
   overwritten were recovered from their original authoring script. Net
   deletions: 0.
3. **Match-quality defects in the new rules.** The three Java WebView setters
   and the TLS override matched a truncated token (`setJavaScriptEnabled(true`
   without `)`, `…= "0` without the quote). Patterns now close the call/value,
   so evidence text and mustContain evidence agree.
4. **Documentation count drift.** 26 drift assertions across README,
   CORPUS_GAP_REPORT, CAPABILITY_COVERAGE, CAPABILITY_GAP_MATRIX, AUDIENCES,
   SCA proposal, REQUIREMENTS_MATRIX, CORPUS_TARGETS and COVERAGE_MAP were
   recomputed from the tree and reconciled (historical changelog lines kept).
5. **Register staleness.** GAP-031 (DAST breadth) is now RESOLVED; GAP-016 was
   updated to 812/1000; five new rows record the SCA engine closure, the report
   truncation closure, the untracked-worktree risk, the 11 UNASSESSED policy and
   the revalidated DAST severities (register now 35 rows).

---

## 8. Duplicate, dangling and originality checks

| Check | Result |
|---|---|
| True duplicates (same pattern + same language) | **0** |
| Shared-pattern groups | 33 groups / 89 rules (was 32/87; the new `openssl enc` dockerfile/shell pair is a reviewed language-native sibling) |
| Groups disagreeing on CWE | 13 (unchanged; owner CWE review remains open) |
| Possible overlaps (≥6 rules on a bare name) | 4 (unchanged) |
| Dangling rule↔pattern or record↔pattern links | **0** |
| Rules without a pattern / patterns without a rule | 0 / 0 |
| Rules without remediation | **0 / 974** |
| Originality report (`--check`) | exit 0; 244 cases / 147 distinct rules; every new asset `original-authored` |
| External/advisory text in new assets | none — no CVE/GHSA/OSV ids, no copied vendor text |

---

## 9. Four-UserType mapping

| User type | What this pump added |
|---|---|
| **DEVELOPER** | 20 new actionable rules in 10 languages/formats, each with a copy-paste remediation action and a verification step (e.g. replace `dill.loads`, close the WebView capability, pass workflow event data through `env:`). |
| **STUDENT** | 20 new concept records with applicability/risk/why text in plain language, plus 87 new synthetic fixtures that demonstrate vulnerable vs safe counterparts. |
| **SECURITY_PROFESSIONAL** | CWE-mapped signals (CWE-749/502/798/79/94/330/284/327/295) with false-positive and limitation statements; DAST checks now all have independent evidence (65/65). |
| **PENTESTER** | DAST observation breadth complete (60 synthetic cases, 65/65 rules) with explicit passive-only, no-request semantics and passive-vs-exploitable wording. |

---

## 10. Verification evidence (commands and exit codes)

| Command | Exit | Evidence |
|---|---|---|
| `npm test` | **0** | 16,883 assertions: 600 + 4,062 + 2,966 + 7,684 + 218 + 78 + 49 + 91 + 57 + 31 + 35 + 38 + 41 + 119 + 153 + 656 + 5, 0 failures |
| `node scripts/validate-packs.mjs packs` | 0 | PASS (977 files, 0 errors) |
| `node scripts/validate-assets.mjs` | 0 | PASS (1,908 files, 0 errors) |
| `node scripts/validate-audiences.mjs` | 0 | PASS (985 files, 0 errors) |
| `node scripts/validate-cwe.mjs knowledge/cwe` | 0 | PASS (61 files, 0 errors) |
| `node scripts/validate-matrix.mjs` | 0 | PASS (matrix valid, inventory recomputed, no license file) |
| `node scripts/validate-capability-coverage.mjs` | 0 | 656 passed, 0 failed |
| `node scripts/render-capability-coverage.mjs --check` | 0 | rendered view matches the JSON |
| `node scripts/test-consistency.mjs` | 0 | PASS (218/218) |
| `node scripts/test-eval.mjs` | 0 | 41 passed, 0 failed |
| `node scripts/test-sca-engine.mjs` | 0 | 38 passed, 0 failed |
| `node scripts/eval-coverage-report.mjs` | 0 | 147/974 (15.09%); SAST 75/812, secrets 7/97, DAST 65/65 |
| `node scripts/run-eval.mjs` | 0 | 244 cases, 233 assessed, TP 165 / FN 0 / FP 1 |
| `node scripts/originality-report.mjs --check` | 0 | no hard defects |
| `node scripts/test-doc-drift.mjs` | 0 | 119 passed, 0 failed |
| `node scripts/test-current-state.mjs` | 0 | 153 passed, 0 failed |
| `node scripts/inventory.mjs --check` | 0 | inventory matches the tree |
| `node scripts/manifest.mjs --scope all --write /tmp/integrity8.json` | 0 | wrote 4,363 files |
| `node scripts/manifest.mjs --scope all --check /tmp/integrity8.json` | 0 | PASS (4,363 files verified) |
| `node scripts/ingestion-gates.mjs` | **1 (expected)** | 4/4 gates blocked (HOLD) |
| `node scripts/test-determinism.mjs` | 0 | 5/5; regenerated tree byte-identical |
| `git status --porcelain` | n/a | 2,305 modified, 256 untracked, **0 deletions** |

Worktree note: the modified-file count moved 2,306 → 2,305 because
`data/asset-cells/sast-calls-5.json` is back at its committed content after the
overwrite repair; determinism proves the regenerated tree is unchanged.

---

## 11. Remaining gaps and exact blockers

| ID | Gap | Type | Exact blocker |
|---|---|---|---|
| GAP-001 | Real advisory breadth 0/100,000 | Data | Production data lock; owner authorization required |
| GAP-002 | Redistribution grant (BLK-001/002) | Legal | No LICENSE; owner/legal decision |
| GAP-003/004 | Importer dry-run and refresh cadence | Governance | Owner decision; no live feed allowed |
| GAP-005..009 | App-side pack/loader integration for SAST, secrets, DAST, remediation, audiences | Integration | Main App workstream; read-only here |
| GAP-016 | Breadth vs 1,000 planning target (812/1,000) | Engineering | Evidence-gated batches only |
| GAP-017/018 | Git/CI integration, account lifecycle | Out of scope | Separate workstream |
| GAP-037 | 256 untracked files (new assets) | Operability | No git writes authorized in this workstream |
| GAP-038 | 11 eval cases UNASSESSED | Policy | Scoring policy owned by the owner |
| GAP-039 | DAST isolation-header severities | Documentation | Severity rubric owned by reviewer policy |
| — | 737/812 SAST rules without an independent eval case | Engineering | Case authoring continues in batches (this pump: +20) |
| — | 207 SAST rules with no analyzed language tag | App contract | Hyphenated/absent app families; schema kept fail-closed |
| — | D-13 40 legacy records inactive | Owner decision | Not activatable without a decision |

---

## 12. Owner / legal, Main App integration, production readiness

* **Owner/legal gates: BLOCKED.** No LICENSE, D-ORIG is not a legal assignment,
  GHSA seed redistribution is unverified, and 4 owner decisions remain pending.
  Nothing in this pump changes a rights status.
* **Main App integration: BLOCKED.** The app contract
  `assess(coordinates) → {providerId, datasetStatus, advisories[]}` matches the
  new engine shape, but the app still runs `VULN_INTEL_PROVIDER=none`; the
  Dataset was not loaded, copied or referenced by the app.
* **Production readiness: NO-GO.** 0 production-verified records, 0/100,000
  breadth, 4/4 ingestion gates blocked, no rights grant.

---

## 13. Honest reading of this pump

What genuinely improved: 20 new end-to-end SAST rules (rule + pattern + record +
remediation + tests + independent evaluation), DAST evaluation breadth from
22/65 to **65/65**, an original fail-closed SCA engine with 38 tests, and the
repair of a real report-truncation defect that would have hidden evaluation
results. Distinct-rule evaluation coverage rose from 8.81% to 15.09%.

What did **not** change: no real advisory data was added or matched, no rights
were granted, no app integration occurred, and 737 SAST rules remain without an
independent eval case. Those are reported as gaps, not converted into
completeness.

---

## 14. Status

```
SAST ADDITIVE COVERAGE: VERIFIED 100% (20/20 new rules complete end-to-end; SAST eval breadth 75/812 = 9.24%)
DAST ADDITIVE COVERAGE: VERIFIED 100% (65/65 rules independently evaluated; 60 synthetic cases; 0 requests)
SCA LOGIC/CONTRACT READINESS: VERIFIED 100% (38/38 contract and fail-closed tests)
SCA AUTHORIZED PRODUCTION DATA: VERIFIED COUNT 0 / REQUIRED COUNT 100,000
RULE/PATTERN/RECORD/REMEDIATION INTEGRITY: PASS (974/974/974 links; 0 dangling; 0 true duplicates)
EVALUATION COVERAGE: 147/974 distinct rules = 15.09%; 244 cases (233 assessed / 11 UNASSESSED); TP 165 / FN 0 / FP 1
OWNER/LEGAL GATES: BLOCKED (no LICENSE; redistribution unverified; 4 owner decisions pending)
MAIN APP INTEGRATION: BLOCKED (app provider disabled; loader absent)
PRODUCTION READINESS: NO-GO
```
