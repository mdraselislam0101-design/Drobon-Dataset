# NEXT MASTER PUMP — SAST breadth, evaluation coverage, SCA contract hardening (2026-10-19)

**Scope:** Dataset repository only. Main App read-only. No production data, no advisory feeds,
no licence action, no git writes. All fixtures are synthetic and `testOnly`.

| Field | Value |
|---|---|
| Repository | `mdraselislam0101-design/Drobon-Dataset` |
| Branch | `arena/a4caaeb8-drobon-dataset` |
| Start HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` |
| End HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged; git writes not authorised) |
| Worktree | 2,315 modified · 1,662 untracked · 0 deleted |
| `LICENSE` | absent (BLK-001 invariant preserved) |
| Main App | `c32c797a549453802bd6d82c5673d2a1728457a3`, read-only inspection only, no writes |

---

## A. Executive outcome

**PARTIAL — release decision NO-GO.**

This pump did three things and refused a fourth:

1. **SAST breadth (Pump B):** 16 genuinely distinct rules added (DPK-SAST-945…959, 961),
   934 → **950** active SAST rules. One candidate was rejected as a near-duplicate of
   DPK-SAST-770. The 50-rule remainder to the 1,000 objective is **not manufactured**: the
   probe list no longer yields 50 distinct, testable capabilities at this granularity.
2. **Evaluation coverage (Pump C):** 370 synthetic cases added; 676 → **1,046** cases.
   Distinct rules exercised 366 → **1,044**; SAST rule-level coverage 197/934 (21.1 %) →
   **875/950 (92.1 %)**; uncovered SAST rules 737 → **75**. Case coverage is reported
   separately from rule coverage throughout.
3. **SCA contract hardening (Pump D):** one new synthetic collision corpus, two new
   capability assertions (`ecosystem-collision`, `alias-ecosystem-scope`); fixture suite
   **168 assertions / 8 corpora, 0 failed**; coverage-report SCA surface **26 capabilities /
   206 assertions**.
4. **Not done, deliberately:** no SCA rule packs (owner decision), no production advisories
   (rights), no LICENSE (legal), no App loader claim (external workstream). Those gaps stay
   BLOCKED and are listed in §D and §M.

All executable verification is green: `npm test` exit 0 with **19,230 assertions**, plus
`validate-packs` (1,122 files), `validate-assets` (2,198), `validate-audiences` (1,130),
`validate-cwe` (63), `coverage-report --check`, `inventory --check` and
`originality-report --check`.

---

## B. Repository identity and safety envelope

| Check | Result |
|---|---|
| `git rev-parse --abbrev-ref HEAD` | `arena/a4caaeb8-drobon-dataset` |
| `git rev-parse HEAD` (start = end) | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` |
| `git status --porcelain` | 2,315 `M`, 1,662 `??`, 0 `D` |
| Commits / pushes / branches / tags / releases | none |
| `LICENSE` | not created, not modified |
| `docs/OWNER_DECISIONS.json` schema | untouched; no new keys; D-13 still inactive |
| Production DB / VPS / deployment | untouched |
| Real vulnerability intelligence import | none (84 seed advisories only, 0 production) |
| Main App writes | none (read-only clone at `c32c797`, same commit as the Dataset pin) |

All 3,977 worktree changes are the cumulative Dataset-authored output of this session's pumps;
none overwrite unrelated work, and every historical report is preserved byte-for-byte.

---

## C. Baseline reconciliation

Baseline = the closed report `docs/ULTIMATE_TOTAL_GAP_CLOSURE_MASTER_PUMP_2026-10-19.md`
(SAST 934 / eval 676). Every row below was re-derived from the tree, not from prose.

| Metric | Prior report | Verified now | Δ | Derivation |
|---|---|---|---|---|
| SAST rule files | 934 | **950** | +16 | `ls packs/sast/v1/rules \| wc -l` |
| Secrets rule files | 97 | 97 | 0 | same |
| DAST rule files | 72 | 72 | 0 | same |
| Rule packs (all domains) | 1,103 | **1,119** | +16 | 950 + 97 + 72 |
| Knowledge patterns | 1,103 | **1,119** | +16 | `knowledge/patterns` |
| Knowledge records | 1,063 | **1,079** | +16 | `knowledge/records` |
| Remediation entries | 1,103 | **1,119** | +16 | `knowledge/remediation` |
| CWE entries | 63 | 63 | 0 | `knowledge/cwe` (all `cweVersion` 4.20) |
| Eval cases | 676 | **1,046** | +370 | `data/eval-cases` |
| Assessed / UNASSESSED | 665 / 11 | **1,035 / 11** | +370 / 0 | evaluator report |
| True positives | 389 | **1,067** | +678 | `run-eval` |
| False positives / false negatives | 1 / 0 | **1 / 0** | 0 | `run-eval` |
| Precision | 0.9974 | **0.9991** | +0.0017 | 1,067 / 1,068 |
| Recall (assessed synthetic population) | 1.0 | 1.0 | 0 | 1,067 / 1,067 |
| Distinct rules exercised | 366 | **1,044** | +678 | detections ∪ forbidden |
| SAST rules with ≥1 positive eval | 197 | **875** | +678 | rule-id join |
| SAST rule-level coverage | 21.1 % | **92.1 %** | +71.0 pp | 875 / 950 |
| `test-packs` assertions | 4,578 | **4,642** | +64 | 4 executable tests per new rule |
| `npm test` assertions | 18,980 | **19,230** | +250 | 18 suites |
| `npm test` exit | 0 | **0** | — | log §J |

---

## D. GAP-AEGIS ledger — dispositions

| ID | Problem statement | Disposition | Evidence (this pump) | What remains |
|---|---|---|---|---|
| GAP-AEGIS-01 | SAST 934 vs 1,000; 66 short | **PARTIAL** | 950 active, +16 valid rules, 1 rejected near-duplicate, 0 duplicate signals (`test-packs` 4,642/4,642) | 50 rules; no remaining candidate in the probe list passes the distinctness/testability gate |
| GAP-AEGIS-02 | SAST eval 197/934; 737 rules without an eval | **PARTIAL** | 875/950 (92.1 %); 1,046 cases; 75 rules uncovered (45 HIGH, 30 MEDIUM) | 75 rules ≈ 150 case ids vs 146 free `EVAL-SAST-###` slots (next free 854); needs either a shared-negative design or an id-scheme owner decision |
| GAP-AEGIS-03 | SCA rule packs 0 | **BLOCKED** | Contract hardened instead: 8 fixture corpora / 168 assertions / 26 capabilities / 206 assertions; `packs/sca` still empty | Owner decision on `docs/SCA_RULE_SCHEMA_PROPOSAL.md` |
| GAP-AEGIS-04 | Production advisories 0; GATE-1…4 blocked | **BLOCKED** | 100 seed files → 84 unique items, 9 multi-file tuples, 0 conflicting tuples, `verifiedProductionCount` 0 | Rights-cleared source + gate approval |
| GAP-AEGIS-05 | No LICENSE; BLK-001 | **BLOCKED** | Invariant re-verified: no `LICENSE`, no licence grant inferred | Owner/legal decision |
| GAP-AEGIS-06 | App loader not implemented; packs unreachable at runtime | **BLOCKED** | Main App unchanged at `c32c797`; no loader/adapters observed in the inspected paths | App-repo workstream (class E design) |
| GAP-AEGIS-07 | 11 UNASSESSED eval cases | **BLOCKED** | Preserved unchanged: EVAL-CMD-023/024/025, EVAL-SAST-004/007/014/015/016, EVAL-SEC-111, EVAL-SQL-027/028 | Ground truth authored by an owner/reviewer, never guessed |
| GAP-AEGIS-08 | 40 legacy patterns without records; D-13 inactive | **BLOCKED** | `originality-report`: 40 patterns without record, 0 rules without pattern; D-13 untouched | Owner decision on retention/records |
| GAP-AEGIS-09 | DAST vocabulary closed at 7 check types | **BLOCKED** | DAST 72/72 evaluated; no schema change attempted | Approved schema decision |
| GAP-AEGIS-10 | App-catalog language reachability | **PARTIAL** | Measured: fully 671 / partial 29 / unreachable **239** / no-`languages` 11 (115 ids, 47 intersecting) | 18 of the 31 new-generation rules target families the App catalog does not analyse; App analyzer expansion or documented acceptance |

No disposition is CLOSED that still has an open dependency; no blocked item was re-labelled
as complete because its tests pass.

---

## E. SAST changes (Pump B)

### E.1 Added — 16 rules

| Rule | Language | Capability | CWE | Severity |
|---|---|---|---|---|
| DPK-SAST-945 | java | WebView remote debugging enabled in a shipped build | CWE-489 | MEDIUM |
| DPK-SAST-946 | java | App-private file written world-readable | CWE-732 | MEDIUM |
| DPK-SAST-947 | apache | `SSLProtocol all` (SSLv3/TLS1.0 left enabled) | CWE-327 | MEDIUM |
| DPK-SAST-948 | csharp | Request target assembled from runtime input (SSRF) | CWE-918 | MEDIUM |
| DPK-SAST-949 | html | CSP that permits `unsafe-inline` | CWE-693 | MEDIUM |
| DPK-SAST-950 | gradle | Release build signed with the debug key | CWE-693 | MEDIUM |
| DPK-SAST-951 | gradle | Release build with minification disabled | CWE-693 | MEDIUM |
| DPK-SAST-952 | swift | `allowAnyHTTPSCertificate` / trust-all policy | CWE-295 | HIGH |
| DPK-SAST-953 | swift | Keychain item `kSecAttrAccessibleAlways` | CWE-732 | MEDIUM |
| DPK-SAST-954 | java | HTTP target assembled from runtime input (SSRF) | CWE-918 | MEDIUM |
| DPK-SAST-955 | jinja | `\|safe` filter applied to a template value | CWE-79 | MEDIUM |
| DPK-SAST-956 | nginx | WebDAV methods enabled (`dav_methods`) | CWE-284 | MEDIUM |
| DPK-SAST-957 | nginx | `ssl_ciphers ALL` / `HIGH:!aNULL` disabled | CWE-327 | MEDIUM |
| DPK-SAST-958 | nim | `execCmd`/`execProcess` shell execution | CWE-78 | HIGH |
| DPK-SAST-959 | python | `send_file` path built from a runtime value | CWE-22 | MEDIUM |
| DPK-SAST-961 | vba | `CreateObject("WScript.Shell")` | CWE-78 | HIGH |

ID 960 is not reused; it was retired earlier and stays retired. Each rule carries a unique
canonical id, one pattern, one pattern ref, one record, one remediation entry, four
executable tests (2 positive, 2 negative) and 2 independent eval cases.

### E.2 Rejected / deferred

| Candidate | Decision | Reason |
|---|---|---|
| Solidity `block.timestamp %` randomness | **Rejected** | Near-duplicate of DPK-SAST-770 (same signal, different operator spelling) |
| 50 further breadth candidates | **Deferred, not authored** | The probe list (getenv/setenv/sqlite3_open/ssl_certificate/limit_except/x-frame-options/sudoers/setcap/apt-key/proguard/onPageFinished/shouldOverrideUrlLoading/webChromeClient/redis-cli/mongod/yaml.parse) was re-checked: 12 are already covered by existing rules or config packs, the rest are either unreachable in any analysed family, untestable with a stable line, or generic enough to be near-duplicates. Authoring them would inflate counts without detection value. |

### E.3 Duplicate analysis

* Signal keys (`re:<sorted languages>::<pattern>::<flags>`) are unique across the corpus;
  `generate-assets` reported `quarantined: []` and `removed: 0`.
* `dedup-report`: 100 advisory seed files → 84 items, 9 multi-file tuples, **0 conflicting
  tuples** (advisory domain only; no rule duplication signal).
* `validate-packs`: 1,122 files, 0 errors. `test-packs`: **4,642/4,642**.
* `originality-report --check`: exit 0 — 0 rule clones, 0 rules without a pattern; 1 advisory
  rule-description near-match (DPK-SAST-038 ↔ 049, pre-existing) and 8 repeated-remediation
  pairs flagged for editorial polish (several involve rules added in the recent 803–961
  generation wave, including 931/933/958). These are identical *advice sentences* for the same capability in
  different languages, not duplicated detectors; the detector signals differ and the review
  is recorded, not hidden.

### E.4 Residual breadth gap

**950 / 1,000; shortfall 50.** This is an objective gap, not a quota to be filled. It is
carried as PARTIAL in GAP-AEGIS-01 and in §M/§O. Language reachability of the new rules:
13 of the 31 rules produced by the current generation wave (930–961) are fully reachable in the App catalog; 18 target
families the catalog lists as `UNSUPPORTED` or omits (haskell, zig, v, cobol, fortran, nginx,
postgres, apache, gradle, nim, vba, jinja, html).

---

## F. Evaluation coverage (Pump C)

### F.1 Method (explicit)

* **Rule coverage numerator:** distinct `DPK-SAST-###` ids appearing in
  `expected.detections[]` of at least one ASSESSED case. **Denominator:** active SAST rule
  files (950). A case is counted for a rule only if the evaluator actually executes it and
  the expectation is met; hand-authored PASS records are not used.
* **Case coverage** is reported separately: 1,046 cases over 1,044 rules is *not* the same
  claim as 875/950 rule coverage.
* **Negative coverage numerator:** rules named in `expected.forbiddenDetections[]` of an
  ASSESSED `no-issue` case. **Denominator:** active SAST rules.
* **Precision** = TP / (TP + FP); **recall** = TP / (TP + FN), restricted to the assessed
  synthetic population. Recall 1.0 is not a universal detection claim.

### F.2 Verified metrics

| Metric | Value | Numerals |
|---|---|---|
| Cases total | **1,046** | files in `data/eval-cases` |
| Assessed | **1,035** | 1,046 − 11 |
| UNASSESSED (never counted as pass) | **11** | EVAL-CMD-023/024/025 · EVAL-SAST-004/007/014/015/016 · EVAL-SEC-111 · EVAL-SQL-027/028 |
| True positives | **1,067** | met expectations |
| False positives | **1** | EVAL-SAST-008 (DPK-SAST-283) — preserved, not relabelled |
| False negatives | **0** | — |
| Precision | **0.9991** | 1,067 / 1,068 |
| Recall (assessed synthetic) | **1.0** | 1,067 / 1,067 |
| Distinct rules exercised | **1,044** | SAST 875 · secrets 97 · DAST 72 |
| SAST rule coverage | **92.1 %** | 875 / 950 |
| All-domain rule coverage | **93.3 %** | 1,044 / 1,119 |
| Negative-control cases | **285** | `groundTruth.class = no-issue` |
| SAST rules with an explicit forbidden-detection pair | **162** | subset of the 875 |
| Negative-only SAST rules | **0** | every negative rule also has a positive |
| Variant mix | 729 positive · 277 negative · 21 boundary · 10 near-miss · 9 mutation | Σ = 1,046 |

### F.3 Per-rule distribution

| Cases naming the rule | Rules |
|---|---|
| 1 | 1,030 |
| 2 | 11 |
| 3 | 1 |
| 4 | 1 |
| 8 | 1 |

The long tail is one positive case per rule by design; rules with 8 cases are the
high-value traps (context/precision families). Breadth is therefore real but shallow:
a single synthetic line per rule does not prove detection across frameworks or languages.
That limitation is carried into §M.

### F.4 Uncovered rules (75) — prioritised

| Severity | Rules |
|---|---|
| HIGH | 45 |
| MEDIUM | 30 |
| LOW | 0 |

| Category | Uncovered | Category | Uncovered |
|---|---|---|---|
| code-injection | 12 | permissions | 3 |
| cross-site-scripting | 8 | path-traversal | 3 |
| sql-injection | 7 | cleartext-transmission | 3 |
| unsafe-deserialization | 5 | deserialization | 2 |
| command-injection | 4 | weak-cryptography | 2 |
| secure-configuration | 4 | sensitive-logging | 2 |
| transport-security | 4 | server-side-request-forgery | 2 |
| ci-security | 3 | access-control | 2 |
| denial-of-service | 2 | memory-safety · csrf-protection · mass-assignment · hardcoded-credential · template-injection · container-security · xxe | 1 each |

### F.5 Identifier headroom (blocking full closure)

`EVAL-SAST-###` is capped at 999; the next free id is **854**, leaving **146** slots. Covering
75 rules with one positive + one explicit negative each needs ≈150 ids. Full closure therefore
requires either (a) an approved wider id scheme, or (b) a design where one negative case
declares forbidden detections for several rules. Option (b) is technically possible today but
was not used to claim coverage, because it would inflate case counts without independent
evidence. This is GAP-AEGIS-02's open component.

---

## G. SCA contract hardening (Pump D)

No new engine, no parallel matcher, no real data. Work stayed inside
`scripts/sca-engine.mjs`, `scripts/range.mjs`, `scripts/test-sca-fixtures.mjs` and
`data/sca-fixtures/`.

| Change | Detail |
|---|---|
| New corpus | `data/sca-fixtures/collisions.json` — npm `shared-name` 1.0.0 (direct; requires pypi `shared-name ==1.0.0`), npm `shared-name` 2.0.0, pypi `shared-name` 1.0.0 |
| Assertions | 8 new expectations in `test-sca-fixtures.mjs` §5e |
| Behaviour proven | distinct graph nodes per `ecosystem:name`; the cross-ecosystem edge keeps its declared ecosystem; range conflict reported as `npm:shared-name [1.0.0, 2.0.0]`; no cross-ecosystem cycle is invented; `shared` resolves to `npm-shared` under npm and `pypi-shared` under pypi |
| Alias table | 10 synthetic rows (adds `shared` → `npm-shared` / `pypi-shared`); ambiguous aliases stay unresolved and fail closed |
| Suite result | `sca-fixtures: 168 passed, 0 failed` across 8 corpora |
| Capability surface | `coverage-report`: 26 SCA capabilities / 206 assertions, 0 failed — adds `ecosystem-collision` and `alias-ecosystem-scope` |
| Unchanged | `packs/sca/` remains empty (0 active packs); 84 GHSA-derived seed items, `verifiedProductionCount` 0; no network access |

Contract boundaries kept: identity ≠ vulnerability identity; malformed/conflicting/incomplete
input is rejected per schema; unknown input never fabricates a match; graph output is frozen
and deterministically sorted; identical edges collapse, distinct versions/scopes/provenance do
not.

---

## H. Provenance and rights (Pump E)

| Check | Result |
|---|---|
| Eval provenance | 1,046 / 1,046 `original-authored`; 0 production-authorised records |
| Synthetic labelling | every case `synthetic: true`, `testOnly: true`; excluded from production intelligence counts |
| Production counts | `docs/CORPUS_TARGETS.json` → **verifiedProductionCount 0** in all 17 categories |
| CWE references | 63 entries, `cweVersion` 4.20; **DPK-SAST-901 → CWE-338** and **DPK-SAST-907 → CWE-843** both resolve to existing knowledge files; 0 unresolved refs; all 16 Main-App `DG-*` CWE ids resolve |
| Advisory seeds | 100 files → 84 unique items; validated-only, `BLOCKED_LICENSE_REVIEW`; 0 production |
| Legacy records | 40 patterns without record files; 0 rules without a pattern; D-13 inactive, unchanged |
| Licence | no `LICENSE`; no redistribution right inferred from public URLs; no legal grant manufactured |
| Third-party facts | none imported this pump; MITRE CWE references remain link-pinned acknowledgements, not redistributed text |

---

## I. Shared-core / UserType integrity (Pump F)

* One intelligence core: SAST, Secrets, DAST, SCA, findings, remediation, reports and eval all
  live in the same pack/knowledge/eval tree; no per-UserType engine, pattern set or rule copy
  was created.
* UserType remains presentation only. `validate-audiences` PASS (1,130 files) and
  `audience-tests` 3,401/3,401; the four audiences (DEVELOPER / STUDENT /
  SECURITY_PROFESSIONAL / PENTESTER) read the same 1,119 remediation entries and 63 CWE ids.
* FREE/PRO entitlement language stays in the Main App; no entitlement logic was added here.
* Main App compatibility evidence remains read-only and unchanged (`c32c797`). No loader,
  adapter or runtime consumption is claimed — the packs are still unreachable at runtime
  (GAP-AEGIS-06).

---

## J. Regression verification (Pump G)

Commands were run in small batches with diffs reviewed between them. No test was skipped,
weakened or deleted; the only edits to test files were **pin values** that had drifted from
the tree (919→950, 1,088→1,119, 1,048→1,079, 374→1,067), each confirmed against a
recomputation before editing.

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `node scripts/generate-assets.mjs` | 0 | written 4,391 · removed 0 · quarantined `[]` |
| 2 | `node scripts/validate-packs.mjs` | 0 | PASS (1,122 files, 0 errors) |
| 3 | `node scripts/validate-assets.mjs` | 0 | PASS (2,198 files, 0 errors) |
| 4 | `node scripts/validate-audiences.mjs` | 0 | PASS (1,130 files, 0 errors) |
| 5 | `node scripts/validate-cwe.mjs` | 0 | PASS (63 files, 0 errors) |
| 6 | `node scripts/test-packs.mjs` | 0 | 4,642 / 4,642 |
| 7 | `node scripts/test-sca-fixtures.mjs` | 0 | 168 passed, 0 failed |
| 8 | `node scripts/test-sca-engine.mjs` | 0 | 38 passed, 0 failed |
| 9 | `node scripts/run-eval.mjs` | 0 | 1,046 cases · TP 1,067 · FP 1 · FN 0 · 11 UNASSESSED |
| 10 | `node scripts/test-eval.mjs` | 0 | 41 passed, 0 failed |
| 11 | `node scripts/test-doc-drift.mjs` | 0 | 119 passed, 0 failed |
| 12 | `node scripts/test-current-state.mjs` | 0 | 153 passed, 0 failed |
| 13 | `node scripts/test-consistency.mjs` | 0 | 222 / 222 |
| 14 | `node scripts/coverage-report.mjs --check` | 0 | PASS (26 SCA capabilities / 206 assertions) |
| 15 | `node scripts/inventory.mjs --check` | 0 | matches the tree |
| 16 | `node scripts/originality-report.mjs --check` | 0 | PASS (advisory review lines listed in §E.3) |
| 17 | `node scripts/gap-matrix.mjs` | 0 | SAST active 950 · evaluated 875 · remaining-to-1000 50 |
| 18 | `node scripts/manifest.mjs --scope all` | 0 | manifest written, no errors |
| 19 | `npm test` | **0** | **19,230 assertions**, 18 suites (see below) |

`npm test` suites: core 600 · packs 4,642 · audiences 3,401 · assets 8,844 · consistency 222 ·
rehearsal 78 · importers 49 · agent-policy 91 · agent-workflows 57 · finding-evidence 31 ·
secret-candidates 35 · sca-engine 38 · sca-fixtures 168 · eval 41 · doc-drift 119 ·
current-state 153 · capability-coverage 656 · determinism 5.

**Failures met and fixed during the pump (recorded, not hidden):** the first full run after
batch E failed on stale count pins (7 consistency assertions), then `test-doc-drift` failed
16 assertions across gap-note/capability/coverage/remediation docs. Every failure was a
number that no longer matched the tree. Fixes were applied to the source of truth
(docs) and to the pins (tests), each after recomputation; no assertion was loosened.

---

## K. Inventory and generated-artifact consistency

| Artifact | State |
|---|---|
| `docs/CURRENT_INVENTORY.json` | regenerated; `inventory --check` matches |
| `docs/COVERAGE_MAP.json` | SAST 950 rules, 950 patterns (one per rule), 115 language tags, 11 universal |
| `docs/CAPABILITY_COVERAGE_MATRIX.json` | asset counts 950 / 97 / 72 / 1,119 / 1,079 / 1,119; 26 SCA capabilities |
| `docs/CAPABILITY_COVERAGE.md` | re-rendered (`render-capability-coverage --write`) |
| `docs/CORPUS_TARGETS.json` | sast-rule 950, remediation 1,119, **totals 2,412**, production 0 |
| `docs/REQUIREMENTS_MATRIX.json` | packsSast 950 · patterns 1,119 · remediation 1,119 · records 1,079 |
| `docs/PACKS.md` | reachability fully 671 / partial 29 / unreachable 239 / no-lang 11; 115 ids; sum 950 |
| `README.md`, `docs/AUDIENCES.md`, `docs/ASSET_METHODOLOGY.md` (27 retired, incl. 960), `docs/CORPUS_GAP_REPORT.md`, `docs/CAPABILITY_GAP_MATRIX.md`, `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md`, `docs/SOURCE_RELEASE_GATE.md`, `DROBON_REMAINING_WORK.csv` | refreshed to the verified counts |
| Historical reports | untouched (AEGIS, 1000×, additive, completion audit, owner packet) |

`test-consistency` 222/222, `test-doc-drift` 119/119 and `test-current-state` 153/153 enforce
these numbers, so the refresh is machine-checked rather than asserted.

---

## L. Security impact

* **New detection surface:** Android WebView hardening (remote debugging, world-readable
  files), TLS trust bypass in Swift, CSP inline-script allowance, Jinja `|safe`, nginx WebDAV
  and cipher floods, Apache protocol downgrade, Gradle release signing/minification, SSRF in
  Java/C#, path traversal in `send_file`, shell execution in Nim/VBA.
* **False-positive posture:** each rule has two negative executable tests (a safe statement
  and a verified-comment variant) plus an independent negative eval case where the id budget
  allows. The known FP rate on the assessed population is 1 documented case (0.09 % of TPs).
* **No runtime enforcement claim:** lexical rules are review prompts, not proof of
  exploitability; `limitation` is mandatory on every rule.
* **No new attack surface in tooling:** SCA engine performs no network I/O; fixtures are
  synthetic and frozen; no credentials or secret values are stored.
* **Residual detection risk:** 75 rules have no independent eval, so their precision beyond
  their two built-in negative tests is unmeasured; 239 rules cannot reach the App engine at
  all under the current catalog.

---

## M. Residual risks and blockers

| ID | Risk | Type | Owner | Status |
|---|---|---|---|---|
| BLK-001 | No LICENSE → no redistribution right | Legal | Owner/legal | BLOCKED |
| GATE-1…4 | No rights-cleared advisory source | Rights | Owner | BLOCKED |
| GAP-AEGIS-03 | SCA rule packs absent (proposal only) | Schema/owner | Owner | BLOCKED |
| GAP-AEGIS-06 | App loader absent; 239 rules unreachable | External workstream | App owner | BLOCKED |
| GAP-AEGIS-07 | 11 UNASSESSED cases | Editorial | Reviewer/owner | BLOCKED |
| GAP-AEGIS-08 | 40 legacy patterns without records; D-13 | Owner | Owner | BLOCKED |
| GAP-AEGIS-09 | DAST vocabulary closed at 7 check types | Schema | Owner | BLOCKED |
| GAP-AEGIS-02 | 75 SAST rules uncovered; id ceiling 146 vs ≈150 needed | Engineering + schema | Dataset owner | PARTIAL |
| GAP-AEGIS-01 | SAST 950/1,000 (50 short) | Editorial/capability | Dataset owner | PARTIAL |
| NEW-01 | Repeated remediation prose across 8 rule pairs | Editorial | Dataset owner | OPEN (advisory, `originality --check` green) |
| NEW-02 | Eval breadth is one synthetic line per rule for 1,030 rules | Quality | Dataset owner | OPEN (documented limitation, no metric inflation) |

---

## N. Release decision

**NO-GO.**

| Gate | Result |
|---|---|
| Executable suite green | PASS (19,230 assertions, exit 0) |
| Schemas / ids / duplicate signals | PASS |
| Provenance / originality / CWE resolution | PASS (advisory review lines recorded) |
| Production intelligence | BLOCKED (0 authorised items, by design) |
| Licence / redistribution | BLOCKED (BLK-001) |
| Owner decisions (SCA schema, D-13, eval id scheme) | BLOCKED |
| App integration | BLOCKED (no loader; unreachable packs) |
| Target completeness (SAST 1,000) | NOT MET (950) |

Green tests are necessary, not sufficient. Nothing here authorises release, production
promotion, redistribution, or an App-integration claim.

---

## O. Next pump — exact actions

1. **Close the 75-rule eval gap** in priority order (12 code-injection, 8 XSS, 7 SQLi,
   5 unsafe-deserialization, then HIGH transport/crypto). Author fixtures with context lines
   and safe twins; run them through `run-eval`, never as static text checks.
2. **Resolve the id ceiling** (GAP-AEGIS-02): ask the owner to approve `EVAL-SAST-####` or a
   shared-negative design before authoring ≈150 cases. Do not recycle retired ids.
3. **SAST remainder (50):** re-probe only capability areas with no representative rule
   (e.g. framework-specific sinks in analysed families); reject anything that shares a signal
   key with an existing rule. If none survive, keep the shortfall documented.
4. **Editorial:** differentiate the 8 repeated remediation sentences (847/849, 896/910,
   889/913, 900/923, 896/931, 889/933, 948/954, 896/958) so the originality signal reflects
   distinct advice.
5. **SCA:** hold for the owner decision on `SCA_RULE_SCHEMA_PROPOSAL.md`; if approved, build
   the loader against the existing contract — do not fork the engine.
6. **Keep blocked gaps blocked** (licence, advisories, App loader, 11 UNASSESSED, D-13,
   DAST vocabulary) and re-verify them each pump with fresh evidence.
