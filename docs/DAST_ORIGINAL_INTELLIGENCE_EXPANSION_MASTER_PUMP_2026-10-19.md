# DROBON AEGIS — DAST Original Intelligence Expansion Master Pump (Iteration 3)

**Date:** 2026-10-19
**Repository:** `mdraselislam0101-design/Drobon-Dataset`
**Branch:** `arena/a4caaeb8-drobon-dataset`
**Baseline commit:** `ed599c654e972cf517331bb504d65f3e8c2dbcf1`
**Final commit:** `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (no commit, push, branch change, tag or release)
**Main App:** read-only; no file in `mdraselislam0101-design/Drobon` was modified.
**Verdict:** **NO-GO** — reasons in §11. This is a DAST workstream result, not a Dataset release decision.

This file is new. No earlier report was edited, moved, renamed or deleted. It is cumulative with
`docs/DAST_AEGIS_ORIGINAL_CAPABILITY_GAP_CLOSURE_MASTER_PUMP_2026-10-19.md` and the DAST reports
that precede it.

---

## 1. Verified repository state

| Point | Value |
|---|---|
| Repository root | `/home/user/Drobon-Dataset` |
| Branch | `arena/a4caaeb8-drobon-dataset` |
| HEAD (start and end) | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` |
| Initial `git status --porcelain` | 2,376 modified, 1,999 untracked (`-uall`) |
| Final `git status --porcelain` | 2,392 modified, 2,003 untracked (`-uall`) |
| Working tree | preserved; no reset, clean, checkout, restore or deletion was run |

All pre-existing modified and untracked files from earlier pumps were left in place. The delta is
the files listed in §6. Nothing was committed or pushed.

## 2. Baseline (reproduced before any edit)

| Check | Command | Result |
|---|---|---|
| Full suite | `npm test` | EXIT 0, 19,668 `ok -` lines |
| Evaluation | `node scripts/run-eval.mjs` | 1,248 cases, 1,237 assessed, 11 UNASSESSED, TP 1,162 / FP 1 / FN 0; only FAIL `EVAL-SAST-008` |
| DAST subset | from the same report | 91 rules, TP 100, FP 0, FN 0 |
| Packs | `node scripts/validate-packs.mjs` | PASS, 1,141 files, 0 errors |
| Assets | `node scripts/validate-assets.mjs` | PASS, 2,276 files, 0 errors |
| Coverage | `node scripts/coverage-report.mjs --check` | PASS |
| Eval coverage | `node scripts/eval-coverage-report.mjs` | 1,138/1,138 rules |
| Duplicates | `node scripts/dedup-report.mjs` | 100 files / 84 items / 9 tuples / 0 conflicts |
| Originality | `node scripts/originality-report.mjs --check` | rules/patterns without record 0 |
| Determinism | `node scripts/test-determinism.mjs` | 5/5, digest at baseline `6799a8fa…` |
| CSP gate | `node scripts/test-csp-semantics.mjs` | 3,706/3,706 |
| Cookie gate | `node scripts/test-cookie-semantics.mjs` | 681/681 |

The previous report described this state correctly. It was re-established from the tree, not
assumed.

## 3. What the audit found

The audit read `scripts/lib/csp.mjs`, `scripts/lib/set-cookie.mjs`, both semantic gates, the
evaluator (`evalDastCheck`), all 91 DAST rule files, the generator, the validators and the
evaluation corpus, and probed behaviour with the real evaluator before changing anything.

### 3.1 CSP defects

| # | Defect | Probe (before) | Standard | Disposition |
|---|---|---|---|---|
| C1 | Nonce/hash suppression used a substring test, so a host containing `nonce-` neutralised `'unsafe-inline'` | `script-src https://nonce-cdn.example 'unsafe-inline'` → rule **false** (not reported) | CSP3: only a quoted `'nonce-…'`/`'sha…-…'` source expression neutralises `'unsafe-inline'` | **Repaired** |
| C2 | The wildcard rules only matched a standalone `*`, so a scheme-scoped wildcard host was missed | `default-src https://*` → **false** for 022/070/086/092 | `https://*` is a host-source whose host is the wildcard: every HTTPS origin | **Repaired** |
| C3 | Keyword matching is case-insensitive, so `'UNSAFE-INLINE'` is read as the keyword | rule true, oracle true | Keywords are case-sensitive; the token grants nothing | **Pinned limitation** (see §5) |
| C4 | Duplicate `Content-Security-Policy` headers are an intersection in browsers, but the evaluator tests each value independently | wildcard in one of two headers → rule true | Intersection of all policies | **Pinned limitation** (needs a header-list check type; owner decision) |
| C5 | Multi-policy comma list cannot be expressed by a single-value regex | already pinned in suite E | Intersection of all policies | Kept as a pinned limitation |

### 3.2 Set-Cookie defects

| # | Defect | Probe (before) | Standard | Disposition |
|---|---|---|---|---|
| K1 | `DPK-DAST-071` required `secure` to be followed by `;` or end of value, so `Secure=0` did not count | `id=1; SameSite=None; Secure=0` → 071 **true** (reported) | RFC 6265 §5.3: flag attributes ignore their value | **Repaired** |
| K2 | The flag rules reported a cookie that browsers refuse | `id=1; SameSite=None` → 004, 006 and 071 all fired (three findings for one cookie) | SameSite=None requires Secure; the cookie is not stored | **Repaired** — storage decision added; 071 owns the finding |
| K3 | One header value is one cookie; a folded multi-cookie value under-flags | parser test | RFC 6265 forbids folding | Kept as a documented limitation |
| K4 | Cookie-name token validity and prefix rules (`__Secure-`, `__Host-`) are not modelled | model test | Browser policy beyond header syntax | **Not modelled**, stated on the rules; no rule claims them |

### 3.3 Rule and asset quality

| Finding | Evidence | Disposition |
|---|---|---|
| Titles `DPK-DAST-039/-041/-042/-043` read "Missing X header response header" | rule files | **Repaired** (cell names held a redundant "header") |
| The hardened-response fixture (`EVAL-DAST-002`) left 8 rules firing because the response lacked seven headers a hardened site would send | probe across all 91 rules | **Strengthened**: headers added, 7 more forbidden detections; only the intentionally informational `Expect-CT` rule still fires on it |
| No duplicate trigger pairs among the cookie rules after K2 | new cross-rule suite, 325 inputs | Asserted, not assumed |

### 3.4 Candidate capabilities investigated and rejected

The brief allows investigation, not padding. Each candidate below was checked against the existing
corpus with the real evaluator before being rejected.

| Candidate | Why it was considered | Why it was not added |
|---|---|---|
| `Cross-Origin-Resource-Policy: cross-origin` weak-value rule | 014 only reports the header missing | `cross-origin` is the correct setting for public CDN resources; without resource context the rule would be a systematic false positive |
| HSTS sent over plaintext HTTP | The directive is inert on that transport | `DPK-DAST-001` already reports the plaintext response; the extra rule would double-report and add no decision |
| `__Host-`/`__Secure-` cookie-prefix enforcement | Browser refusal is a real failure mode | Needs cookie-model semantics (name + attributes) inside a check; the closed vocabulary has no such check type, and adding one is an owner decision |
| Report-only CSP alongside an enforcing policy | 072 fires even when enforcement exists | Multi-header correlation; blocked by the same owner decision as §7 |
| `Permissions-Policy` / `Referrer-Policy` additional value rules | Not exhaustively covered | Existing rules 017/077 and 009/068 already cover missing and permissive cases; new variants would re-state the same trigger |

No rule was added in this pump. The count is unchanged at 91, and that is deliberate.

## 4. Repairs implemented

### 4.1 CSP model (`scripts/lib/csp.mjs`)

* `hasNonceOrHash` now tests `/^'(?:nonce-[^'\s]+|sha(?:256|384|512)-[^'\s]+)'$/` — a complete,
  quoted source expression. A host name that merely contains `nonce-` no longer counts.
* New `hasSchemeWildcardHost(sources)` and `hasAllOriginsWildcard(sources)`; the four wildcard
  predicates use them. `https://*.example.com` remains a scoped wildcard and is not matched.

### 4.2 CSP rules

| Rule | Change |
|---|---|
| `DPK-DAST-021` | nonce/hash lookahead anchored to a quoted source expression |
| `DPK-DAST-022`, `-070`, `-086`, `-092` | wildcard token widened to `*`, `https://*`, `http://*`, `ws://*`, `wss://*` |

New tests in the rule files: `script-src https://nonce-cdn.example 'unsafe-inline'` → true;
`default-src https://*` / `http://*` / `script-src https://*` / `connect-src https://*` /
`connect-src wss://*` / `frame-ancestors https://*` → true; the scoped `https://*.example.com`
variants → false.

### 4.3 Set-Cookie model (`scripts/lib/set-cookie.mjs`)

* `cookieStorageRejection(raw)` returns `discarded:<reason>` or `samesite-none-without-secure`, or
  null.
* `cookieWillBeStored(raw)` exposes the decision. The evaluator now uses it instead of a
  discard-only test.

### 4.4 Cookie rules

| Rule / artefact | Change |
|---|---|
| `DPK-DAST-004`, `-006`, `-008` | limitations rewritten; test row for a refused `SameSite=None` cookie (`match: false`); 004/006 also gained `SameSite=None; Secure` near-miss rows |
| `DPK-DAST-071` | pattern rewritten to an attribute-name boundary `secure(?=[\s;=]\|$)`, so `Secure=0` counts; three new tests; limitation and remediation rewritten |

The `DPK-DAST-071` rewrite first failed the generator's ReDoS lint (a nullable group containing
`[^;]*`), was rewritten without a nested quantifier, and now lints clean (`lintRedos → null`).

### 4.5 Rule text

`DPK-DAST-039/-041/-042/-043`: the cell `name` no longer repeats the word "header"; titles and
descriptions now read "Missing NEL response header" / "The response carries no NEL header."

## 5. Differential and robustness testing

### 5.1 CSP gate — `node scripts/test-csp-semantics.mjs` → **PASS 3,720/3,720**

| Suite | Content | Assertions |
|---|---|---|
| A + B | parser and predicate unit tests (combined) | 47 |
| C | curated rule-vs-oracle rows (53, including the nonce-lookalike host and the scheme wildcards) | 53 |
| D | generated rule/policy pairs, LCG seed `0x5eed1234`, 400 policies × 9 rules | 3,600 |
| E1 | multi-policy intersection limitation (4 policies × 2) | 8 |
| E2 | keyword-case limitation pin | 2 |
| E3 | duplicate-header intersection limitation pin | 1 |
| Absent-header rows | every CSP rule (9) on a missing header | 9 |
| **Total** | | **3,720** |

The generated source pool now contains `https://*`, `http://*`, `wss://*` and a `nonce-` lookalike
host, so the two repairs are exercised by generated policies as well as curated rows. The generator
is seeded, has no clock and no I/O beyond the rule files; repeated runs produce identical output.

### 5.2 Cookie gate — `node scripts/test-cookie-semantics.mjs` → **PASS 2,104/2,104**

| Suite | Content | Assertions |
|---|---|---|
| A | parser units (identity, last-wins, quoting, discard) | 27 |
| B | flag predicates | 16 |
| C | curated rule rows (22) plus the "shipped in the rule file" check (22) | 44 |
| D | generated rule pairs (300) plus round-trip (300), LCG `0x5e7c00c1` | 600 |
| E | pinned limitations | 4 |
| F | 325 cross-rule inputs × 3 assertions (no duplicate, 071 vs model, storage predicate) | 975 |
| **Total** | | **2,104** |

Suite D's oracle now applies the two storage rules first (discarded header, refused cookie), so the
generated corpus tests the new decision rather than assuming the old behaviour. Suite F fails the
build if `DPK-DAST-071` ever co-fires with `004`, `006` or `008`, and separately checks that 071
reports exactly the cookies the model calls refused — that is how K1 was found.

### 5.3 Robustness

* Malformed input never throws: absent headers, non-string values, empty cookie strings, control
  characters, unparseable URLs and empty policies are all exercised by the existing suites.
* Generator regeneration is deterministic and validated against the checked-in tree.

## 6. Files changed in this pump

| File | Purpose |
|---|---|
| `scripts/lib/csp.mjs` | anchored nonce/hash detection; all-origins wildcard incl. scheme-scoped host wildcards |
| `scripts/lib/set-cookie.mjs` | storage decision (`cookieStorageRejection`, `cookieWillBeStored`) |
| `scripts/validate-packs.mjs` | cookie branch consults the storage decision |
| `scripts/test-csp-semantics.mjs` | 11 new curated rows, wider generated pool, 3 limitation pins |
| `scripts/test-cookie-semantics.mjs` | storage-aware oracle, 5 new curated rows, cross-rule suite F |
| `scripts/test-eval.mjs` | TP pin 1,162 → 1,164 |
| `data/asset-cells/dast.json` | 021 nonce anchor, 022 scheme wildcard, tests |
| `data/asset-cells/dast-2.json` | 039/041/042/043 names |
| `data/asset-cells/dast-3.json`, `dast-10.json`, `dast-11.json` | 070/086/092 scheme wildcard, tests |
| `data/asset-cells/dast-4.json` | 071 attribute-boundary pattern, tests, limitation, remediation |
| `packs/dast/v1/rules/DPK-DAST-004/-006/-008.json` | hand-authored legacy rules: limitations and near-miss rows |
| `data/eval-cases/EVAL-DAST-002.json` | hardened-response fixture extended with 7 headers and 7 forbidden detections |
| `data/eval-cases/EVAL-DAST-074.json` | rationale clarified (refused-cookie ownership) |
| `data/eval-cases/EVAL-DAST-149…151.json` | nonce-lookalike positive, scheme-wildcard positive, refused-cookie negative |
| generated patterns, records and remediation | regenerated by `node scripts/generate-assets.mjs` (1,138 / 1,138 / 1,138, 0 quarantined) |
| `docs/PACKS.md` | DAST Batch 15 entry; cookie check-type row |
| `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md` | header-model status and counts |
| `docs/CURRENT_INVENTORY.json`, `docs/CAPABILITY_COVERAGE_MATRIX.md` | machine-regenerated |

No rule id was retired, renamed, repurposed or rescoped. No check type was added. No schema change.
`DPK-DAST-050` was not touched.

## 7. Blocked decisions (unchanged)

| Item | Status | What is needed |
|---|---|---|
| `DPK-DAST-050` (`^//` on `Location`) | `OWNER_DECISION_BLOCKED` | The pattern cannot express "different host" in a single-header type; retirement or rewrite changes a permanent id |
| Multi-header correlation | `OWNER_DECISION_BLOCKED` | Vocabulary entry + evaluator receiving the header list; proposals exist, approval does not |
| Request/response pairs | `OWNER_DECISION_BLOCKED` | Same decision; no request model in the schema |
| Header-list check for CSP/`report-only` intersection | `OWNER_DECISION_BLOCKED` | Same decision; pinned as limitations E3 and §3.4 |
| Cookie-prefix semantics | `OWNER_DECISION_BLOCKED` | Needs a cookie-model check type |

A proposal is not an approval. None of these was simulated with a single-header rule.

## 8. Evaluation

### 8.1 Final metrics

| Metric | Value |
|---|---|
| Cases | **1,251** (baseline 1,248) |
| Assessed | 1,240 |
| UNASSESSED | 11 (pinned, zero contribution) |
| TP / FP / FN | **1,164 / 1 / 0** (baseline 1,162 / 1 / 0) |
| FAIL | 1 — `EVAL-SAST-008`, preserved |
| DAST subset | 91/91 rules, TP 102, FP 0, FN 0 (baseline TP 100) |
| SAST subset | 942 rules referenced, TP 963, FP 1, FN 0 |
| Secrets subset | 97 rules referenced, TP 99, FP 0, FN 0 |

### 8.2 New and changed cases

| Case | Variant | Outcome | What it proves |
|---|---|---|---|
| `EVAL-DAST-149` | positive | PASS (TP 1) | a `nonce-` lookalike host does not neutralise `unsafe-inline` |
| `EVAL-DAST-150` | positive | PASS (TP 1) | `https://*` is an every-origin permission |
| `EVAL-DAST-151` | negative | PASS | flag rules stay silent on a refused `SameSite=None` cookie |
| `EVAL-DAST-074` | positive (existing) | PASS | 071 still reports the refused cookie |
| `EVAL-DAST-002` | negative (strengthened) | PASS | 20 forbidden detections on a hardened response |

`EVAL-DAST-002` still triggers `DPK-DAST-040` (Expect-CT absent). That rule is explicitly
informational about a deprecated header, it is not in the case's forbidden list, and removing the
finding would mean sending a header no modern site should send. This is recorded rather than
hidden.

### 8.3 Metric definitions

* **TP** — an expected detection whose rule id, line and declared evidence text all match.
* **FP** — a rule fires on a case whose ground truth is `no-issue`, or a detection not declared.
* **FN** — a declared detection that did not fire with exact evidence.
* **UNASSESSED** — the case has ground truth `UNASSESSED`; it is excluded from TP/FP/FN.
* Counts are produced from the current case list by `run-eval`, not carried from a report.

## 9. Verification (final)

| Command | Exit | Result |
|---|---|---|
| `node scripts/test-csp-semantics.mjs` | 0 | PASS 3,720/3,720 (53 curated, 3,600 generated) |
| `node scripts/test-cookie-semantics.mjs` | 0 | PASS 2,104/2,104 (22 curated, 600 generated, 325 cross-rule inputs) |
| `node scripts/test-packs.mjs` | 0 | PASS 4,734/4,734 |
| `node scripts/run-eval.mjs` | 0 | 1,251 / 1,240 / 11; TP 1,164 / FP 1 / FN 0; 1 FAIL |
| `npm test` | 0 | 19,668 `ok -` lines; `asset-tests` 9,122/9,122; eval 43/43; doc-drift 119/119; current-state 153/153 |
| `node scripts/validate-packs.mjs` | 0 | PASS 1,141 files, 0 errors |
| `node scripts/validate-assets.mjs` | 0 | PASS 2,276 files, 0 errors |
| `node scripts/coverage-report.mjs --check` | 0 | PASS |
| `node scripts/eval-coverage-report.mjs` | 0 | 1,138/1,138 (SAST 950, secrets 97, DAST 91) |
| `node scripts/dedup-report.mjs` | 0 | 100 files / 84 items / 9 tuples / **0 conflicts** |
| `node scripts/originality-report.mjs --check` | 0 | rules/patterns without record 0 |
| `node scripts/test-determinism.mjs` | 0 | 5/5; regenerated tree byte-identical and digest reproducible across fresh copies (the digest value changes whenever any file changes, so it is not quoted as a fixture) |
| `node scripts/inventory.mjs --check` | 0 | inventory matches the tree |

Not run, because the repository has no such tooling: a separate linter, formatter, type checker and
build. The test chain is the repository's own verification mechanism. Nothing is claimed beyond it.

## 10. Provenance, rights and duplicate audit

* All detection logic, patterns, predicates, tests, fixtures and remediation text added or changed
  here are DROBON-authored. No third-party code, rule text, catalogue or corpus was consulted or
  copied.
* Behavioural references are public standards (CSP Level 3, RFC 6265 §5.2/§5.3). No standard text
  is redistributed.
* Fixtures remain synthetic and `testOnly`; no real vulnerability intelligence, advisory feed,
  exploit data or paid API was used.
* **No `LICENSE` file exists.** `docs/OWNER_DECISIONS.json` is unmodified and still valid
  (sha256 `a359d3f5…`). Technical originality is not legal permission; the Dataset must not be
  described as legally exclusive.
* Duplicate audit: 9 multi-file tuples, 0 conflicts; every rule has exactly one pattern and one
  record; no asset was orphaned by the edits.

## 11. Verdict

**NO-GO.**

DAST-specific state: all 91 rules validate, both semantic gates pass, the two repaired false
negatives and the two repaired false positives are covered by rule tests, curated gate rows,
generated pairs and evaluation cases, and the evaluation corpus is internally consistent at
1,164 TP / 1 FP / 0 FN with `EVAL-SAST-008` preserved.

The release decision does not follow from that:

* no `LICENSE`; redistribution rights remain unresolved;
* SCA has no packs and no lawful advisory data — not built, not faked;
* `DPK-DAST-050`, multi-header correlation, request/response pairs and the header-list check remain
  owner decisions;
* the Main App still contains no Dataset consumer, so integration is unverified;
* SAST breadth remains an objective (950 rules), not a completed gate;
* one known SAST evaluation failure remains by design.

DAST completion is not Dataset completion, and a green suite is not a GO.
