# DROBON AEGIS — DAST Dataset Full Intelligence Build & Master Completion Pump

**Date:** 2026-10-19
**Repository:** `mdraselislam0101-design/Drobon-Dataset`
**Branch:** `arena/a4caaeb8-drobon-dataset`
**Baseline and final commit:** `ed599c654e972cf517331bb504d65f3e8c2dbcf1`
**Main App:** read-only; nothing in `mdraselislam0101-design/Drobon` was modified or bundled.
**Dataset publication verdict:** **NO-GO** (§11).
**Main App publication readiness:** **NOT VERIFIED** — the App still has no Dataset consumer (§12).

This is one cumulative report. No earlier report was edited, moved, renamed or deleted. It
supersedes none of them; it records this pump's work on top of
`docs/DAST_ORIGINAL_INTELLIGENCE_EXPANSION_MASTER_PUMP_2026-10-19.md` and the DAST reports before it.

---

## 1. Starting state (verified, not assumed)

| Point | Value |
|---|---|
| Repository root | `/home/user/Drobon-Dataset` |
| Branch / HEAD | `arena/a4caaeb8-drobon-dataset` / `ed599c654e972cf517331bb504d65f3e8c2dbcf1` |
| Initial `git status` | 2,392 modified, 2,003 untracked (`-uall`) |
| Final `git status` | 2,392 modified, 2,030 untracked (`-uall`) |
| Working tree | preserved; no reset, clean, checkout, restore, delete, commit, push, tag or release |

Baseline reproduced before any edit:

| Check | Result |
|---|---|
| `npm test` | EXIT 0, 19,668 assertions |
| `node scripts/run-eval.mjs` | 1,251 cases, 1,240 assessed, 11 UNASSESSED, TP 1,164 / FP 1 / FN 0, only FAIL `EVAL-SAST-008` |
| DAST subset | 91 rules, TP 102, FP 0, FN 0 |
| `validate-packs` / `validate-assets` | 1,141 / 2,276 files, 0 errors |
| CSP / cookie gates | 3,720/3,720 · 1,968/1,968 |
| dedup / originality / determinism | 0 conflicts · 0 orphans · 5/5 |

## 2. Requirement-to-asset matrix

The matrix was derived from the actual tree, the closed check-type vocabulary, the 91 pre-existing
DAST rules and the product surface described in the capability matrix — not from a target count.

| Domain | Required knowledge | Assets after this pump | Status |
|---|---|---|---|
| **A. HTTP protocol / response semantics** | status classes, redirect targets, scheme context, header normalization, duplicate/empty values | 7 check types, `normalizeHeaders` (OWS trim, empty⇒missing), 100 (plaintext redirect), 001, 050, 056, 085, 094 | **Present but incomplete** — redirect *chains* and request/response context need OD-4 |
| **B. Browser security headers** | CSP grammar + fallback + duplicates; HSTS directives; XFO/COOP/COEP/CORP; Permissions/Referrer policy | CSP: 11 rules (021/022/061/070/075/086/092/093/095/098/099) driven by `scripts/lib/csp.mjs` + differential gate; HSTS 003/016/023/024/049; COOP/COEP/CORP 012/013/014/046/047/076; policies 009/017/068/077 | **Implemented and verified**, with three pinned limitations (§6) |
| **C. Cookies / session controls** | attribute tokenization, quoting, duplicates, flag values, discard and refusal | `scripts/lib/set-cookie.mjs`; 004/006/008/071 + storage predicate + cross-rule suite | **Implemented and verified**; prefix/domain/lifetime need OD-5 |
| **D. CORS** | origin matching, wildcards, credentials, methods, headers, exposed headers | 011 (origin `*`), 058 (null), 078 (methods `*`), 084 (expose `*`), **097 (allow-headers `*`)** | **Implemented and verified**; credentialed-origin interaction needs OD-3 |
| **E. Auth / session observations** | challenge schemes, cookie properties, redirect boundaries | 096 (Basic over http), 004/006/008/071, 100 (downgrade) | **Present but incomplete** — no authenticated testing by design |
| **F. Transport security** | HTTPS context, HSTS, downgrade | 001, 016, 023, 024, 049, 096, 100 | **Present but incomplete** — no TLS/certificate evidence exists in the scanner |
| **G. Browser-executable / injection signals** | reflection and context | 19 body rules cover disclosures, not reflection | **Present but incomplete** — reflection needs OD-4; the Dataset does not claim exploitability |
| **H. API / content-type** | media types, charset, error leakage | 045, 074, 062, 089 | **Present but incomplete** — no API authorization claims |
| **I. Information exposure** | banners, traces, paths, debug endpoints | 19 information-disclosure + 12 debug-exposure rules | **Implemented and verified** |
| **J. Remediation / evidence** | one record + remediation per rule, evidence contract | 1,142 records, 1,142 remediation entries, 0 orphans | **Implemented and verified** (structure); per-rule human review continues |

Every DAST rule is reachable: `eval-coverage` reports **1,142/1,142 rules (100%)**, and every rule
has exactly one pattern and one record.

## 3. Track A — existing implementation

The baseline was green and no new rule-level defect was confirmed in this pass; the previously
repaired defects (CSP nonce anchoring, scheme wildcards, cookie flag semantics, refused-cookie
duplication, COOP typing, HSTS quoting, cookie titles) remain covered by their rule tests and eval
cases. Track A work in this pump was therefore limited to keeping the count pins truthful after the
build:

| File | Change |
|---|---|
| `README.md` | pack total 1,138→1,142, DAST 91→95 |
| `docs/REQUIREMENTS_MATRIX.json` | patterns / records / remediation / DAST inventory |
| `docs/CORPUS_TARGETS.json` | DAST category 91→95, pack category 1,138→1,142, validated total 2,450→2,458 |
| `docs/CORPUS_GAP_REPORT.md`, `docs/CAPABILITY_COVERAGE.md`, `docs/CAPABILITY_COVERAGE_MATRIX.json`, `docs/SCA_RULE_SCHEMA_PROPOSAL.md` | count claims |
| `docs/AUDIENCES.md`, `docs/CAPABILITY_GAP_MATRIX.md` | count tripwires and prose |
| `docs/COVERAGE_MAP.json` | DAST rule/category/check-type tallies recomputed |
| `scripts/test-doc-drift.mjs`, `scripts/test-current-state.mjs` | pins moved with the tree (not weakened: the assertions still compare against recomputed counts) |

No expectation, `groundTruth`, `forbiddenDetections` or severity was relaxed.

## 4. Track B — new original DAST intelligence (4 rules)

All four use existing check types and existing assets. None duplicates a finding that already
exists; each answers a question the corpus could not express.

| ID | Title | Check | Sev | CWE | Category |
|---|---|---|---|---|---|
| `DPK-DAST-097` | CORS allows every request header | `response-header-matches` · `Access-Control-Allow-Headers` · `^\s*\*\s*$` | LOW | CWE-942 | `cors` |
| `DPK-DAST-098` | CSP `base-uri` allows every origin | `response-header-matches` · CSP · first-declaration wildcard | MEDIUM | CWE-693 | `csp-weakness` |
| `DPK-DAST-099` | CSP `form-action` allows every origin | `response-header-matches` · CSP · first-declaration wildcard | MEDIUM | CWE-693 | `csp-weakness` |
| `DPK-DAST-100` | HTTPS response redirects to a plaintext URL | `response-header-matches` · `Location` · `^http://` · `requireScheme: https` | MEDIUM | CWE-319 | `transport-security` |

**Why each is distinct.**

* **097** — 011 reports which origins are allowed, 078 which methods, 084 which response headers are
  exposed; none reports that the preflight accepts *any request header*. The allow-list is the
  server's chance to reject a header it never expected, and a wildcard removes it.
* **098** — 059 reports `base-uri` missing. `base-uri` has **no** `default-src` fallback, so an
  explicit `base-uri *` inside an otherwise strict policy is a different fact: a base element can
  rewrite every relative URL.
* **099** — 060 reports `form-action` missing. `form-action *` is explicit permission for a form to
  post anywhere, which needs no script execution and therefore survives a strict `script-src`.
* **100** — 001 reports the observed response being http; 050, 056 and 085 report Location shape,
  host and userinfo. None sees an **https response downgrading the next hop to http**, which is
  exactly the case where the first hop's TLS buys nothing.

**Assets produced per rule:** one cell definition (question, scope, limitation, false-positive
condition), 6–8 executable observation tests (positives, near-miss negatives, out-of-scope scheme,
empty/absent header), one pattern, one record, one remediation entry, two evaluation cases. The CSP
model gained `headerHasBaseUriWildcard` and `headerHasFormActionWildcard`; both new CSP rules are in
the differential gate, so they are checked against grammar semantics and not only against their own
examples.

**Evaluation cases added:** `EVAL-DAST-152`…`159` — one positive and one negative per rule, each
declaring forbidden detections from the neighbouring rules to prove no double-reporting.

**Rejected after probing (no rule added):** `object-src *` (subsumed by 022 when `default-src` is
effective and by 075 when it is not), `Access-Control-Allow-Credentials: true` alone (no finding
without the origin value — OD-3), CSP `style-src` scheme rules (the same question as 093 under a
different directive), JSON/XML content-type rules (a media type alone is not evidence), and
`Corp: cross-origin` (correct for public assets; would be a systematic false positive).

## 5. Verification (all commands run after the final edit)

| Command | Exit | Result |
|---|---|---|
| `node scripts/test-csp-semantics.mjs` | 0 | **4,538/4,538** (67 curated, 4,400 generated rule/policy pairs, 11 CSP rules) |
| `node scripts/test-cookie-semantics.mjs` | 0 | **1,968/1,968** (22 curated, 600 generated, 325 cross-rule inputs) |
| `node scripts/test-packs.mjs` | 0 | PASS 4,750/4,750 |
| `node scripts/run-eval.mjs` | 0 | 1,259 cases, 1,248 assessed, 11 UNASSESSED, TP 1,168 / FP 1 / FN 0 |
| `npm test` | 0 | **19,728** assertions; `asset-tests` 9,154/9,154; consistency 222/222; eval 43/43; doc-drift 119/119; current-state 153/153 |
| `node scripts/validate-packs.mjs` | 0 | PASS 1,145 files, 0 errors |
| `node scripts/validate-assets.mjs` | 0 | PASS 2,284 files, 0 errors |
| `node scripts/validate-capability-coverage.mjs` | 0 | 656 passed, 0 failed |
| `node scripts/coverage-report.mjs --check` | 0 | PASS |
| `node scripts/eval-coverage-report.mjs` | 0 | **1,142/1,142 rules** (SAST 950, secrets 97, DAST 95); 1,259 cases |
| `node scripts/dedup-report.mjs` | 0 | 100 files / 84 items / 9 tuples / **0 conflicts** |
| `node scripts/originality-report.mjs --check` | 0 | rules without record 0; patterns without record 0; rules without pattern 0 |
| `node scripts/test-determinism.mjs` | 0 | 5/5; regenerated tree byte-identical, digest reproducible |
| `node scripts/inventory.mjs --check` | 0 | inventory matches the tree |

**Cross-corpus false-positive probe:** all four new rules were run against every negative
observation case in the corpus (61 cases). **0 hits.** Running all 95 rules against each new positive
fixture showed only the expected "other header missing" findings on the deliberately minimal
fixtures — not double-reports of the same fact.

**Not run:** a separate linter, formatter, type checker or build. The repository has none; the test
chain is its verification mechanism.

## 6. Before / after

| Metric | Baseline | Final |
|---|---:|---:|
| DAST rules | 91 | **95** |
| Pack rules | 1,138 | **1,142** |
| Patterns / records / remediation | 1,138 / 1,138 / 1,138 | **1,142 / 1,142 / 1,142** |
| `validate-packs` / `validate-assets` | 1,141 / 2,276 | **1,145 / 2,284** |
| Eval cases | 1,251 | **1,259** |
| Assessed / UNASSESSED | 1,240 / 11 | **1,248 / 11** |
| TP / FP / FN | 1,164 / 1 / 0 | **1,168 / 1 / 0** |
| DAST TP / FP / FN | 102 / 0 / 0 | **106 / 0 / 0** |
| CSP gate | 3,720 | **4,538** |
| Cookie gate | 1,968 | 1,968 |
| `npm test` assertions | 19,668 | **19,728** |

Definitions: TP = expected detection with matching rule id, line and evidence text; FP = a rule
firing on a declared `no-issue` case or an undeclared detection; FN = a declared detection that did
not fire with exact evidence; UNASSESSED = ground truth `UNASSESSED`, excluded from the ratios.
Counts come from `run-eval` over the current case list.

## 7. Known limitations (pinned, never claims of correctness)

1. **Multi-policy CSP** — a comma list is an intersection; a single-value regex sees the union.
   Pinned in suite E for 022/070/086/092/098/099.
2. **Keyword case** — `'UNSAFE-INLINE'` is ignored by browsers, but the check type compiles patterns
   case-insensitively. Pinned (E2).
3. **Duplicate CSP headers** — each value is tested independently; the intersection needs OD-2.
   Pinned (E3).
4. **One header value is one cookie** — folded multi-cookie values under-flag.
5. **Cookie prefixes / domain scope / lifetime** are not modelled (OD-5).
6. **`DPK-DAST-050`** still fires on same-host scheme-relative redirects (OD-1).
7. **Correlation and request/response pairs** are not simulated anywhere (OD-3, OD-4).
8. **`DPK-DAST-040`** (Expect-CT absent) fires on the hardened fixture because a modern hardened
   response should not send a deprecated header. Informational by design; excluded from the
   fixture's forbidden list on purpose.

## 8. Provenance, rights, originality, duplicates

* Every new cell, pattern, record, remediation text, test and eval fixture is DROBON-authored for
  this repository. No third-party rule pack, source file, signature catalogue, remediation wording
  or test corpus was consulted or copied.
* Technical references are public standards behaviour (CSP Level 3, Fetch/CORS, RFC 6265, RFC 6797).
  No standard text is redistributed.
* Fixtures are synthetic, `testOnly`, and excluded from intelligence counts. No advisory feed, CVE,
  KEV, EPSS, exploit data or paid API was used.
* `docs/OWNER_DECISIONS.json` is unmodified (sha256 `a359d3f5…`), closed-key validation intact;
  **no `LICENSE` file exists** and none was added.
* Duplicates: 9 multi-file tuples, **0 conflicts**; every rule has exactly one pattern and one
  record; no orphaned asset.
* An originality check is not a legal permission. The Dataset cannot be described as legally
  exclusive or third-party-free.

## 9. Owner decisions consolidated

`docs/DAST_OWNER_DECISION_PACKET_2026-10-19.md` collects all five open items in one place, each with
the blocked question, the minimum change, compatibility impact and the tests it would need:

| ID | Decision |
|---|---|
| OD-1 | `DPK-DAST-050` retire / rewrite / accept |
| OD-2 | header-list check type (`response-header-set-matches`) for CSP intersection |
| OD-3 | multi-header correlation (CORS credentials, report-only + enforcing, cache + cookies) |
| OD-4 | request/response pair mode |
| OD-5 | cookie-model check type (prefix, domain, lifetime) |

Nothing in the packet is approved, enabled, stubbed or simulated.

## 10. Remaining blockers and their exact dependency

| Blocker | Dependency |
|---|---|
| `DPK-DAST-050` false positives | owner decision OD-1 |
| CSP duplicate-header and multi-policy precision | owner decision OD-2 |
| CORS credentialed-origin, report-only, cache+cookie findings | owner decision OD-3 |
| Reflection / authenticated-exposure confirmation | owner decision OD-4 (turns passive into active) |
| Cookie prefix/domain/lifetime findings | owner decision OD-5 |
| SCA | no lawful advisory data; separate design + owner decision; not built |
| Legal redistribution | no licence; owner/legal decision |
| App integration | App has no Dataset consumer (loader gap) |
| SAST breadth | objective, not a quota; 950 rules |

## 11. Dataset publication verdict

**NO-GO.**

The DAST workstream is in a verified state: 95 rules, 1,142 complete asset triplets, both semantic
models and their differential gates green, every rule exercised by the evaluation corpus, no
duplicate or orphaned assets, deterministic regeneration. That is not permission to publish:

* no licence / no redistribution rights;
* SCA absent by design and by data restriction;
* five owner decisions open, three of which bound real detection precision;
* the Main App has no consumer for any of it;
* one preserved evaluation failure (`EVAL-SAST-008`);
* the SAST breadth objective is unmet.

## 12. Main App publication readiness

**NOT VERIFIED.** The Main App was read-only and is unchanged. It still contains no Dataset path
reference and no DAST pack loader, so Dataset-side completion does not make the App publishable.
That gate is owned by the App workstream.

## 13. Actions not performed

No commit, push, branch, PR, merge, tag, release or deployment. No history rewrite, reset, clean,
checkout, mass restore or deletion. No Main App modification or asset embedding. No real
vulnerability feed, advisory import, exploit data or paid API. No `LICENSE` file and no change to
`docs/OWNER_DECISIONS.json`. No new check type, schema change, parallel engine or duplicate
registry. No rule retired, renamed or re-scoped. No test weakened, skipped or deleted, and no
expectation relaxed to obtain a green result.
