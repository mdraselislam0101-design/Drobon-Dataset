# DAST remaining-coverage forensic pump — 2026-10-20

**Scope:** Dataset repository only (`mdraselislam0101-design/Drobon-Dataset`), branch `arena/a4caaeb8-drobon-dataset`.
**Question answered:** after the capability-aligned expansion reached 252 DAST detections, what remaining coverage is genuinely reachable under the closed seven-type check contract, and is 500 reachable at all?
**Verdict:** **PARTIAL — 263 / 500 (52.6%).** 500 is assessed as **unreachable** under the closed contract without either a new check type (owner decision) or counting rules the Dataset has rejected as padding. Eleven independently justified detections were added; sixteen composed candidates were rejected before any repository write and consumed no IDs. No rule was merged, renamed, retired or deleted; one pre-existing semantic duplicate is reported for an owner decision.
**Report discipline:** this is a new dated report. `docs/DAST_CAPABILITY_ALIGNED_500_2026-10-20.md`, `docs/DAST_CAPABILITY_ALIGNED_500_TRANCHE2_3_2026-10-20.md` and all earlier reports are preserved unchanged.

---

## 1. Verified baseline and final counts

Every number below was recomputed from this checkout with the command shown; no reported value was carried forward from an earlier report.

| Measure | Baseline (start of pump) | Final (end of pump) | Recomputed by |
|---|---|---|---|
| DAST rules (`packs/dast/v1/rules`) | 252 (IDs 1…259, gaps 151/154) | **263** (IDs 1…270, gaps 151/154) | `ls packs/dast/v1/rules/*.json` → 263 |
| Pattern files | 1,299 | **1,310** | `ls knowledge/patterns/*.json` → 1,310 |
| Record files | 1,299 | **1,310** | `ls knowledge/records/*.json` → 1,310 |
| Remediation files | 1,299 | **1,310** | `ls knowledge/remediation/*.json` → 1,310 |
| Pack total (SAST+Secrets+DAST) | 1,299 (950+97+252) | **1,310** (950+97+263) | `docs/CURRENT_INVENTORY.json` |
| CWE entries | 67 | **68** (CWE-116 added for the UTF-7 rule) | `ls knowledge/cwe/*.json` → 68 |
| Evaluation cases | 1,588 (1,577 assessed, 11 UNASSESSED) | **1,610** (1,599 assessed, 11 UNASSESSED) | `docs/CURRENT_INVENTORY.json` |
| DAST observation cases | 487 | **509** (265 positive + 244 negative) | `data/eval-cases/EVAL-DAST-*.json` → 509 |
| DAST rule tests | 1,208 (542 pos / 666 neg) | **1,274** (574 pos / 700 neg) | rule files → sum of `tests` |

Baseline reconciliation: branch `arena/a4caaeb8-drobon-dataset`, HEAD `ed599c654e972cf517331bb504d65f3e8c2dbcf1`, worktree 5,464 entries (2,461 modified / 3,003 untracked), no `LICENSE`, `docs/OWNER_DECISIONS.json` untouched, `docs/CURRENT_INVENTORY.json` at dastRules 252 / packRules 1,299 / evalCases 1,588 (1,577 assessed, 11 UNASSESSED). Final worktree: 5,533 entries (2,461 modified / 3,072 untracked) — the 69 new entries are exactly 11 rules + 11 patterns + 11 records + 11 remediation + 22 evaluation cases + 1 asset-cell file + 1 CWE entry + this report.

---

## 2. Separate asset counts (never summed into one figure)

| Asset family | Count | Counting rule |
|---|---|---|
| DAST detection rules | 263 | one `(check type, target, semantic condition)` per file |
| DAST observation tests (evidence examples) | 1,274 (574 positive / 700 negative) | test objects inside rule files |
| Patterns (`knowledge/patterns`) | 1,310 | one per rule, all families |
| Records (`knowledge/records`) | 1,310 | one per rule, all families |
| Remediation (`knowledge/remediation`) | 1,310 | one per rule, all families |
| Evaluation cases (all families) | 1,610 | synthetic observation/line fixtures, `testOnly` |
| DAST evaluation cases | 509 | `data/eval-cases/EVAL-DAST-*.json` |
| CWE reference entries | 68 | own-words entries, canonical link only |

The 22 new evaluation cases are `EVAL-DAST-493…EVAL-DAST-514` (11 positive + 11 negative, cohort `dast-forensic-2026-10-20`). They are synthetic, `testOnly`, and are **not** vulnerability intelligence. Patterns, records, remediation, tests and evaluation cases are counted separately from detections and are never added to the rule figure.

---

## 3. Coverage per check type (all seven, with the residual that is genuinely left)

| Check type | Rules | New this pump | Residual coverage assessed | Why no further rules |
|---|---|---|---|---|
| `response-header-matches` | 133 | +9 | CSP (40 rules), cookies (11), CORS (15), security headers (44), response headers (7), redirect (7), transport (14) already enumerate the value-shape space of every header the App emits; the residual is mechanical per-directive variants | A further rule per directive/scheme pair would repeat one decision; three plaintext-scheme variants remain (child-src, script-src-elem, style-src-elem) and were deliberately not added — recorded here as mechanical, not capability |
| `response-body-matches` | 101 | +2 | debug/error disclosure, console fingerprints (57 debug-exposure + 62 information-disclosure), served artefacts | Product fingerprints are unbounded in number but identical in decision; ten were rejected this pump (see §4). Body rules cannot see a status code contract, a cookie, or another response |
| `missing-response-header` | 16 | 0 | Every header the App can omit already has a rule | Complete for the App's header set; adding rarer vendor headers would be volume |
| `response-header-missing-directive` | 8 | 0 | frame-ancestors, base-uri, form-action, default-src, object-src, script-src-directive family | Complete; the remaining CSP directives (`require-trusted-types-for`, `report-to`) are recommendations, not conditions the response violates |
| `cookie-missing-flag` | 3 | 0 | Secure, HttpOnly, SameSite presence | Complete. The cookie *value* contract is handled by `response-header-matches` (11 rules) |
| `http-url` | 1 | 0 | Plaintext absolute URL in the observation | One condition; splitting by context would fake a context the observation does not carry |
| `response-header-host-differs` | 1 | 0 | Location host differs from the request host | One condition. Backslash forms were composed and rejected because this rule already reports every form that resolves off-host (§4) |

Structural facts recomputed for this report (they define the ceiling):

- **105 of 263 rules carry no `check.header`** (101 `response-body-matches`, 3 `cookie-missing-flag` which use `flag`, 1 `http-url`). Keying a "body rule" tally off `!check.header` over-counts by the cookie and URL rules — the correct key is `check.type`.
- **Tests per rule**: `{3: 5, 4: 166, 5: 29, 6: 28, 7: 12, 8: 13, 9: 7, 10: 2, 11: 1}`; the five 3-test rules are `DPK-DAST-003`, `-057`, `-058`, `-063`, `-065`.
- **Six descriptions are 138–139 characters** — a threshold artefact of the 140-character authoring gate, not a defect; each states a distinct condition.
- **Sixteen remediations are under 60 characters** (`-011`, `-026`…`-038`, `-050`, `-070`). They are actionable but terse; they are pre-existing and were not rewritten in this pump because rewriting remediation text is a separate, reviewable change.

---

## 4. Candidate groups: accepted and rejected

26 candidates were composed and run through the pre-write harness before any file was written; 10 passed every gate. One more rule (`cookie-host-prefix-domain`) was authored after the gap check showed that no rule in the corpus addresses the `__Host-`/`__Secure-` prefix contract. Total written: **11**.

### 4.1 Accepted (11 rules, IDs 260–270, no gaps consumed)

| ID | Rule | Type | Sev | CWE | Independent justification |
|---|---|---|---|---|---|
| DPK-DAST-260 | Docker Compose file served | body | MEDIUM | CWE-200 | Document-shape disclosure with environment blocks; the corpus covers `.env`, `package.json`, `web.config`, kubeconfig and Terraform state, but not Compose |
| DPK-DAST-261 | WordPress `wp-config.php` served | body | MEDIUM | CWE-200 | Configuration file with database credential and salt definitions; distinct from `.env` because the evidence is the PHP definition set plus the `wp-settings.php` bootstrap |
| DPK-DAST-262 | `Content-Type` declares UTF-7 | header | MEDIUM | CWE-116 | Encoding-confusion vector; the corpus has charset-*absence* (DPK-DAST-045) but no charset-*value* rule |
| DPK-DAST-263 | `Set-Cookie` `Expires` is not an HTTP date | header | LOW | CWE-613 | Attribute-validity rule parallel to DPK-DAST-188 (`Max-Age` invalid), which had no `Expires` counterpart |
| DPK-DAST-264 | `__Host-` prefix paired with `Domain` | header | LOW | CWE-1275 | Prefix-contract violation; no rule in the corpus reads cookie name prefixes |
| DPK-DAST-265 | `SameSite=None` without `Partitioned` | header | LOW | CWE-1275 | Third-party cookie jar sharing; scoped to cookies the browser would store (`Secure` present), so it is disjoint from DPK-DAST-071 |
| DPK-DAST-266 | CSP directive declared twice | header | MEDIUM | CWE-16 | Silent loss of the second list; no duplicate-directive rule existed |
| DPK-DAST-267 | CSP `manifest-src` allows `http:` | header | LOW | CWE-319 | Completes the 197–208 plaintext-scheme series for the last loadable subresource directive it omits |
| DPK-DAST-268 | CSP `script-src` trusts `*.domain` | header | MEDIUM | CWE-693 | DPK-DAST-070's own tests treat `https://*.cdn.example` as a **negative**, so the subdomain wildcard was uncovered |
| DPK-DAST-269 | CSP nonce shorter than 16 characters | header | MEDIUM | CWE-330 | No nonce-strength rule existed (DPK-DAST-153 is about `strict-dynamic` without a nonce) |
| DPK-DAST-270 | Permissions-Policy grants a device feature to `*` | header | MEDIUM | CWE-693 | DPK-DAST-077 covers camera/microphone/geolocation only; usb/serial/hid/bluetooth/midi/nfc and similar were uncovered |

Every accepted rule carries: a positive fixture and a near-miss negative that keeps the surface, at least one further negative from a different surface, boundary tests where the contract supports them (§6), a limitation that names what the single-response model cannot see, and a two-step remediation.

### 4.2 Rejected before any repository write (16 candidates, no IDs consumed)

| Candidate | Reason for rejection |
|---|---|
| 10 management-console body fingerprints (GitLab, Gitea, Zipkin, Rundeck, Graylog, Sentry, YARN ResourceManager, Trino, Druid, Flink) | A page marker cannot distinguish an exposed console from a public product page; the decision ("this product's UI is served here") is already represented 25 times in the corpus. Adding products is regex volume, not new capability — exactly the padding this pump was required to refuse |
| `location-backslash` | Evidence subset of DPK-DAST-056. Every backslash form that resolves off-host (`/\evil.example`, `\\evil.example`, `//\evil`) is already reported by 056; the only forms 056 misses (`/\app.example`, `/%5C…`) do not resolve off-host and would be an over-claim |
| `location-empty` | A redirect that does not happen is a functional defect; no security-relevant control changes |
| `cors-allow-methods-empty` | An empty allow-list fails closed — the preflight is refused and nothing is exposed |
| `cors-expose-headers-forbidden` | The entry is inert by specification (`Set-Cookie` is never exposed to script); the evidence cannot support a security conclusion |
| `body-htaccess-served` | Rewrite-rule disclosure with no credential and no actionable consequence |
| `body-composer-json-served` | Dependency inventory only; version disclosure is already represented by DPK-DAST-239 and matching a version to an advisory needs SCA data this pack may not import |

The rejections are recorded here rather than in `data/asset-cells/quarantine.json`, which stayed empty (`{"quarantined": []}`) because no rejected candidate entered the generator.

---

## 5. Overlap and duplicate results

**Canonical gate (after the write):** `node scripts/validate-dast-overlaps.mjs` → **PASS**, `332 checks; 128 subset pairs (123 expected absence, 5 reviewed)`. The pair count is **unchanged from the baseline** — the eleven new rules introduced no evidence-subset pair. The reviewed set is still the five entries in `docs/DAST_OVERLAP_LEDGER.json`; no ledger entry was added, weakened or removed, and no rule's limitation was edited to satisfy the gate.

Pre-write differential results (computed with the real `evalDastCheck` over the candidate corpus plus all 252 existing rules):

- **0 exact check-signature duplicates.**
- **0 subset pairs touching a candidate** against the existing corpus in either direction.
- **131 same-target subset pairs** when the scan includes body rules and cookie rules (the committed gate is header-keyed and skips them, hence its 128). The three gate-invisible body pairs are unchanged and explained:
  - `DPK-DAST-004 ⊆ DPK-DAST-006` — coincidental evidence overlap: both parse the same `Set-Cookie` string for different decisions (flag presence vs attribute validity).
  - `DPK-DAST-066 ⊆ DPK-DAST-065` and `DPK-DAST-067 ⊆ DPK-DAST-065` — framework stack/error-path rules whose evidence is a subset of the generic path rule but whose conclusions are framework-specific.

**Two pairs the earlier recount flagged as "equal evidence" were reconciled:**

| Pair | Result |
|---|---|
| `DPK-DAST-010` (CSP without `frame-ancestors`) vs `DPK-DAST-060` (CSP without `form-action`) | **Distinct.** Differential test over 8 policy variants produced 4 disagreements (`frame-ancestors 'none'` alone → 060 only; `form-action 'self'` alone → 010 only). The "equal" signal was an artefact of both rules' fixtures lacking both directives |
| `DPK-DAST-106` ("sandbox can remove itself") vs `DPK-DAST-150` ("sandbox grants both allow-scripts and allow-same-origin") | **Semantically identical.** 10 sandbox variants, 0 disagreements: both fire exactly when the `sandbox` directive carries both `allow-scripts` and `allow-same-origin`. Different regex spellings, one condition |

**Proposed retirement (owner decision required, nothing changed):** retire **DPK-DAST-150** and keep DPK-DAST-106, whose limitation is the more precise of the two. IDs are permanent assets; a retirement is an owner act. Until then both rules ship and the duplicate is visible here. The existing ledger format has no `EQUIVALENT` kind, and adding one would be a gate change this pump did not make.

---

## 6. Positive, negative, boundary and benign results

- **Positive/negative per rule:** every new rule has at least two positives and two negatives; the corpus total is 574 positive / 700 negative observation tests.
- **Boundary and malformed cases added with the new rules:** nonce at 15 vs 16 characters; `Partitioned=1` (flag semantics: present, not reported); a lowercase HTTP-date `Expires` accepted under the evaluator's case-insensitive compile; `Expires=Wednesday` rejected; `manifest-src http:` inside the directive vs `http:` in another directive; a `__Host-` name appearing in a *value* rather than the name position; a CSP whose `report-uri` value contains the text `script-src`; a duplicate-directive policy where the name appears three times with distinct directives; bare `*` in `script-src` (belongs to DPK-DAST-070, must not fire); `usb=(self "https://app.example")` (allow-list, not a wildcard).
- **Contract limit found:** the observation model carries one value per header, so repeated-header observations (two `Set-Cookie` lines, duplicate `Content-Security-Policy` headers) **cannot** be represented. Tests for that case were therefore not fabricated; the limit is stated in each affected rule's limitation.
- **Case-folding limit found:** header rules compile with the `i` flag, so the `__Host-` rule cannot honour cookie-name case sensitivity. A lowercase `__host-` name is reported; this is stated in the rule's limitation rather than claimed as correct behaviour.
- **Benign-page audit:** a 10-page benign corpus (sign-in page, JSON API with complete CORS, dashboard with a full and non-duplicated CSP using a 26-character nonce and `manifest-src 'self'`, login redirect, embedded-context cookie with `Partitioned`, UTF-8 page with valid `Expires`, a documentation page that *quotes* `wp-config.php` and a Compose snippet in prose, a CSP whose `report-uri` contains `script-src`, a 404 page, an XHTML page) → **0 hits for the 11 new rules**.
- **False positive found and fixed at the root cause:** the Compose rule initially fired on the documentation page that quotes a Compose snippet. Cause: an unanchored `services:`/`image:` pair. Fix: require `services:` at a line start followed by an indented `image:` line (`(?:^|\n)services\s*:(?=[\s\S]*\n[ \t]+image\s*:)`), plus a regression test that keeps the quoted-snippet page negative. This is the only candidate defect the benign corpus exposed.
- **Honesty note:** 212 firings of *existing* rules occur on the benign corpus, overwhelmingly absence-class rules (`CSP missing`, `X-Frame-Options missing`) because those pages deliberately carry only the header family under test. Zero hits on the new rules is a fixture-level statement, **not** a production zero-false-positive proof.

---

## 7. False positives, false negatives, unassessed

| Measure | Value | Source |
|---|---|---|
| True positives | **1,336** | `run-eval` counts (was 1,325; +11 positive cases) |
| False negatives | **0** | `run-eval` counts |
| False positives | **1** | `run-eval` counts — `EVAL-SAST-008`, preserved, not suppressed |
| UNASSESSED cases | **11** | preserved; excluded from precision/recall |
| DAST cases not PASS | **0** of 509 | `run-eval` |
| New cohort `dast-forensic-2026-10-20` | 22/22 PASS | `run-eval` |
| Independent evaluation breadth | 1,310/1,310 rules (SAST 950/950, secrets 97/97, DAST 263/263) | `eval-coverage-report.mjs` |

No expectation was edited to obtain a green run. The two pin updates in `scripts/test-eval.mjs` (TP 1,325 → 1,336) and `scripts/test-doc-drift.mjs` (252 → 263, 1,299 → 1,310, CWE 67 → 68) were made **after** recomputing the figures from the tree, and each new value is reproducible by the command named in §8.

---

## 8. Commands run and measurements (actual output, final state)

| Command | Result |
|---|---|
| `node scripts/generate-assets.mjs` | EXIT 0 — written 5,195, removed 0, quarantined **0** |
| `node scripts/validate-packs.mjs packs` | PASS — 1,313 files, 0 errors |
| `node scripts/validate-assets.mjs` | PASS — 2,620 files, 0 errors |
| `node scripts/validate-cwe.mjs knowledge/cwe` | PASS — 68 files, 0 errors |
| `node scripts/validate-corpus.mjs` | PASS — 3 files, 0 errors |
| `node scripts/validate-dast-overlaps.mjs` | PASS — 332 checks; 128 subset pairs (123 expected absence, 5 reviewed) |
| `node scripts/test-packs.mjs` | PASS — 5,422/5,422 |
| `node scripts/run-eval.mjs` | EXIT 0 — 1,610 cases, 1,599 assessed, 11 UNASSESSED; TP 1,336 / FN 0 / FP 1 |
| `node scripts/eval-coverage-report.mjs` | 1,310/1,310 rules exercised (DAST 263/263); 1,610 cases |
| `node scripts/coverage-report.mjs --check` | PASS |
| `node scripts/test-consistency.mjs` | PASS — 232/232 |
| `node scripts/test-eval.mjs` | 43 passed, 0 failed |
| `node scripts/test-doc-drift.mjs` | 120 passed, 0 failed |
| `node scripts/test-current-state.mjs` | 155 passed, 0 failed |
| `node scripts/validate-capability-coverage.mjs` | 695 passed, 0 failed |
| `node scripts/inventory.mjs --write` | wrote `docs/CURRENT_INVENTORY.json` (dastRules 263, packRules 1,310, cweEntries 68, evalCases 1,610/1,599/11) |
| `node scripts/render-capability-coverage.mjs --write` | wrote `docs/CAPABILITY_COVERAGE_MATRIX.md` (33 rows) |
| `npm test` | **EXIT 0** — 22,302 `ok`, zero FAIL; `test:determinism` 5/5. The suite prints the tree digest live; the value is not embedded in this document because writing it here would change the digest it describes. The digest for the final tree is reported alongside this report in the pump summary |
| Pre-write harness (scratch, `/tmp/pump4`, not committed): structure gate / overlap gate / benign gate | 26 candidates → 11 structural problems fixed → 0 problems; 0 exact duplicates; 0 subset pairs touching a candidate; 0 benign hits |

The pre-write harness used the repository's real interfaces (`evalDastCheck`, `lintRedos` imported from `scripts/validate-packs.mjs`), not a reimplementation. Its scripts live outside the repository and are not part of the deliverable.

---

## 9. Why 500 is unreachable, and the minimum owner decision that would change that

The seven closed check types express exactly one class of question: *does this single response carry this single-surface condition?* With 263 rules the corpus already answers that question for:

- every security header the App can emit, in presence, value-shape, directive and scheme form (44 `security-headers` + 40 `csp-weakness` + 7 `response-headers` + 14 `transport-security`);
- every cookie attribute contract a single `Set-Cookie` value can violate (11 `cookie-flags`);
- every CORS header value shape (15 `cors`);
- every redirect target form the `Location` header can carry (7 `open-redirect`);
- the served-artefact and console classes that a body marker can identify (57 `debug-exposure` + 62 `information-disclosure`).

What remains is not 237 further *conditions*. It is a set of questions the contract cannot ask:

| Residual family | Why the closed contract cannot express it |
|---|---|
| Request/response correlation (reflected input, echoed headers, parameter-driven redirects) | needs two observations; the model holds one |
| Preflight CORS without preflight evidence | needs an OPTIONS exchange; a value match cannot prove a preflight was answered |
| Session-cookie model (is this cookie a session cookie?) | needs a cookie jar and a comparison across responses |
| TLS/certificate/cipher inference | the observation carries no transport metadata |
| Authenticated/stateful flows | needs credentials and sequence |
| Active injection | needs a request the Dataset may not send |
| Browser/DOM execution | needs a rendering engine |
| Response-chain semantics (redirect chains, header smuggling, duplicate-header folding) | needs ordered multiple headers/responses, which the observation cannot represent |

The 29 single-surface variants still derivable (three remaining plaintext-scheme directives, additional vendor security headers, additional product fingerprints, additional `Permissions-Policy` feature groups) would add rules without adding a decision. They were measured, not written.

**Minimum owner decision or contract change to move past ~263 with genuine value:** approve (or decline) one new check type for **multi-header / multi-response correlation** — the design proposal template and the closed-key vocabulary already exist in `docs/DAST_CHECK_TYPE_EXTENSION_PROPOSAL.md`. That single change would unlock the only residual family that carries independent security value (correlated redirects, preflight consistency, cookie-jar scoping). Two other routes exist and are **not** recommended: (a) redefining a detection to admit product fingerprints, which inflates counts without capability; (b) importing advisory data to match disclosed versions, which is SCA, is outside the DAST contract, and is prohibited before deployment.

Until an owner decision is recorded, the honest ceiling of this pack under its own contract is in the low hundreds, and this pump reached it at **263**.

---

## 10. Publication verdict (separate from technical status)

- **Technical status:** all gates green (`npm test` EXIT 0, validators PASS, overlaps PASS, determinism 5/5, benign corpus clean for the new rules).
- **Publication readiness:** **NO-GO.** There is no `LICENSE` file and no grant of redistribution rights; every asset remains `RIGHT_STATUS = NO_GRANT_ALL_RIGHTS_RESERVED` / `NOT_ELIGIBLE_NO_LICENSE`. Technical test success is not a publication permission, and this report does not claim otherwise.
- **App integration:** **NOT VERIFIED.** The Main App was not read, modified, built or consumed in this pump; no loader exists that reads `packs/dast` (GAP-007 remains open).

---

## 11. Repository, branch, HEAD, worktree

| Item | Value |
|---|---|
| Repository | `mdraselislam0101-design/Drobon-Dataset` |
| Branch | `arena/a4caaeb8-drobon-dataset` |
| HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged; no commit made) |
| Worktree at start | 5,464 entries (2,461 modified / 3,003 untracked) |
| Worktree at end | 5,533 entries (2,461 modified / 3,072 untracked) |
| New files | 69 = 11 rules + 11 patterns + 11 records + 11 remediation + 22 evaluation cases + `data/asset-cells/dast-21.json` + `knowledge/cwe/CWE-116.json` + this report |
| Modified tracked files | `README.md`, `DROBON_REMAINING_WORK.csv`, `docs/CAPABILITY_COVERAGE.md`, `docs/CAPABILITY_COVERAGE_MATRIX.json/.md`, `docs/CORPUS_GAP_REPORT.md`, `docs/CORPUS_TARGETS.json`, `docs/COVERAGE_MAP.json`, `docs/PACKS.md`, `docs/REQUIREMENTS_MATRIX.json`, `docs/SCA_RULE_SCHEMA_PROPOSAL.md`, `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md`, `docs/SOURCE_RELEASE_GATE.md`, `docs/ASSET_METHODOLOGY.md`, `docs/AUDIENCES.md`, `docs/CAPABILITY_GAP_MATRIX.md`, `docs/CURRENT_INVENTORY.json`, `data/asset-cells/.manifest.json`, `scripts/test-doc-drift.mjs`, `scripts/test-eval.mjs` — the remaining 2,461 modified entries are pre-existing and were not touched |
| `LICENSE` | absent (invariant preserved) |
| `docs/OWNER_DECISIONS.json` | not edited (`git diff` empty); schema `drobon.corpus.decisions/v1` untouched; 4 `OWNER_DECISION_REQUIRED` + 1 `APPROVED` (original content) unchanged |
| D-13 | inactive; the legacy-record exception decision was not activated |

---

## 12. Main App confirmation

The Main App repository (`mdraselislam0101-design/Drobon`) was **not** modified, built, deployed, read for new facts, or bundled with Dataset content in this pump. No code, configuration, dependency, database, migration, production data, build or deployment file was touched. Dataset / App / production-DB separation is unchanged. The previously verified App pin (`c32c797a549453802bd6d82c5673d2a1728457a3`, 2026-10-14) is carried forward as historical evidence only and was not re-verified in this pump.

---

## 13. Git operations performed

**None.** No commit, push, branch, merge, tag, release, deploy, history rewrite, `git reset --hard`, `git clean`, mass restore or deletion was performed. All changes are working-tree changes on `arena/a4caaeb8-drobon-dataset`, preserved for the owner's review. No pre-existing modified or untracked file was reverted, overwritten or removed; every earlier report, appendix, manifest, audit artefact and user file is intact.

---

## Appendix A — what the semantic inventory of the corpus found (baseline 252 → final 263)

- **Purpose grouping is saturated**: 12 categories, 7 check types, 44 security-header rules, 40 CSP rules, 15 CORS rules. The corpus is not missing categories; it is missing question types.
- **Duplicates under different names**: one (`106` ≡ `150`, §5). Reported, not merged.
- **Strict evidence subsets**: 131 same-target pairs, 3 invisible to the header-keyed gate, all explained (§5); 128 tracked by the gate, 5 reviewed in the ledger, 123 expected absence-class.
- **Findings whose evidence cannot support a conclusion**: three candidates were rejected on this ground this pump (`cors-expose-headers-forbidden`, `location-empty`, `cors-allow-methods-empty`), and 10 fingerprint rules were rejected for the same reason at the corpus level.
- **Generic remediation / insufficient negatives**: 16 remediations under 60 characters and five rules with only three tests are recorded as pre-existing quality debt, not fixed silently in this pump.
- **Text-string-only rules**: the 101 body rules remain text-string predicates by construction; no rule claims to have parsed a document.

## Appendix B — retained blockers and honesty items

| Item | State |
|---|---|
| `EVAL-SAST-008` | FAIL preserved (documented false positive, not suppressed) |
| 11 UNASSESSED evaluation cases | preserved |
| BLK-001…BLK-004 | unchanged |
| OD-1 (`DPK-DAST-050`, protocol-relative Location) | unchanged, still `BLOCKED_PENDING_OWNER_DECISION` in the overlap ledger |
| D-13 | inactive |
| SCA | `RIGHTS_BLOCKED`, no advisory data imported, no SCA rule pack authored |
| GAP-005 / GAP-006 / GAP-007 | unchanged, App-side |
| `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md` | corrected: the guessed `test-packs 6,163/6,163` is replaced by the measured `5,422/5,422` and rule count 1,310 |
| Tranche 2–3 report's "npm test after every edit" claim | not restated; this report cites only the final full run (`npm test` EXIT 0, 22,302 `ok`, determinism 5/5) executed after the last content edit, with the tree digest printed by that run and quoted in the pump summary |
| Counting vocabulary | one detection = one `(check type, target, semantic condition)`; patterns, records, remediation, tests and evaluation cases are counted separately and never summed into the detection figure |
