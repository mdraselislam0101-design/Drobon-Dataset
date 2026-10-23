# DROBON AEGIS — DAST 1,000 DATA + 1,000 PATTERNS + 1,000 RULES MASTER EXPANSION PUMP

**Date:** 2026-10-19
**Repository:** `mdraselislam0101-design/Drobon-Dataset` (branch `arena/a4caaeb8-drobon-dataset`)
**Scope:** cumulative expansion of the existing DAST Dataset, on top of the 95-rule DAST inventory, its semantics, evaluations, tests, provenance and documentation.
**Baseline commit:** `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged at the end of this execution)
**Dataset license:** none (`LICENSE` absent; the no-LICENSE invariant is preserved)
**Authorization:** Dataset-only. The Main App was read-only background context and was not modified, loaded, built or invoked.

---

## 0. Verdict in one table

| Target | Baseline | Final (verified) | Target | Status |
|---|---|---|---|---|
| DAST rules | 95 | **116** | 1,000 | **NOT MET** — 884 short |
| DAST intelligence records | 95 (one per DAST rule) | **116** | 1,000 | **NOT MET** — 884 short |
| DAST detection patterns | 95 (one per DAST rule) | **116** | 1,000 | **NOT MET** — 884 short |
| Dataset-wide records (all families) | 1,142 | **1,163** | — | meets 1,000 but is **not** a DAST-domain count |
| Dataset-wide patterns (all families) | 1,142 | **1,163** | — | meets 1,000 but is **not** a DAST-domain count |
| DAST evaluation cases | 130 (DAST) / 1,259 (all) | **215 / 1,316** | — | every DAST rule has ≥1 positive and ≥1 negative case |
| `npm test` | exit 0 / 19,728 ok-lines | **exit 0 / 20,043 ok-lines** | exit 0 | PASS |
| Synthetic eval metrics | TP 1,168 / FP 1 / FN 0 | **TP 1,189 / FP 1 / FN 0** | — | 11 cases remain UNASSESSED |

**Pump verdict:** the expansion executed and is verified, but the 1,000/1,000/1,000 objective is **NO-GO as met**. The honest ceiling of the current scanner contract is far below 1,000; padding was refused. Section 9 gives the measured ceiling analysis and the exact capability dependencies.

---

## 1. What this execution actually did

1. Reconstructed the baseline from the tree before editing (no inherited number was trusted).
2. Added **21 new DAST rules** in three evidence-gated batches (ids `DPK-DAST-101` … `DPK-DAST-121`), each with one pattern, one record, one remediation entry, executable tests and evaluation cases.
3. Extended the CSP semantic model with **four** predicates and added the new CSP rule to the independent differential gate (`test-csp-semantics` grew from 11 to 19 rules and from 4,400 to 22,800 generated rule/policy pairs).
4. Added **57 evaluation cases**: 42 positive/negative pairs for the new rules (`EVAL-DAST-160` … `-201`) and 15 negative cases (`EVAL-DAST-202` … `-216`) that close a measured negative-coverage gap for 15 pre-existing rules.
5. Repaired two pre-existing rule descriptions (`DPK-DAST-049`, `DPK-DAST-051`) that still carried unrelated boilerplate; documented cross-rule absence overlaps on four rules without changing behaviour.
6. Re-ran every gate in the repository and reconciled every count pin that the tree change touched (`README.md`, `REQUIREMENTS_MATRIX.json`, `CORPUS_TARGETS.json`, `COVERAGE_MAP.json`, `CAPABILITY_COVERAGE_MATRIX.json` + rendered `.md`, `AUDIENCES.md`, `CORPUS_GAP_REPORT.md`, `CAPABILITY_COVERAGE.md`, `SCA_RULE_SCHEMA_PROPOSAL.md`, `PACKS.md`, and the hard-coded pins in `test-doc-drift.mjs`, `test-current-state.mjs`, `test-eval.mjs`).
7. Wrote this report. No git commit, push, branch, tag, merge, release or history operation was performed.

---

## 2. Baseline (measured, not assumed)

Method: read the tree, count files, run the generators and the suite before any edit.

| Fact | Value |
|---|---|
| `git rev-parse HEAD` | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` |
| `git status --porcelain -uall` | 4,433 entries |
| DAST rule files | 95 |
| Patterns / records / remediation | 1,142 / 1,142 / 1,142 |
| Evaluation cases | 1,259 total; 11 UNASSESSED; `EVAL-SAST-008` FAIL (pre-existing, preserved) |
| Synthetic eval metrics | TP 1,168 / FP 1 / FN 0 |
| `npm test` | exit 0, 19,728 `ok` lines |
| `npm run dedup-report` | 100 files / 84 items / 9 multi-file tuples / 0 conflict tuples |
| `LICENSE` | absent |
| `docs/OWNER_DECISIONS.json` | unmodified, closed-key schema intact |

The reported "95-rule DAST inventory" reconciled exactly with the tree. The gap to the objective was therefore 905 rules at the start of this execution.

**Critical structural fact discovered during reconciliation:** the pack model is *one pattern, one record and one remediation entry per rule* (`packs/dast/v1/rules/*.json` → `patternRefs` → `knowledge/patterns/` → `knowledge/records/` → `knowledge/remediation/`). `knowledge/patterns` is dataset-wide (SAST + secrets + DAST), not DAST-only. Therefore the DAST-domain record count and the DAST-domain pattern count are **identical to the DAST rule count by construction**. Reaching 1,000 DAST records or patterns requires 1,000 justified DAST rules; it cannot be achieved by adding data files independently without inventing patterns with no distinct detection purpose.

---

## 3. New rules (21)

Every rule below is original DROBON work: its detection logic, title, rationale, limitation, tests and remediation text were authored for this Dataset. Public protocol facts (RFC 6265, RFC 6797, CSP Level 3, Fetch/CORS, Reporting API, HTML `Refresh`, `Alt-Svc`/RFC 7838) informed semantics; no third-party rule text, signature pack or catalogue structure was copied.

| ID | Question | CWE | Sev | Category | Check type | Tests | Eval cases |
|---|---|---|---|---|---|---|---|
| `DPK-DAST-101` | CORS lists a plaintext `http://` origin | 942 | LOW | cors | response-header-matches | 6 | 160/161 |
| `DPK-DAST-102` | CSP `connect-src` allows a plaintext scheme/origin | 319 | MEDIUM | transport-security | response-header-matches | 7 | 162/163 |
| `DPK-DAST-103` | CSP `form-action` allows plaintext submissions | 319 | MEDIUM | transport-security | response-header-matches | 7 | 164/165 |
| `DPK-DAST-104` | CSP `frame-src` allows every origin | 693 | MEDIUM | csp-weakness | response-header-matches | 7 | 166/167 |
| `DPK-DAST-105` | CSP `object-src` allows every origin | 693 | MEDIUM | csp-weakness | response-header-matches | 7 | 168/169 |
| `DPK-DAST-106` | CSP `sandbox` grants `allow-scripts` + `allow-same-origin` (self-removal) | 693 | MEDIUM | csp-weakness | response-header-matches | 7 | 170/171 |
| `DPK-DAST-107` | CSP `style-src` allows every origin | 693 | MEDIUM | csp-weakness | response-header-matches | 7 | 172/173 |
| `DPK-DAST-108` | CSP `worker-src` allows every origin | 693 | MEDIUM | csp-weakness | response-header-matches | 7 | 174/175 |
| `DPK-DAST-109` | Laravel Whoops error page disclosed | 209 | MEDIUM | debug-exposure | response-body-matches | 5 | 176/177 |
| `DPK-DAST-110` | `Refresh` redirects to a plaintext URL | 319 | MEDIUM | transport-security | response-header-matches | 6 | 178/179 |
| `DPK-DAST-111` | Spring Boot Whitelabel error page disclosed | 209 | MEDIUM | debug-exposure | response-body-matches | 5 | 180/181 |
| `DPK-DAST-112` | `X-Frame-Options` value is ignored by browsers | 693 | MEDIUM | security-headers | response-header-matches | 6 | 182/183 |
| `DPK-DAST-113` | `Alt-Svc` advertises cleartext `h2c` | 319 | MEDIUM | transport-security | response-header-matches | 7 | 184/185 |
| `DPK-DAST-114` | CORP explicitly set to `cross-origin` | 693 | LOW | security-headers | response-header-matches | 6 | 186/187 |
| `DPK-DAST-115` | CSP `report-uri` uses a plaintext endpoint | 319 | LOW | transport-security | response-header-matches | 7 | 188/189 |
| `DPK-DAST-116` | `Link` header points at a plaintext origin | 319 | LOW | transport-security | response-header-matches | 6 | 190/191 |
| `DPK-DAST-117` | `Referrer-Policy: no-referrer-when-downgrade` leaks full URLs | 200 | LOW | information-disclosure | response-header-matches | 6 | 192/193 |
| `DPK-DAST-118` | `Refresh` uses a protocol-relative target | 601 | MEDIUM | open-redirect | response-header-matches | 7 | 194/195 |
| `DPK-DAST-119` | `Report-To` names a plaintext endpoint | 319 | LOW | transport-security | response-header-matches | 6 | 196/197 |
| `DPK-DAST-120` | `X-Permitted-Cross-Domain-Policies: all` | 693 | LOW | security-headers | response-header-matches | 6 | 198/199 |
| `DPK-DAST-121` | HSTS `max-age` is not a valid delta-seconds value | 319 | MEDIUM | transport-security | response-header-matches | 9 | 200/201 |

**Non-overlap justification (the hard part).** Each new rule answers a question no existing rule answers, and the justification is recorded in the rule description:

- 101 vs 011/058/078/084/097: those cover wildcard origin, `null` origin, methods, exposed headers, request headers. None looked at the *scheme* of the allowed origin.
- 102/103 vs 093: 093 covers `script-src` plaintext only. `connect-src` and `form-action` govern XHR/WebSocket and submission respectively; they have different fallback and browser behaviour.
- 104/105/107/108 vs 022/070/086/092/093: existing wildcard rules cover `default-src`, `script-src`, `connect-src`, `frame-ancestors` and `script-src` plaintext. These four directives are separate policies with separate effects (frames, legacy plugin content, styles, workers).
- 106 vs 010/012/092: framing *presence* rules do not read the `sandbox` token pair. `allow-scripts` together with `allow-same-origin` is the one sandbox combination that can remove its own restriction.
- 109/111 vs 052/053/054/067/079/082/083/088/090: each existing body rule matches a language/framework stack-frame shape. The Whoops and Whitelabel page markers are different evidence (framework default error template) and are independent of the trace format.
- 110 vs 094/100/118: 094 is any absolute `Refresh` target, 100 is `Location` downgrade, 118 is protocol-relative `Refresh`. 110 is specifically a plaintext `Refresh` URL.
- 112 vs 007/025: 007 is the header missing, 025 is `ALLOW-FROM`. 112 is a present but unrecognised value that browsers discard, which neither covers.
- 113 vs 001/100: 001 is the observed URL scheme, 100 is a redirect downgrade. `Alt-Svc: h2c` is an advertisement that later requests may use cleartext HTTP/2.
- 114 vs 014: 014 is the header missing; 114 is an explicit `cross-origin` opt-out.
- 115 vs 072/119: 072 is report-only delivery, 119 is the `Report-To` header. `report-uri` is a CSP directive whose values are URLs (`report-to` values are group names, deliberately not treated as URLs).
- 116 vs 055: 055 matches markup in the body; 116 reads the `Link` response header.
- 117 vs 068: `unsafe-url` sends the full URL everywhere; `no-referrer-when-downgrade` still sends it to every HTTPS destination.
- 118 vs 050/094: 050 is a protocol-relative `Location`, 094 is any absolute `Refresh` target. 118 is the protocol-relative `Refresh` case, which only becomes cross-origin after resolution.
- 119 vs 043: 043 is the header missing; 119 is a present header with a plaintext endpoint.
- 120 vs 044: 044 is the header missing; 120 is the explicit `all` value.
- 121 vs 003/016/024: 003 reports a missing `max-age` *directive*, 016 reports a missing header, 024 reports a weak numeric or quoted value. None reported an unquoted non-numeric value, which makes browsers discard the whole header.

---

## 4. Capability → asset mapping

| Capability | Implementation | Assets that depend on it | Verification |
|---|---|---|---|
| CSP grammar + directive fallback + duplicate-directive first-wins | `scripts/lib/csp.mjs` (`parseCspHeader`, `effectiveSources`, `declaresDirective`, `everyPolicy`) | rules 002/010/021/022/059/060/061/070/072/075/086/087/092/093/095/098/099/102–108/115 | `test-csp-semantics` 22,983/22,983 |
| New CSP predicates: any-directive wildcard, directive plaintext, sandbox escapability, `report-uri` plaintext | `headerHasDirectiveWildcard`, `headerDirectiveAllowsPlaintext`, `headerSandboxEscapable`, `headerReportUriAllowsPlaintext` | 102–108, 115 | differential gate: 19 rules × 1,200 generated policies + 96 curated rows |
| Set-Cookie attribute model (flag attributes ignore their value; discarded cookies set nothing; duplicate attributes last-wins) | `scripts/lib/set-cookie.mjs` (`parseSetCookie`, `cookieHasFlag`, `cookieStorageRejection`, `cookieWillBeStored`) | 004/006/008/071 | `test-cookie-semantics` 1,676/1,676 (22 curated, 600 generated, 325 cross-rule inputs) |
| Single-header value matching (case-insensitive) | `evalDastCheck` `response-header-matches` | 66 rules | `test-packs` 4,834/4,834 |
| Body signature matching | `response-body-matches` | 21 rules | `test-packs`, evaluation |
| Absence semantics | `missing-response-header`, `response-header-missing-directive` | 24 rules | `test-packs`, evaluation |
| Cookie flag semantics | `cookie-missing-flag` | 3 rules | cookie gate |

Check vocabulary: **unchanged at 7 types**; no schema change and no new check type was introduced.

---

## 5. Verification evidence (real commands, real exit codes)

| Command | Exit | Result |
|---|---|---|
| `npm test` | **0** | all suites PASS; 20,043 `ok` lines |
| `node scripts/test.mjs` (inside suite) | 0 | 600/600 |
| `node scripts/test-packs.mjs` | 0 | 4,834/4,834 |
| `node scripts/test-audiences.mjs` | 0 | 3,533/3,533 |
| `node scripts/test-assets.mjs` | 0 | 9,322/9,322 |
| `node scripts/test-csp-semantics.mjs` | 0 | 22,983/22,983 assertions; 96 curated rows; 22,800 generated rule/policy pairs |
| `node scripts/test-cookie-semantics.mjs` | 0 | 1,676/1,676 assertions; 22 curated rows; 600 generated pairs; 325 cross-rule inputs |
| `node scripts/test-consistency.mjs` | 0 | 222/222 |
| `node scripts/test-rehearsal.mjs` | 0 | 78/78 |
| `node scripts/test-eval.mjs` | 0 | 43/43 |
| `node scripts/validate-packs.mjs` | 0 | PASS, 1,166 files, 0 errors |
| `node scripts/validate-assets.mjs` | 0 | PASS, 2,326 files, 0 errors |
| `node scripts/validate-audiences.mjs` | 0 | PASS, 1,174 files, 0 errors |
| `node scripts/validate-capability-coverage.mjs` | 0 | 656 passed, 0 failed |
| `node scripts/test-doc-drift.mjs` | 0 | 119 passed, 0 failed |
| `node scripts/test-current-state.mjs` | 0 | 153 passed, 0 failed |
| `node scripts/originality-report.mjs --check` | 0 | 1,163 rules / 1,163 patterns / 1,163 records / 1,163 remediation; **0 hard defects**; 0 patterns without a record, 0 rules without a record, 0 rules without a pattern |
| `node scripts/dedup-report.mjs` | 0 | 100 files / 84 items / 9 multi-file tuples / **0 conflict tuples** |
| `npm run test:determinism` | 0 | 5/5; regenerated files byte-identical, checked-in tree matches regeneration, digest reproducible (`fa3dfb3e4f5ce773…`, measured before the final report-only edits) |
| `node scripts/run-eval.mjs` | 0 | 1,316 cases; TP 1,189 / FP 1 / FN 0; 11 UNASSESSED; `EVAL-SAST-008` FAIL preserved |

Additional checks performed for this report:

- **Duplicate check definitions:** 0. No two DAST rules share an identical `(type, header/directive, pattern)` tuple.
- **Rule-level test depth:** 622 executable observation tests across 116 rules (min 3, max 11). Fifteen rules that shipped only two tests (001/002/005/007/009/010 and nine cell-generated rules) gained two meaningful cases each; expectations were not relaxed.
- **Negative-coverage audit:** before this execution, 15 DAST rules had a positive case but no negative case. After adding `EVAL-DAST-202…216`, **all 116 rules have at least one positive and at least one negative evaluation case**.
- **Cross-rule absence overlap audit:** 120 same-header co-firing pairs were observed across the corpus's own positive fixtures. Every one is an intended, documented composition (for example a missing CSP triggers 002 and 059/060/087 together; each of those rules states that it also fires when the header is absent and points at 002). Two rules (003, 010) and the two repaired cells (023, 049) were given the missing cross-reference sentence; behaviour was not changed. `DPK-DAST-057` intentionally keeps absence semantics because no dedicated "Cache-Control missing" rule exists.

---

## 6. Evaluation results

- Cases: **1,316** (1,305 assessed + 11 UNASSESSED).
- Synthetic, test-only population: FP **1**, FN **0**, TP **1,189**. (The single FP is `EVAL-CMD-023`, the documented keyword-trap case; it is part of the measured population and is not hidden.)
- DAST cases: **215**, covering **116/116** rules with a positive detection and **116/116** with a negative expectation.
- New cases in this execution: **57** (`EVAL-DAST-160` … `-216`), all PASS on execution.
- **UNASSESSED preserved** (not counted as successes): `EVAL-CMD-023`, `EVAL-CMD-024`, `EVAL-CMD-025`, `EVAL-SAST-004`, `EVAL-SAST-007`, `EVAL-SAST-014`, `EVAL-SAST-015`, `EVAL-SAST-016`, `EVAL-SEC-111`, `EVAL-SQL-027`, `EVAL-SQL-028`.
- **`EVAL-SAST-008` remains FAIL.** It is unrelated to DAST, was failing before this execution, and was not rewritten, weakened or deleted.

No case's `groundTruth`, `forbiddenDetections` or expected evidence was relaxed to obtain a green result. Two batch-1 body-marker rules initially failed because their *negative* fixtures quoted the detection marker; the fixtures were replaced with genuinely marker-free negatives, not the rules.

---

## 7. Provenance, rights, determinism

- **Provenance:** every new rule carries its cell provenance (`data/asset-cells/dast-15.json`, `dast-16.json`, `dast-17.json`), a DROBON-authored description/rationale/limitation, and a generated record and remediation entry.
- **Rights:** the Dataset still has **no `LICENSE`**; publication rights remain unverified. No new third-party content was imported. No CVE/NVD/GHSA/OSV/KEV/EPSS/advisory data was imported or fabricated. All new fixtures are synthetic observations (`synthetic: true`, `testOnly: true`, labelled "NOT vulnerability intelligence").
- **Originality:** the originality checker reports 0 hard defects. This is a technical duplicate/similarity check and is **not** a legal conclusion.
- **Determinism:** regeneration is byte-identical; the whole-tree digest is reproducible; no timestamps or randomness were introduced.
- **No production claims:** nothing in this execution proves live-target behaviour, exploitability or scanner parity.

---

## 8. Count reconciliation

| Inventory | Raw files | Validated / usable | Target | Unique | Integrated | Tested |
|---|---|---|---|---|---|---|
| DAST rules | 116 | 116 | 1,000 | 116 | 116 (1 pattern + 1 record + 1 remediation each) | 116 (622 observation tests, 215 eval cases) |
| DAST patterns | 116 | 116 | 1,000 | 116 | 116 (all referenced by exactly one rule) | 116 |
| DAST records | 116 | 116 | 1,000 | 116 | 116 | 116 |
| Dataset-wide patterns | 1,163 | 1,163 | — | 1,163 | 1,163 | — |
| Dataset-wide records | 1,163 | 1,163 | — | 1,163 | 1,163 | — |
| Remediation entries | 1,163 | 1,163 | — | 1,163 | 1,163 | — |
| Evaluation cases | 1,316 | 1,305 assessed | — | 1,316 | — | 1,305 |

**No padding was used.** No placeholder rule, inert record, spelling-variant pattern, unreachable ID or duplicated question is included in the 116. The 21 new rules each passed the same gate as the pre-existing corpus: distinct question, precise evidence, positive/negative/boundary tests, ReDoS lint, linked pattern/record/remediation, and executed evaluation cases.

---

## 9. Why the 1,000 target is not reachable honestly under the current contract

This is the central finding of the execution. It is a measured capability ceiling, not a claim that "1,000 is impossible in principle".

### 9.1 The binding constraint is the rule, not the data files

The pack model emits exactly one pattern and one record per rule. The DAST inventories therefore cannot diverge: **records = patterns = rules**. Any attempt to raise records or patterns independently would either duplicate detection purposes (forbidden) or create data with no consuming rule (inert, forbidden). The only honest path to 1,000 is 1,000 distinct DAST questions.

### 9.2 The scanner's input contract is one HTTP response

All seven check types evaluate a single observation `{url, status, headers, body}`. They cannot:

- correlate two headers (`Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials`, `Set-Cookie` + `Cache-Control`, CSP + HSTS, `X-Frame-Options` + `frame-ancestors`);
- read a header list or a duplicate header (the evaluator sees one value per name);
- compare a request with its response (reflection, injection, parameter handling, verb tampering);
- inspect cookies as structured objects beyond the four implemented predicates (prefixes, `Domain`, `Path` semantics, lifetime);
- observe TLS handshakes, certificates or redirect chains;
- inspect the DOM, scripts, or a rendered page.

Those six gaps are exactly the classes that contain most of the remaining plausible DAST questions. Five of them are already recorded as owner decisions (`docs/DAST_OWNER_DECISION_PACKET_2026-10-19.md`, OD-1…OD-5) and remain **`BLOCKED_PENDING_OWNER_DECISION`**. Closing them would require new check types and a schema decision, which this pump was not authorized to make.

### 9.3 The single-header space is nearly exhausted

The 116 rules now cover **43 distinct response-header names**, 12 categories, 15 CWEs, 21 body-signature families, and every standard security header a passive single-response scan can see (CSP and its directives, HSTS, COOP/COEP/CORP, CORS, cookies, framing, referrer, permissions, MIME sniffing, caching, reporting, redirects, transport).

In this execution alone, 7 additional candidates were probed and **rejected**:

| Candidate | Probe result | Decision |
|---|---|---|
| HSTS delivered over plaintext | Header is inert; the response is already reported by `DPK-DAST-001` | Rejected: duplicate finding |
| `X-XSS-Protection: 1` / `1; mode=block` | Retired auditor; enabling it is not a defensible security finding | Rejected: no justified finding |
| More per-directive CSP wildcards (`img-src`, `font-src`, `media-src`, `manifest-src`) | Same question as 104/105/107/108 with a directive substitution | Rejected: spelling variants |
| `Access-Control-Allow-Credentials: true` with a wildcard origin | Needs the origin header at the same time | Rejected: multi-header correlation (OD-3) |
| `__Host-` / `__Secure-` cookie prefix enforcement | Needs name + attribute semantics; no check type exists | Rejected: new check type (OD-5) |
| `Permissions-Policy` with an invalid allowlist | The whole declaration is ignored, but browsers differ and the default allowlist is feature-specific | Rejected: semantics not provable with the available evidence |
| Cookie name-validity discard rule | A discarded cookie is a functional bug, not a security condition; needs a cookie-model check type | Rejected: no security question + new check type |

The same bar rejected candidates in earlier iterations (`object-src *` as subsumed by 022/075, `style-src` scheme rules as duplicates of 093, `Set-Cookie` prefix rules, JSON/XML content-type rules). The remaining implementable, non-duplicative single-header questions are now a small handful, and several of those are low-value (legacy headers with no modern browser effect).

### 9.4 What 1,000 would require

To reach 1,000 distinct DAST rules honestly, the Dataset would need **at least one** of the following, each of which is an owner decision or prohibited:

1. **Owner approval of the blocked check types** (header list, multi-header correlation, request/response pairs, cookie model). Even with all four, the question space is unlikely to reach 884 additional *distinct* questions.
2. **A different scanner contract** (active probing, TLS handshake data, rendered DOM, redirect-chain execution). That is a product-scope change, not a Dataset batch.
3. **Advisory/CVE-driven detection.** Prohibited by the brief and by the repository's no-intel policy; it would also turn the corpus into a feed consumer, not an original intelligence asset.
4. **Padding.** Explicitly forbidden and deliberately not used.

The demonstrated ceiling for the current contract is therefore *the current corpus plus a small tail of genuinely new single-response questions* — on the order of tens, not hundreds. This pump implemented every candidate that survived the probe bar and stopped when the bar stopped admitting new questions.

---

## 10. Owner decisions and standing blockers (unchanged)

| ID | Blocker | Status |
|---|---|---|
| OD-1 | `DPK-DAST-050` (protocol-relative `Location`) scope/permanent-ID issue | `BLOCKED_PENDING_OWNER_DECISION` — untouched |
| OD-2 | Header-list check type (duplicate `Content-Security-Policy`) | `BLOCKED_PENDING_OWNER_DECISION` |
| OD-3 | Multi-header correlation | `BLOCKED_PENDING_OWNER_DECISION` |
| OD-4 | Request/response pair analysis | `BLOCKED_PENDING_OWNER_DECISION` |
| OD-5 | Cookie-model check type (prefix/domain/lifetime semantics) | `BLOCKED_PENDING_OWNER_DECISION` |
| — | Dataset license / redistribution rights | No `LICENSE`; rights unverified; **NO-GO** |
| — | SCA rule packs | 0 packs; schema proposal not approved |
| — | SAST 950 / 1,000 objective | Unchanged, not this pump's scope |
| — | `EVAL-SAST-008` | Pre-existing FAIL, preserved |
| — | App consumption of the Dataset | No loader/consumer exists; **NOT VERIFIED** |

`docs/OWNER_DECISIONS.json` was not modified. No owner decision was simulated, approved or inferred.

---

## 11. GO / NO-GO

- **DAST 1,000/1,000/1,000 objective: NO-GO (not met).** Verified at 116 rules, 116 DAST records, 116 DAST patterns.
- **Dataset publication: NO-GO.** No license, no rights grant, SCA still empty, owner decisions open, App has no consumer, and `EVAL-SAST-008` remains failing.
- **Expansion quality: GO (verified).** All new assets are unique, integrated, executable, tested and covered by positive and negative evaluation cases; every gate passes.
- **Main App readiness: NOT VERIFIED.** The App was not modified, loaded, built or exercised; no integration claim is made.

---

## 12. Final state

| Fact | Value |
|---|---|
| `HEAD` | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged) |
| Branch | `arena/a4caaeb8-drobon-dataset` |
| Worktree | 2,434 modified + 2,186 untracked = **4,620** `git status --porcelain -uall` entries |
| DAST rules | 116 |
| Patterns / records / remediation | 1,163 / 1,163 / 1,163 |
| Evaluation cases | 1,316 (1,305 assessed, 11 UNASSESSED) |
| `npm test` | exit **0**, 20,043 `ok` lines |
| Determinism digest | `fa3dfb3e4f5ce773…` (reproducible; recorded as a run artifact — report-only edits change the tree hash) |
| Git operations | **none** — no commit, push, branch, tag, merge, release or history rewrite |

### What this report does not claim

- It does not claim that 1,000 rules were produced.
- It does not claim live-site testing, active probing, exploitability, or parity with commercial scanners.
- It does not claim legal ownership or third-party-free status; originality checks are technical, not legal.
- It does not claim that the remaining single-response question space is literally empty; it claims that every candidate probed under this contract either became a rule or was rejected for a recorded reason.

**Bottom line:** the DAST corpus grew from 95 to 116 verified rules (+21, +22.1%), with 57 new evaluation cases, a stronger differential CSP gate, complete positive/negative evaluation coverage for every DAST rule, and zero duplicate check definitions. The 1,000 target is not met, and the measured reason is a capability ceiling that only an owner decision (or a product-scope change) can lift.
