# DAST capability-aligned expansion (500-target pump) — 2026-10-20

Repository: `mdraselislam0101-design/Drobon-Dataset` · branch `arena/a4caaeb8-drobon-dataset`
· HEAD `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged all pump).
Method: Dataset-only. The Main App was read-only; no git object was written (no commit, branch,
tag, push, reset). This report is new; every earlier report is kept unchanged as history.

The pump asked for **up to 500 distinct, legitimate, useful DAST detections**. 500 is treated as a
target, never a quota. This report states what was actually authored, tested and evaluated, and it
does **not** claim 500.

---

## 1. Scope, definitions and the honest headline

A detection counts here only when it is (a) expressible by one of the seven check types this
repository's evaluator implements and `docs/DATASET_APP_CONTRACT.md` documents, (b) semantically distinct from every rule already in the pack,
(c) tested positively and negatively against real observation objects, (d) covered by an
independent evaluation case with an authored-before-run expectation, (e) attributed to an asset
cell with provenance, (f) free of duplicate, placeholder or inert behaviour.

| Quantity | Value | Meaning |
|---|---|---|
| Verified detections (rules) | **153** | one rule = one (check type, header or body target, semantic condition) |
| Delivered by this pump | **+37** | DPK-DAST-122 … DPK-DAST-160 |
| Remaining to the 500 target | **347** | not authored, not claimed |
| Fabricated to close the gap | **0** | no filler, no duplicate wording, no variants of one question |

**Headline: 153 of the 500 target, all verified; the target is not met and is not claimed.** The
difference is unauthored work inside an existing capability, not evidence that 500 is impossible —
and it is certainly not a reason to pad.

## 2. Baseline reconciliation (before → after)

Every number below is recomputed from the tree, not recalled.

| Item | Before | After | Delta |
|---|---|---|---|
| DAST rules | 116 | 153 | +37 |
| Distinct check types used | 7 | 7 | 0 (no new type; the vocabulary is closed) |
| Headers with at least one rule | 43 | 47 | +4 |
| DAST rule tests | 622 (262 pos / 360 neg) | 812 (344 pos / 468 neg) | +190 |
| DAST evaluation cases | 215 | 289 | +74 |
| Pack rules (SAST 950 + secrets 97 + DAST) | 1,163 | 1,200 | +37 |
| Patterns / records / remediation | 1,163 / 1,163 / 1,163 | 1,200 / 1,200 / 1,200 | +37 each |
| Evaluation cases (all cohorts) | 1,316 | 1,390 | +74 |
| Retired reservations | 27 | 29 | +2 (`DPK-DAST-151`, `-154`, withdrawn as duplicates) |
| Worktree entries | 4,639 (2,461 M / 2,178 ??) | 4,863 (2,461 M / 2,402 ??) | +224 entries |

The 224 new entries are exactly: 1 cell batch (`data/asset-cells/dast-18.json`), 37 rules,
37 patterns, 37 records, 37 remediation entries, 74 evaluation cases and this report. No file was
deleted from the repository: four evaluation cases created earlier in the pump were removed
because they referenced the two withdrawn rules, and those paths had no prior history.

## 3. Verified capability map (families A–H)

Only capabilities that exist in the repository's own evaluator are used. `evalDastCheck()`
(`scripts/validate-packs.mjs`) implements exactly seven types: `response-header-matches`,
`missing-response-header`, `response-header-missing-directive`, `cookie-missing-flag`,
`response-header-host-differs`, `http-url`, `response-body-matches`.

| Family | State | Rules after pump | What is genuinely checkable |
|---|---|---|---|
| A. CSP (directives, keywords, sources) | VERIFIED | 33 | directive-scoped value matching, `'none'` semantics, wildcard and scheme sources, nonce/hash escape, obsolete directives, report-only mode |
| B. HSTS / transport security | VERIFIED | 7 HSTS + 13 transport-security | max-age/directives, quoted values, over-plaintext delivery (`requireScheme: http`) |
| C. COOP / COEP / CORP / XFO / Referrer-Policy / Permissions-Policy | VERIFIED, single-response only | 3 / 2 / 2 / 3 / 4 / 2 | value and token matching on one header; **no** frame-ancestor computation, no cross-header correlation |
| D. Cookies | VERIFIED | 5 (2 `Set-Cookie` value + 3 flag rules) | flag presence and SameSite token validity; no session-cookie assumption, no jar modelling |
| E. CORS | VERIFIED, no preflight | 8 | one `Access-Control-*` header per rule; **no** preflight or multi-request reasoning, so "exploitable CORS" is never claimed |
| F. Cache / transport metadata | VERIFIED (thin) | 1 cache-control + 1 alt-svc + 1 via + 1 x-cache | single header values only |
| G. Information disclosure / errors | VERIFIED | 33 information-disclosure + 22 debug-exposure | banner headers and body fingerprints (actuator, pprof, mod_status, Elasticsearch, etcd, Prometheus, GraphQL, Swagger, ASP.NET, Tomcat, WildFly, WebLogic, better_errors, S3 listing, dotenv) |
| H. HTTP semantics / auth controls | PARTIAL | 1 `http-methods` (`Allow`), 1 `WWW-Authenticate`, 1 `Location` host change | status-line semantics and multi-step auth flows are out of contract |

Out of contract and therefore **not** attempted: active injection, replay, multi-request
state machines, authenticated crawling, browser execution, TLS protocol/cipher inference, and any
request-side observation. A missing header is still never reported as a confirmed vulnerability,
and a single header string never produces an exploitable-CORS claim.

## 4. Counting ledger — five separate ledgers, never summed

| Ledger | Count | Unit |
|---|---|---|
| Detections | 153 | rule (`packs/dast/v1/rules/*.json`) |
| Evidence definitions | 153 | one `check` object per rule, 7 permitted types |
| Patterns / knowledge records / remediation | 1,200 / 1,200 / 1,200 | generated from cells, 1:1 with rules |
| Rule tests | 812 | positive and negative observation examples |
| Evaluation cases | 289 DAST (1,390 all cohorts) | `data/eval-cases/EVAL-DAST-*.json` |

These are five different things. 153 detections are supported by 812 tests and 289 evaluation
cases; adding those numbers together would be inflation, so they are never added.

## 5. Batches executed, each with its own focused gate

| Batch | Content | Rules | Focused check |
|---|---|---|---|
| B0 | Candidate design in a scratch harness that imported the *real* `evalDastCheck` and `lintRedos` before any repo write. 40 groups designed, 1 withdrawn (`'none'` combined with other sources: existing rules already cover `'none'` semantics and the rewrite kept failing the ReDoS lint) | — | 39 candidate groups, 0 problems after redesign; 0 byte-identical check objects vs the 116 existing rules |
| B1 | CSP: six directive wildcards (`img-src`, `font-src`, `media-src`, `manifest-src`, `child-src`, `script-src-elem`), `strict-dynamic` without nonce/hash, `sandbox` + `allow-scripts allow-same-origin`, obsolete directives | 9 | `test-csp-semantics.mjs` (22,983 assertions), pack tests |
| B2 | Misc headers/transport: HSTS over plaintext, invalid `SameSite`, CORS wildcard-in-host, CORS origin with path, unrecognised `Referrer-Policy` token, `Refresh` script scheme, `X-DNS-Prefetch-Control: on`, `Origin-Agent-Cluster: ?0` | 8 | pack tests, ReDoS lint |
| B3 | Banner headers: `X-Backend-Server`, `X-AspNetMvc-Version`, `X-Debug-Token-Link`, `Docker-Distribution-Api-Version` | 4 | pack tests |
| B4 | Body fingerprints (16): Spring actuator env/index, Go pprof, Apache mod_status, Elasticsearch, etcd, Prometheus, GraphQL introspection, Swagger UI, ASP.NET dev exception, Tomcat, WildFly, WebLogic, better_errors, S3 listing, dotenv | 16 | pack tests, body-marker precision review |
| B5 | Retired after review: `script-src-attr` and `style-src-attr` `'unsafe-inline'` | −2 | overlap gate caught both as evidence subsets of `DPK-DAST-021` |
| B6 | Evaluation batch for every accepted rule (positive + negative pair) | 74 cases | `run-eval.mjs`, `test-eval.mjs` |

## 6. What the 37 rules actually add

| Family | New rules | Severity |
|---|---|---|
| CSP weakness (directive wildcards, strict-dynamic, sandbox, obsolete directives) | 9 | M/L |
| Information disclosure (banners + body fingerprints) | 13 | M/L/H (3 HIGH: actuator env, Elasticsearch info, dotenv served) |
| Debug exposure (pprof, mod_status, GraphQL, Swagger, ASP.NET, Tomcat, WildFly, WebLogic) | 8 | M/L |
| CORS (wildcard in host, origin with path) | 2 | L |
| Security headers (X-DNS-Prefetch-Control, Origin-Agent-Cluster) | 2 | L |
| Transport security (HSTS over plaintext) | 1 | M |
| Cookie flags (invalid SameSite token) | 1 | M |
| Open redirect (Refresh `javascript:`/`vbscript:`) | 1 | M |

New header names not previously covered: `X-Backend-Server`, `X-AspNetMvc-Version`,
`X-Debug-Token-Link`, `Docker-Distribution-Api-Version`.

## 7. Evidence model — unchanged schema, explicit limitations

Each rule states: what it reads (`check`), what counts as evidence, what the evidence does **not**
prove (`limitation`), the remediation, and the CWE where the mapping is defensible. Examples of
the limitation discipline that new rules follow:

- CSP directive wildcards: "one header value and one directive; a wildcard source widens where
  resources may load from, it does not prove that hostile content is reachable".
- `Refresh` script scheme: "the response tells the browser to navigate to a script URL; whether
  that URL executes depends on the browser and on navigation context".
- Body fingerprints: "a marker in the body identifies a deployed component; reachability and
  authentication of that component are not established by the marker".

No rule infers TLS versions, cipher suites, exploitability, or "vulnerable" status from a string.

## 8. Overlap, duplication and regex safety

- **Regex safety**: every new pattern passes `lintRedos()` (no nested quantifier, no unbounded
  wildcard pair). The initial design failed 11 patterns; they were redesigned around
  non-quantified lookaheads rather than loosened, and the lint was never edited.
- **Byte-level duplication**: the pre-write harness compared every candidate `check` object
  against the then-116 rules — 0 identical.
- **Evidence-subset gate** (`validate-dast-overlaps.mjs`): 222 checks, **100 subset pairs**, of
  which 95 are classified EXPECTED because the wider rule observes *absence* (a missing header
  makes every per-directive rule true), and 5 carry explicit ledger entries (1
  `BLOCKED_PENDING_OWNER_DECISION` on `DPK-DAST-050`, 4 `REVIEWED_RETAINED`). No new pair entered
  without review; the gate would have failed otherwise.
- **Two rules were withdrawn** because the gate proved them strict subsets of `DPK-DAST-021`
  (`script-src(-elem/-attr)` `'unsafe-inline'` with a nonce/hash escape). They were briefly
  generated and are now retired reservations — IDs never reused.

## 9. Evaluation coverage (measured by running, not asserted)

| Measure | Value |
|---|---|
| DAST rules with a positive case | 153 / 153 |
| DAST rules with a negative case | 153 / 153 |
| DAST evaluation cases | 289 (215 before, 74 added) |
| Result | TP 1,226 · FN 0 · FP 1 (the documented `EVAL-SAST-008` mutation case) |
| UNASSESSED preserved | 11 (unchanged) |

`test-eval.mjs` pins the population counts, so the totals cannot drift silently.

## 10. Documentation truth repair (defects found while verifying)

The drift gate was green before this pump while several live documents were stale, because the
pins were literals that matched the stale text. Fixed at the source:

| Defect | Evidence | Fix |
|---|---|---|
| `docs/ASSET_METHODOLOGY.md` header still claimed 1,163 pack rules / patterns / records | header line | 1,200/1,200/1,200 with the refresh date; the 954/954/914 figure stays only as dated history |
| `docs/AUDIENCES.md` carried two conflicting shared-base lines (1163 and 1200) | lines 56 and 90 | one authoritative statement, cross-referenced |
| `docs/DATASET_APP_CONTRACT.md` §1 said "1:1 with rules (1,163)" | rows 17–19 | 1,200; `1.1` history line kept as history |
| `README.md`, `docs/CORPUS_GAP_REPORT.md`, `docs/COVERAGE_MAP.json`, `docs/CORPUS_TARGETS.json`, `docs/REQUIREMENTS_MATRIX.json`, `docs/SCA_RULE_SCHEMA_PROPOSAL.md` | stale pack totals (1,163), DAST 116, SCA pack total 1,066 | recomputed to 1,200 / 153 / 1,103; the drift suite's audit-claim pins in `scripts/test-doc-drift.mjs` were refreshed in the same edit |
| `docs/CAPABILITY_COVERAGE_MATRIX.json` DAST row | declared 116 rules, 215 cases | 153 rules, 289 cases, prose recount dated |
| `docs/CAPABILITY_COVERAGE.md` remediation count | 1,163 | 1,200 |
| Retired reservation list | 27 IDs | 29 IDs, including the two withdrawn CSP rules |
| `docs/CORPUS_TARGETS.json` `totals.validated` | categories updated to 153 / 1,200 while the total still said 2,500 (the categories sum to 2,574) | total recomputed to 2,574; the validator now fails on any mismatch |

Gate hardening that came out of this: `docs/CAPABILITY_COVERAGE.md`'s DAST/pack totals are now
asserted from `computeInventory()` instead of a literal sentence, and the corpus-total check now
fails on any category/count mismatch.

## 11. Content-quality repair (found by reading the shipped records)

25 records carried vacuous consequence text ("Varies by setting", "X crypto or diagnostics are
weak") produced by group-level templates. All are now specific, mechanism-grounded sentences
derived from the literal the rule matches; 15 descriptions that fell under the 80-character floor
were lengthened rather than exempted. Examples:

- `php:pdo` — "$pdo->query interpolates the statement string instead of binding parameters, so the value becomes SQL syntax."
- `spring:h2` — "…publishes the H2 web console at /h2-console, a servlet that runs SQL entered in a browser form."
- `tf:masterpw` — "…written as a literal string in the configuration, so the highest-privilege database credential is stored with the code."

`test-assets.mjs` enforces the 80-character floor for all 1,200 records (9,620/9,620 assertions).
Its vacuous-risk guard previously matched only `Varies by control`, which is exactly why `Varies by setting` and `Varies by service` survived the check; the pattern now matches every `Varies by …` opener, so this class cannot come back through a new group template.

## 12. Rights, originality, publication safety

- All 37 rules, their tests, records, remediation and evaluation cases are DROBON-authored; no
  third-party rule text, identifier scheme or catalogue structure was copied. Standards (CSP,
  CORS, HSTS, RFC 9110) informed correctness only.
- No CVE/NVD/GHSA/OSV/KEV/EPSS feed, no exploit, no paid API, and no vendor name or signature
  database was used. Body fingerprints are written from protocol behaviour, not from a scanner's
  rule pack.
- Fixtures remain synthetic and are excluded from intelligence counts. No real credential, secret
  value or target was collected.
- **Publication remains NO-GO**: no `LICENSE` file exists and the owner grant (BLK-001/BLK-002) is
  still missing. Nothing in this pump changes the rights position.

## 13. Full canonical suite re-run (after the final edit)

`npm test` — one command, the repository's own chain (22 gates) — **EXIT 0**.

| Gate | Result |
|---|---|
| `scripts/test.mjs` | 600 / 600 |
| `scripts/test-packs.mjs` | 4,982 / 4,982 (DAST 153 rules, 812 tests) |
| `validate-dast-overlaps.mjs` | 222 checks, 100 subset pairs, PASS |
| `test-assets.mjs` | 9,620 / 9,620 |
| `test-csp-semantics.mjs` | 22,983 assertions |
| `test-cookie-semantics.mjs` | 1,666 assertions |
| `test-consistency.mjs` | 222 / 222 |
| `test-eval.mjs` | 43 / 43 (TP 1,226 · FN 0 · FP 1) |
| `test-doc-drift.mjs` | 120 / 120 |
| `test-current-state.mjs` | 155 / 155 |
| `validate-capability-coverage.mjs` | 695 / 695 |
| `originality-report.mjs --check` | 1,200 rules / 1,200 patterns / 1,200 records / 1,200 remediation |
| determinism | 5 / 5 (the whole-tree digest is printed by `npm run test:determinism` on every run; it is not quoted here because this report file is itself part of the hashed tree) |
| Aggregate | **20,642 `ok` lines, no FAIL, no NOT OK** |

`node scripts/run-eval.mjs` — EXIT 0 · 1,390 cases · 1,379 assessed · 11 UNASSESSED ·
TP 1,226 / FP 1 / FN 0.

The `npm test` run above happened after the last source and content edit; the documentation gates
were also re-run after this report was written and stayed green (`doc-drift` 120/120,
`current-state` 155/155, `test-assets` 9,620/9,620). A whole-tree digest is deliberately not quoted
as a fixed string: this report is inside the tree it hashes, so any later edit to these words would
make a quoted digest wrong.



`node scripts/generate-assets.mjs` — EXIT 0 · sast 950 · secrets 97 · dast 153 · patterns 1,200 ·
records 1,200 · remediation 1,200 · `quarantined: []`.
`node scripts/validate-packs.mjs` — PASS (1,203 files, 0 errors).
`node scripts/validate-assets.mjs` — PASS (2,400 files, 0 errors).

The pre-existing `EVAL-SAST-008` mutation case still fails by design and the 11 UNASSESSED cases
are untouched; both are pinned, neither was weakened to obtain a green run.

## 14. Verdict and what must happen next

**Verdict: PARTIAL.** 153 capability-justified detections exist and every gate is green; the
dataset as a whole cannot be declared COMPLETE.

| Objective | Verdict | Reason |
|---|---|---|
| 500 DAST detections | **NO-GO in this pump** | 153 delivered (30.6%); the remaining 347 are unauthored. Padding, header variants of one question, or per-UserType copies were refused. |
| Capability-aligned DAST expansion | COMPLETE for what was attempted | every added rule is tied to a real check type, tested, evaluated and overlap-reviewed |
| Dataset completion | PARTIAL | license/rights (BLK-001/002), production SCA intelligence, and App pack loaders (GAP-005/006/007) remain open |
| Publication | NO-GO | no license grant |
| App integration | NOT VERIFIED — and not claimed | the App repo was read-only; nothing here proves consumption |

Decisions needed, in order:

1. **Owner — license/rights (BLK-001/BLK-002)**: without a written grant, publication stays NO-GO.
2. **Owner — `DPK-DAST-050` (OD-1)**: rewrite, retire or retain; the overlap pair with
   `DPK-DAST-056` is recorded as `BLOCKED_PENDING_OWNER_DECISION`.
3. **Owner — D-13**: the condition is gone (0 patterns without a record, verified by recomputation);
   the decision file is untouched and D-13 stays inactive until the owner closes it.
4. **Owner/engineering — SCA**: a lawful advisory source is required before any production match.
5. **Engineering — App pack loaders**: GAP-005/006/007 decide whether any of these 153 rules can
   ever run inside the product.
6. **Engineering — next DAST tranche**: families C, F and H have thin coverage (COOP/COEP value
   sets, cache directives, `WWW-Authenticate` schemes). They are the honest place to continue;
   none of them reaches 500 on its own, and none should be stretched to.

---

## Appendix — 2026-10-21 update (defensive batch, DAST 263 → 280)

This section is appended; nothing above it was rewritten, because the 2026-10-20
figures were correct for the tree of that day.

| Item | 2026-10-20 (as written above) | 2026-10-21 (this batch) |
|---|---|---|
| DAST rules | 263 | **280** |
| Patterns / records / remediation | 1 310 each | **1 327 each** |
| Declared DAST tests | 1 292 | **1 371** (+79) |
| DAST evaluation cases | 509 | **528** (+19) |
| Check types | 7 (closed) | 7 (unchanged) |
| `run-eval` true positives | 1 336 | **1 353** |
| Distance to the 500 target | 237 | **220** |

The batch target was not "reach 500 faster" but "make the pack answer the question the
App asks of every response: is it hardened, and does it leak". Seventeen rules were
added across 7 families, two candidates were withdrawn with their IDs reserved, and one
was rejected before ID allocation (a 784-character pattern against a 500-character schema
limit). Full method, rule table, rejection reasons and measured outputs:
`docs/DAST_DEFENSIVE_BATCH_2026-10-21.md`.

What did **not** change, deliberately: the check vocabulary, the passive-observation
contract, the overlap policy (349 checks, 130 subset pairs, 0 unreviewed), the licence
position (still no `LICENSE`, BLK-001), and the 15 App-evaluator divergences recorded in
GAP-041. A larger pack is not a more integrated one.

---

## Appendix 2 — 2026-10-21 (app-surface batch, DAST 280 → 292)

Appended again; the figures above and in Appendix 1 remain correct for their own tree
state.

| Item | Appendix 1 (defensive batch) | Now (app-surface batch) |
|---|---|---|
| DAST rules | 280 | **292** |
| Patterns / records / remediation | 1 327 each | **1 339 each** |
| Declared DAST tests | 1 371 | **1 419** (+48) |
| DAST evaluation cases | 528 | **542** (+14) |
| `run-eval` true positives | 1 353 | **1 365** |
| Distance to the 500 target | 220 | **208** |
| Rules evaluable inside the App | not measured before this batch | **219 of 292 (75 %)** |

The second number is the one that matters. Reading the App's DAST engines
(`apps/api/src/scans/dast/engine.ts`, `activeEngine.ts` at `9360dd1`) showed that the pack
evaluator receives only 11 response headers and the body, clipped at 32 768 bytes. The
batch therefore added only body- and allowlisted-header rules, and it produced a new
gate that records which existing rules can never fire in the product:
`interop/app-dast-reachability.json` (73 rules across 47 headers), checked by
`scripts/validate-app-dast-reachability.mjs` inside `npm test`.

That gate changes the shape of the remaining work honestly: adding another
`Permissions-Policy` or CORP rule would raise the rule count without raising App
coverage. Until the App forwards those headers, the reachable ceiling is 219 plus
whatever new body/`Set-Cookie`/`Location` evidence can be defended. Full method and
rule table: `docs/DAST_APP_ALIGNED_BATCH_2026-10-21.md`.

---

## Appendix 3 — 2026-10-21 (app-surface batch 2, DAST 292 → 306)

| Item | Appendix 2 | Now |
|---|---|---|
| DAST rules | 292 | **306** |
| Patterns / records / remediation | 1 339 each | **1 353 each** |
| Declared DAST tests | 1 419 | **1 478** (+59) |
| DAST evaluation cases | 542 | **558** (+16) |
| `run-eval` true positives | 1 365 | **1 379** |
| Distance to the 500 target | 208 | **194** |
| Rules evaluable inside the App | 219 of 292 (75 %) | **233 of 306 (76.1 %)** |

Four areas that had no rule at all are now covered: debug output left in a response
(Xdebug, Symfony VarDumper, ASP.NET trace viewer, Node.js inspector), cookie attribute
contracts (misspelt names, public-suffix `Domain`, `Partitioned` without `Secure`),
policies delivered through a `meta` element (where `frame-ancestors` is ignored), and host
/ frame disclosure. Every rule was checked against every existing rule's positive
observations before it was written; none of the 14 is a restatement, and the overlap gate
did not move. Full method: `docs/DAST_APP_SURFACE_BATCH_2_2026-10-21.md`.

The ceiling has not moved: 73 rules remain unreachable until the App forwards their
headers, so the next honest tranche is body evidence plus the 11 forwarded names — not
another header family that the product cannot see.

---

## Appendix 4 — 2026-10-21 (app-surface batch 3, DAST 306 → 325)

| Item | Appendix 3 | Now |
|---|---|---|
| DAST rules | 306 | **325** |
| Patterns / records / remediation | 1 353 each | **1 372 each** |
| Declared DAST tests | 1 478 | **1 554** (+76) |
| DAST evaluation cases | 558 | **579** (+21) |
| `run-eval` true positives | 1 379 | **1 398** |
| Distance to the 500 target | 194 | **175** |
| Rules evaluable inside the App | 233 of 306 (76.1 %) | **252 of 325 (77.5 %)** |

This tranche added no header-reading rule at all: markup trust decisions (`data:` anchor,
cross-origin script without an integrity hash, `target="_blank"` without `rel=noopener`),
credential-form placement (third-party password `action`, `GET` password form), secrets
that exist only as text (Django `SECRET_KEY`, GCP service-account JSON, Kubernetes
`Secret` manifest, Stripe live key, unsigned JWT, incoming webhook URL), deployment
artefacts and diagnostics (`.DS_Store`, `.htaccess`, Redis `INFO`, webpack dev client, JSON
stack field, internal address with port, presigned object URL) and one cookie lifetime
(`Expires` beyond the 400-day cap, the attribute form of DPK-DAST-281).

Five candidates were dropped instead of ledgered because their evidence was a strict
subset of an existing rule's positive fixture, or because the ReDoS lint rejected the
pattern. That is the honest cost of not padding: the three dropped evidence-subset
families are still only visible through a neighbouring rule. Full method:
`docs/DAST_APP_SURFACE_BATCH_3_2026-10-21.md`.

The ceiling still has not moved: the same 73 rules remain unreachable until the App
forwards their headers, so the remaining 175 rules cannot come from header families the
product cannot see. What would close the distance: (1) more body evidence that does not
restate an existing rule, and (2) an owner decision to widen the 11-header allowlist in
`apps/api/src/scans/dast/{rules,engine}.ts`, which is worth 47 further headers and the 73
rules behind them.

---

## Appendix 5 — 2026-10-21 (app-surface batch 4, DAST 325 → 367)

| Item | Appendix 4 | Now |
|---|---|---|
| DAST rules | 325 | **367** |
| Patterns / records / remediation | 1 372 each | **1 414 each** |
| Declared DAST tests | 1 554 | **1 722** (+168) |
| DAST evaluation cases | 579 | **623** (+44) |
| `run-eval` true positives | 1 398 | **1 440** |
| Distance to the 500 target | 175 | **133** |
| Rules evaluable inside the App | 252 of 325 (77.5 %) | **294 of 367 (80.1 %)** |

The largest single tranche since the capability-aligned pump, built from the same reading of
the App: 21 administrative-console fingerprints, 9 framework debug surfaces, 8 served
artefacts, 2 markup rules that complement the plaintext `base`/`meta refresh` rules, and 2
cookie `Domain` contracts. Every rule reads the body or `Set-Cookie`, so the unreachable set
did not move: 73 rules across 47 filtered headers remain frozen.

Honest characterisation: the console family is breadth inside one existing class, not a new
class. The batch raises the number of distinct interfaces the pack recognises; it does not
raise the semantic ceiling, which is fixed by the seven closed check types.

The remaining 133 rules and their family-by-family candidates are recorded in
`docs/DAST_500_GAP_PLAN_2026-10-21.md`. That plan states the one thing this appendix has
said at every step: the *reachable* count cannot approach the *declared* count until the
owner widens `ALLOWED_RESPONSE_HEADERS` in `apps/api/src/scans/dast/rules.ts`, because 73
rules already need headers the App filters out before evaluation.

---

## Appendix 6 — 2026-10-21 (app-surface batch 5, DAST 367 → 398)

| Item | Appendix 5 | Now |
|---|---|---|
| DAST rules | 367 | **398** |
| Patterns / records / remediation | 1 414 each | **1 445 each** |
| Declared DAST tests | 1 722 | **1 846** (+124) |
| DAST evaluation cases | 623 | **656** (+33) |
| `run-eval` true positives | 1 440 | **1 471** |
| Distance to the 500 target | 133 | **102** |
| Rules evaluable inside the App | 294 of 367 (80.1 %) | **325 of 398 (81.7 %)** |

This batch is entirely body evidence: framework development surfaces (Django Debug
Toolbar, Flask Debug Toolbar, Rails web-console, Next.js development build, Nuxt DevTools,
Astro toolbar), two development consoles (Quarkus Dev UI, Spring Boot Admin), twelve
orchestration and data-platform consoles, the dependency-lockfile family, and four served
runtime files. Because nothing reads a header, the 73 header-blocked rules are untouched and
the reachable share rises only because the denominator grew with reachable rules.

The 102 rules that remain, and the families they can come from, are in
`docs/DAST_500_GAP_PLAN_2026-10-21.md`. The one honest statement that has not changed: the
*reachable* count cannot approach the *declared* count until the owner widens
`ALLOWED_RESPONSE_HEADERS` in `apps/api/src/scans/dast/rules.ts`, because 73 rules already
need headers the App filters out before evaluation.
