# DAST actionable findings and capability audit — 2026-10-20

**Scope:** `mdraselislam0101-design/Drobon-Dataset`, branch `arena/a4caaeb8-drobon-dataset`,
HEAD `ed599c654e972cf517331bb504d65f3e8c2dbcf1`. Dataset only. The Main App
(`mdraselislam0101-design/Drobon`) was read, never modified.

**Object of this pump:** make DAST intelligence as complete and as *actionable* as the
existing App scanner can actually execute, and establish — from source, not from
assumptions — what a DAST detection can and cannot become as a structured finding.

**Verdicts (independent dimensions):**

| Dimension | Verdict | Basis |
|---|---|---|
| Dataset content completion | **PARTIAL** | 263 / 500 rules; every remaining family within the closed contract is either already represented or rejected on evidence (§4, §12) |
| 500-rule coverage goal | **NOT MET — 263 / 500 (52.6 %)** | unchanged this pump; no candidate survived the acceptance bar (§3) |
| Publication readiness | **NO-GO** | no licence, rights unresolved, owner decisions open (§10, §13) |
| App runtime integration | **NOT VERIFIED** | static contracts only; no App execution was performed (§11) |

No git write of any kind was performed (§14).

---

## 1. Repository state

| Item | Value |
|---|---|
| Branch | `arena/a4caaeb8-drobon-dataset` |
| HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged) |
| `LICENSE` | absent (invariant preserved) |
| `docs/OWNER_DECISIONS.json` | untouched — 5 decisions, `ORIGINAL_CONTENT = APPROVED`, four `OWNER_DECISION_REQUIRED` |
| Worktree at pump start | 3,072 untracked / 2,461 modified (5,533 entries) |
| Worktree at pump end | 3,073 untracked / 2,495 modified (5,568 entries) — the new untracked entry is this report |

The 2,461-entry modified set is pre-existing (carried from earlier pumps) and was preserved.
This pump modified only files under `data/asset-cells/`, plus the generated
`packs/dast/v1/rules/`, `knowledge/patterns|records|remediation/` trees that
`scripts/generate-assets.mjs` rewrites, plus this report. Nothing was deleted, renamed,
retired or reset.

## 2. Starting and ending counts

Counts are from `ls` / `docs/CURRENT_INVENTORY.json`, not from generator stdout.

| Asset | Start | End | Delta |
|---|---|---|---|
| DAST rules | 263 | **263** | 0 |
| Pack rules (DAST + SAST + Secrets) | 1,310 | **1,310** | 0 |
| Patterns / records / remediations | 1,310 each | **1,310 each** | 0 |
| CWE entries | 68 | **68** | 0 |
| Eval cases | 1,610 | **1,610** | 0 |
| DAST eval cases | 509 | **509** | 0 |
| DAST rule `tests` entries | 1,274 | **1,292** | **+18** |
| DAST rules with ≥ 6 tests | 56 | **65** | +9 |
| DAST remediations with ≥ 2 actions | 248 | **258** | **+10** |
| DAST rules whose remediation carries an Immediate / Durable / Trade-off structure | 0 | **24** | +24 |

The rule count did not move because no candidate detection passed the acceptance bar (§3).
What moved is evidence quality: boundary and negative cases, and remediation depth.

## 3. Candidates: accepted, rejected, deduplicated

**33 composed candidates were evaluated; 0 were accepted as new detections; 0 IDs were
consumed.** Every candidate was checked for observable signal, equivalence with the 263
existing rules, semantic distinctness, and whether the closed check vocabulary could
express it. Rejections fall into five classes:

| Reason | Count | Candidates |
|---|---|---|
| Duplicate of an existing rule | 11 | `body-policy-duplicate-directive` (=266), `body-grafana-ui` (=166), `header-object-src-missing` (=075), `header-origin-empty` (=194), `body-laravel-debug` (=109, 231), `header-samesite-invalid` (=159), `body-django-debug` (=052), `header-xss-protection` (=259), `body-python-http-listing` (=081), `body-spark-ui` (=182), `body-solr-admin` (=180) |
| Already rejected in the previous pump — not re-proposed | 6 | `cors-expose-headers-forbidden`, `location-backslash`, `location-empty`, `cors-allow-methods-empty`, `body-htaccess-served`, `body-composer-json-served` |
| Management-console fingerprint (rejected corpus-wide on 2026-10-20 §4 for being volume, not capability) | 5 | `body-gitlab-ui`, `body-mailhog-ui`, `body-flink-dashboard`, `body-trino-ui`, `body-kyverno-ui` |
| Semantically wrong or benign | 8 | `body-csp-strict-dynamic-nonce` (that is the *hardened* form), `body-technical-docs-list` (an ordinary docs page), `cors-partitioned-allow-origin` (token has no meaning in that header; 143/194 already cover non-origin values), `header-source-map` (a JSON content type has no source-map semantics), `header-refresh-url` (fires on `url=/login`), `header-cache-public-credentials` (contradictory but harmless; 251 covers the material case), `body-xmlrpc-pingback` (normal WordPress advertisement), `body-jwt-none-token` (pattern matches *any* compact JWT — a false-positive generator) |
| Not expressible under the closed contract, or not verifiable | 3 | `header-wildcard-credentials` (needs `Access-Control-Allow-Origin` **and** `Access-Control-Allow-Credentials` together — a correlation the single-header check cannot make), `body-weak-jwt` (cannot distinguish an issued unsigned token from a documentation example in one body), `cors-expose-headers-empty` (empty-value family already rejected as evidence-free) |

Three candidates deserve their rejection recorded verbatim, because each looked plausible:

- `header-wildcard-credentials` is the canonical CORS misconfiguration, and the Dataset
  **cannot** detect it: `response-header-matches` sees one header. Emitting it from the
  `Access-Control-Allow-Origin` value alone would report `*` as "wildcard with credentials"
  on every public API, which is exactly the fabricated-correlation failure the contract
  forbids. It stays a **documented capability gap** (§4, row D), not a rule.
- `location-backslash` reproduces the same defect class as `DPK-DAST-050`, whose scope is
  frozen by owner decision **OD-1** (`BLOCKED_PENDING_OWNER_DECISION`). Adding a second rule
  with the same unresolved form-versus-destination ambiguity would multiply the open
  decision instead of closing it.
- The five console fingerprints were rejected one pump earlier on the record
  ("a page marker cannot distinguish an exposed console from a public product page; the
  decision is already represented 25 times"). Re-adding them under a new date would be
  padding with extra steps.

**Deduplicated:** 0 new overlaps. The canonical gate reports the same 332 checks /
128 subset pairs (123 expected absence, 5 reviewed) as before the pump — the test additions
introduced no new pair.

## 4. Category coverage matrix (A–N)

Verdict vocabulary: **SUPPORTED** — the closed contract expresses the capability and the
corpus exercises it; **PARTIALLY_SUPPORTED** — expressible for some observable subset, with
a named limit; **UNSUPPORTED** — not expressible; **NOT_ASSESSED** — no Dataset artefact
claims it, and nothing was tested.

| # | Category | Verdict | What the contract actually permits | Missing requirement |
|---|---|---|---|---|
| A | Headers / CSP | **SUPPORTED** | Absence (`missing-response-header`), directive absence (`response-header-missing-directive`), value shape including duplicate directives and wildcard sources (`response-header-matches`) — 84 rules over CSP and security headers | Multi-header policy evaluation, report-only vs enforcing correlation, browser enforcement evidence |
| B | Cookies / session | **PARTIALLY_SUPPORTED** | Flag absence on cookies that would actually be stored (`cookie-missing-flag`, Set-Cookie parsing incl. `SameSite=None` without `Secure` being discarded), plus attribute-validity rules (11) | No session lifecycle, no rotation-on-login, no fixation test, no way to know a cookie *is* a session cookie |
| C | TLS / transport | **PARTIALLY_SUPPORTED** | `http-url`, HSTS presence/value, plaintext redirect targets, secure-cookie-over-HTTP, Alt-Svc cleartext (14 rules) | No handshake: certificate, protocol version, cipher suites and key exchange cannot be observed from an HTTP response and are explicitly out of scope |
| D | CORS | **PARTIALLY_SUPPORTED** | Single-header value checks: wildcard, `null`, wildcard-in-origin, non-bare origin, userinfo, multiple origins, bad `Max-Age`, wildcard methods, `TRACE` in methods (15 rules) | No `ACAO`+`ACAC` correlation, no `Origin` reflection test, no preflight (`OPTIONS`) evidence — therefore **no exploitability claim from a CORS header is possible** |
| E | Redirects | **PARTIALLY_SUPPORTED** | Host-differs on 3xx (`response-header-host-differs`), scheme downgrade, protocol-relative, `Refresh` variants (7 rules) | No redirect-chain following, no destination-policy model, so open-redirect exploitability is not asserted |
| F | Information disclosure | **SUPPORTED** | 62 rules: banners, framework versions, debug/error pages, served secrets, source-map references | Cannot distinguish "returned by this URL" from "returned to an unauthorised caller" |
| G | Sensitive endpoints / resources | **PARTIALLY_SUPPORTED** | Body-marker detection of served files, consoles and status pages | No path enumeration, no authorisation check; "disclosed" means *content returned*, never *access granted* |
| H | Methods / content types / response semantics | **PARTIALLY_SUPPORTED** | `Allow` advertisement, `Content-Type`/charset rules, multipart boundary | The method itself cannot be exercised (advertisement ≠ reachability); status-code semantics cannot be judged without an expected policy |
| I | Injection indicators | **UNSUPPORTED** | Nothing | Requires payload injection and reflection/differential analysis — active testing the Dataset does not perform; generic error text is never treated as injection evidence |
| J | Auth / authz / session management | **UNSUPPORTED** | Nothing | Requires credentials, roles, an expected-authorization model and multi-step flows |
| K | API security | **PARTIALLY_SUPPORTED** | Served OpenAPI/GraphQL-introspection markers, CORS header values, content-type rules | No schema-driven testing, no per-endpoint authorization, no rate-limit observation |
| L | Browser-side controls | **PARTIALLY_SUPPORTED** | Static CSP, `Referrer-Policy`, `X-Frame-Options`, COOP/COEP/CORP, Permissions-Policy values | No DOM execution, no clickjacking proof, no frame-busting behaviour |
| M | Stateful / multi-step | **UNSUPPORTED** | Nothing | The model is one request → one response |
| N | Standards alignment | **PARTIALLY_SUPPORTED** | CWE-68 mapping on all 263 rules; DROBON category taxonomy | No OWASP Top-10 / ASVS field exists in the rule schema; no coverage record per standard |

**Reading the matrix.** Nine of fourteen categories are reachable in some form; three
(I, J, M) are impossible under the closed model, and two (H, N) are limited by information
the observation does not carry. The 263 rules concentrate where the contract is strongest:
`response-body-matches` 101 and `response-header-matches` 133 rules.

## 5. Finding-evidence and source-line audit

**The question:** can a validated DAST detection become a `drobon.finding.evidence/v1`
record?

**The answer: partially, and never with a source location.**

`scripts/finding-evidence.mjs` builds a record from `extractEvidence(sourceText, spec)`,
which requires real source text plus an exact span inside it, and computes
`findingId = FIND-<sha256(ruleId, path, normalizedSpan)[:16]>`. A DAST observation has no
source text. Calling `extractEvidence` on a response body or header block would manufacture
a "source file" that does not exist, and deriving `location.lineFrom` from a byte offset in
a header would be equally fabricated. Both were therefore **not attempted**.

What the Dataset can legitimately supply, using the rule as the evidence source:

| Evidence field | DAST value | Status |
|---|---|---|
| `ruleId` / rule title | from `packs/dast/v1/rules/DPK-DAST-*.json` | available |
| Location | **runtime only**: request URL, method, response status, header name or body span in the *observation* | available, must be labelled runtime |
| Matched evidence | the offending header value or the matched body excerpt, redacted for secrets/tokens/PII | available (bounded excerpt) |
| `analysis.method` | `observation` | available |
| Severity / CWE | from the rule (`severity`, `cwe`) | available |
| Confidence | `SHAPE_MATCH` with the mandatory uncertainty text | available |
| `dataFlowEvidence` / `callChainEvidence` | `NOT_ASSESSED` (forced by the contract) | available |
| CVSS | absent by design | available (absent) |
| `verification.state` | `UNVERIFIED` — the Dataset cannot replay a probe | available |
| Remediation | `knowledge/remediation/<ruleId>.json` | available |
| Source file + line | **unavailable, and must stay unavailable** | correctly absent |
| `findingId` | **not derivable** — the identity function hashes a *source* span | **contract amendment required** |

Three consequences are recorded as findings rather than worked around:

1. **Identity.** `findingId` is defined over `(ruleId, path, normalizedSpan)` where path and
   span are source artefacts. A DAST finding has no such pair. The honest options are
   (a) an owner decision extending the identity function with a runtime-location variant, or
   (b) the App computing identity in its own layer. Neither is a Dataset change, and neither
   was made.
2. **Rename semantics.** The contract says a renamed file turns an open finding into
   `NOT_OBSERVED_UNVERIFIED`. A DAST URL that 404s later is the same situation; the
   `classifyTransition` path already yields that state for source-less disappearance, so the
   semantics fit — the identifier does not.
3. **No exploitability, no verification.** `SHAPE_MATCH` plus `UNVERIFIED` is the correct
   ceiling: a header value cannot prove an attack, and verification needs a rescan the
   Dataset does not perform.

A separate hardening observation, **not** an active defect: `normalizeHeaders()` in
`scripts/validate-packs.mjs` passes non-string header values through unchanged, so a
non-string value would make `.split`/`.test` throw at evaluation time. No current pack rule
supplies one (exactly one array-valued header exists, in `DPK-DAST-096`), so this is a
loader-side robustness note, not a false positive or false negative in the corpus.

## 6. Rule / pattern / record / remediation quality audit

| Surface | Finding |
|---|---|
| Rule keys | exactly the 12 closed keys; `DAST_ALLOWED` = 8 required + `cwe, check, tests, patternRefs`; no rule carries an evidence or runtime-location field |
| `tests` | 1,292 (582 positive / 710 negative); 165 rules have the 4-test minimum, 65 have ≥ 6 after this pump; `MAX_TESTS` 50 |
| Multi-value headers | 11 tests now use array-valued headers (was 1). This is the only way the evaluator's "present but every value empty" and "duplicate directive" branches can be exercised; before this pump those branches were untested at corpus level |
| `limitation` | 220 / 263 state a limit explicitly; the remaining 43 describe scope rather than a limit |
| Patterns | 263 `drobon.knowledge.pattern/v1`, `origin: original-authored`, `validationStatus: VALIDATED`, 2–8 examples each |
| Records | 263 `drobon.knowledge.record/v1`; 7 descriptions under 100 characters — thin but not misleading |
| Remediation assets | 1,310 files; DAST 263. **258 now carry ≥ 2 actions** (was 248). 24 rules carry an Immediate / Durable / Trade-off structure with a verification step. Five remain single-action: `DPK-DAST-040` ("no action needed" — the header is deprecated, an honest actionless answer), `DPK-DAST-045/046/047` (one line that names the exact required value), and `DPK-DAST-050` (frozen by OD-1) |
| Short remediations (< 60 chars) | **1** (`DPK-DAST-050`, 45 chars, OD-1). Was 16 at the start of the previous pump; 15 were rewritten in the cell definitions (`data/asset-cells/*.json`), not in generated JSON, so regeneration reproduces them |
| Class-level upgrade used | `server-version`, `banner-more`, `cors-open`, `http-methods`, `header-weak-script`, `cache-no-store`, `cors-null-origin`, `csp-directive-gap`, `csp-unsafe-eval`, `debug-token-header`, `filesystem-path-disclosed`, `referrer-unsafe-url`, `sourcemap-reference`, `header-missing-2`. 13 cells carry per-cell `overrides`; those rules kept their existing bespoke text (verified: `DPK-DAST-021`, `-022`, `-039`, `-075`, `-087` unchanged), which is why 37 classes were targeted and 24 rules show the new structure |
| Technology-specific guidance | only where the technology is named by the rule itself (PHP `expose_php`, nginx `server_tokens`, Apache `ServerTokens`, Symfony `web_profiler`, Varnish `vcl_deliver`, ASP.NET `enableVersionHeader`). No invented file names, versions or vendor settings |
| Generic advice | labelled generic where it is generic ("strengthen the value to the recommended form recorded for this header"), never dressed as a specific fix |

## 7. Positive / negative / boundary evaluation

Every rule's fixtures run through `evalDastCheck` in `scripts/validate-packs.mjs`
(`validatePackFile` compares each fixture's declared `match` with the evaluator's verdict;
1,313 files, 0 errors) and through `scripts/test-packs.mjs` (5,422 / 5,422 passed).

That the added cases are genuinely executed — not merely stored — was proved by flipping the
expectation of one added fixture in memory: `validatePackFile` then returns
`tests[#4]: expected match=true but check says false`. No repository file was modified for
this check.

The 18 added cases were chosen because they exercise evaluator branches that the corpus did
not previously reach, and each is a *documented* behaviour rather than a new detection:

| Rule | Added behaviour | Why it matters |
|---|---|---|
| `-002` | CSP as a 2-element array, one element empty, one whitespace | Proves `missing-response-header` treats "all values empty after OWS trim" as missing — previously only single string values were tested |
| `-003` | HSTS as an array `["includeSubDomains","max-age=31536000"]` | Proves a directive split across array elements is still found (joins on `[;,]`) |
| `-004`, `-006` | Two cookies, one flagged and one not; all-flagged negative | Proves the cookie flag check is per-cookie, not per-response |
| `-010` | CSP array where one element lacks `frame-ancestors` | Proves directive lookup across array elements |
| `-057` | `public, x-no-store` (token boundary) vs `NO-STORE` (case) | Proves `no-store` is matched as a directive token, case-insensitively |
| `-058` | `https://null.example` (not the token) vs `" NULL "` | Proves `null` is matched as a value, not a substring |
| `-063` | Whitespace-only value vs array `["", "a1b2c3"]` | Proves "present but blank" and "populated through an array" differ |
| `-065` | `/var/www/app/config.php` positive, `/home/user/notes.txt` negative | Proves the path pattern requires a server-looking root, not any absolute-looking path |

Boundary and malformed coverage that already existed and was re-verified (spot check with the
real evaluator, 18/18 matching expectations): empty header value treated as missing;
`SameSite=None` without `Secure` not stored; path-disclosure regex excluding `README.md`;
duplicate-directive detection tolerating a `script-src` token inside a `report-uri` value.

## 8. False positives, false negatives, unassessed

| Metric | Value | Change |
|---|---|---|
| Eval true positives | 1,336 | 0 |
| Eval false negatives | 0 | 0 |
| Eval false positives | 1 | 0 |
| Assessed cases | 1,599 of 1,610 | 0 |
| UNASSESSED | 11 (`EVAL-CMD-023/024/025`, `EVAL-SAST-004/007/014/015/016`, `EVAL-SEC-111`, `EVAL-SQL-027/028`) | preserved |
| `EVAL-SAST-008` | FAIL | preserved (must stay FAIL) |
| Benign-page regression | the 9 rules that gained tests were re-run against a 4-page control-present corpus (sign-in page, marketing page, JSON API response, documentation page). 35 rule/page pairs where the control is present: **0 unexpected hits**. Pages that legitimately lack a control were excluded from the benign set, because a hit there is the rule's own true positive | no regression; no assertion weakened |

No assertion, `groundTruth`, `forbiddenDetections`, threshold or expectation was weakened,
skipped or deleted. The one known false positive and the eleven unassessed cases remain
exactly as they were.

## 9. Commands and exit codes

All run from the repository root on the final tree.

| Command | Exit | Result |
|---|---|---|
| `npm test` | **0** | 22,302 `ok`; determinism 5/5; tree digest reproducible |
| `node scripts/validate-packs.mjs packs` | 0 | PASS (1,313 files, 0 errors) |
| `node scripts/validate-assets.mjs` | 0 | PASS (2,620 files, 0 errors) |
| `node scripts/validate-cwe.mjs knowledge/cwe` | 0 | PASS (68 files) |
| `node scripts/validate-corpus.mjs` | 0 | PASS (3 files, totals 2,799) |
| `node scripts/validate-matrix.mjs docs/REQUIREMENTS_MATRIX.json` | 0 | PASS (inventory recomputed, no licence file) |
| `node scripts/validate-dast-overlaps.mjs` | 0 | PASS — 332 checks, 128 subset pairs (123 expected absence, 5 reviewed) |
| `node scripts/test-eval.mjs` | 0 | 43 / 43 |
| `node scripts/eval-coverage-report.mjs` | 0 | 1,310 / 1,310 rules exercised |
| `node scripts/validate-capability-coverage.mjs` | 0 | 695 / 695 |
| `node scripts/run-eval.mjs` | 0 | 1,610 cases, 1,599 assessed, 11 UNASSESSED; TP 1,336 / FN 0 / FP 1 |
| `node scripts/generate-assets.mjs` | 0 | 5,195 written, 0 removed, 0 quarantined |

No gate was bypassed, piped into a masking construct, or re-run until green. The generator
was run after every cell edit; its printed file counts are *not* on-disk totals and were not
used as such.

## 10. Provenance, legal and owner blockers

| Blocker | State | Effect |
|---|---|---|
| Licence / rights | no `LICENSE`; `ORIGINAL_CONTENT = APPROVED` only | publication stays **NO-GO**; nothing here grants redistribution rights |
| `docs/OWNER_DECISIONS.json` | 5 decisions, 4 `OWNER_DECISION_REQUIRED` (GHSA/OSV/NVD/CWE) | schema untouched; no decision was fabricated or inferred |
| OD-1 — `DPK-DAST-050` scope | open, `BLOCKED_PENDING_OWNER_DECISION` | the rule stays untouched, including its 45-character remediation |
| Multi-header / multi-response check type | not requested, not created | categories B, D, E, H remain partial by design; nine residual families need it |
| BLK-001…004 | unchanged | still blocked |
| D-13 | inactive | unchanged |
| SCA rights | `RIGHTS_BLOCKED` | unchanged; no vulnerability-intel import, no paid API |
| Provenance of this pump's changes | cell definitions in `data/asset-cells/*.json`, original DROBON wording | no third-party rule text, catalogue structure or remediation text was copied |

## 11. App-side gaps (Dataset cannot close these)

1. **No consumer for `packs/dast`.** The App has eight hard-coded `DG-DAST-001…008` checks in
   `apps/api/src/scans/dast/rules.ts`; the Dataset's 263 rules have no loader. "Structurally
   loadable" is therefore an assessment from static contracts, not a verified integration.
2. **No evidence record for a runtime observation.** The App's finding shape is
   source-span-oriented (§5). Producing a DAST finding with a runtime location and a stable
   identity needs an App-side decision, not a Dataset field.
3. **No rescan linkage.** Verification of a remediation is a scan-over-scan comparison; the
   Dataset supplies `knowledge/remediation` but cannot attest that a fix took effect.
4. **Non-string header values** would throw in the Dataset evaluator; a loader should
   normalise or reject them (§5).

## 12. Remaining legitimate work and exact blockers

| Work | Blocked by |
|---|---|
| Any correlation-based detection (CORS credentials, cache+set-cookie, multi-header policy) | new check type — owner decision; **not** simulable |
| Preflight / `OPTIONS` evidence | an active probe model the Dataset does not have |
| TLS, certificate and cipher findings | handshake data outside the request/response model |
| Session lifecycle, fixation, authorization findings | credentials + expected-policy model + multi-step flows |
| Injection findings | active payload testing; explicitly out of scope |
| Beyond 263 within the closed contract | no candidate survived §3; the residual families are either duplicated, benign, or blocked |
| `DPK-DAST-050` rewrite/retire | OD-1 |
| Remediation for `-040`, `-045`, `-046`, `-047` | they are individually authored legacy rules with correct, terse text; deepening them is a style change, not a correctness fix, and was not justified |
| Publication | licence + owner decisions |

**500 assessed unreachable under the closed contract** without either a new check type
(owner decision) or padding. That conclusion, reached in the previous pump, was re-tested
here with 33 fresh candidates and held: every plausible family ends in duplication,
benignity, or a capability the model does not have.

## 13. Publication verdict

**NO-GO — unchanged.** The technical corpus is internally consistent and all gates pass, but
there is no licence, four owner decisions remain open, and this pump added no rights
evidence. Technical readiness and publication readiness are separate dimensions and are
reported separately.

## 14. Confirmation of repository operations

- No `git add`, `commit`, `push`, `branch`, `tag`, `merge`, `reset --hard`, `clean`, checkout
  or history rewrite was performed.
- No file was deleted, renamed, retired or merged; no permanent ID was created, consumed or
  reused; three previously rejected families were not re-proposed.
- No change was made to the Main App, to the scanner schema, to the closed check-type
  registry, or to any App integration.
- `docs/OWNER_DECISIONS.json` and the absence of `LICENSE` are unchanged.
- Earlier reports, appendices, manifests and audit evidence are untouched; this file is the
  only new report from this pump.

---

## Appendix A — runtime-location finding shape (illustrative, not produced)

The shape below is what a consumer could build from Dataset content **after** an owner
decision on identity. It is deliberately not committed as a record: doing so would create a
finding with a fabricated identity.

```
ruleId        DPK-DAST-033
title         Infrastructure banner disclosed (Via header)
location      { kind: "runtime", url: "https://app.example/", method: "GET", status: 200,
                header: "Via", matchedValue: "1.1 internal-proxy-3" }        # runtime only
evidence      excerpt: "Via: 1.1 internal-proxy-3"  (bounded, redacted)
analysis      { method: "observation", sourceLocation: UNAVAILABLE }
confidence    { level: "SHAPE_MATCH", uncertainty: "The header proves the proxy is declared;
                it does not prove the proxy is reachable or that the hostname resolves." }
severity      LOW          (from the rule)
cwe           CWE-200      (from the rule)
verification  UNVERIFIED
dataFlow      NOT_ASSESSED
remediation   knowledge/remediation/DPK-DAST-033.json  (3 actions + verification)
findingId     NOT DERIVABLE — requires a runtime-location identity variant (owner decision)
```

## Appendix B — how to reproduce this report

```
node scripts/generate-assets.mjs
node scripts/validate-packs.mjs packs
node scripts/validate-assets.mjs
node scripts/validate-dast-overlaps.mjs
npm test
node scripts/run-eval.mjs
```

Expected: exit 0 for every command; 22,302 `ok` in `npm test`; 1,336 / 0 / 1 in `run-eval`;
263 DAST rules, 1,310 pack rules, 1,292 DAST tests.
