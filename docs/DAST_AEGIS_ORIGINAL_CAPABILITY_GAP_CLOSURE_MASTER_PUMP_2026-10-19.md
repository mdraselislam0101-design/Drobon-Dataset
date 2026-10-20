# DROBON AEGIS — Original Capability Gap-Closure Master Pump

**Date:** 2026-10-19
**Branch:** `arena/a4caaeb8-drobon-dataset`
**Baseline commit:** `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged at the end of this pump)
**Scope:** Dataset repository only. The Main App was read, never written.
**Verdict:** **NO-GO** (reasons in §9). This pump closes two gaps and does not, and cannot, close the release gates.

This report is a new file. No earlier report was edited, moved or deleted. It is cumulative with
`docs/DAST_CUMULATIVE_MASTER_PUMP_2026-10-19.md`,
`docs/DAST_CUMULATIVE_MASTER_PUMP_ITER2_2026-10-19.md` and
`docs/DAST_CUMULATIVE_GAP_CLOSURE_MASTER_PUMP_2026-10-19.md`, and it supersedes none of them.

---

## 1. What this pump was asked to do

Build DROBON's own missing security-intelligence capability cumulatively and in place: keep working
components, repair defective ones, and where a capability is genuinely absent, create an original
algorithm, evaluator, evidence model and regression suite for it — not a cosmetic tweak to an old
rule. A gap is built only after it is confirmed from the repository, the code, the fixtures and a
failing or missing behaviour, and every change must be executable, evidence-backed and reversible
in meaning.

## 2. Git state

| Point | Value |
|---|---|
| HEAD at start | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` |
| HEAD at end | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (no commit, no push, no branch change) |
| `git status --porcelain` (end) | 2,376 modified, 1,999 untracked (`--untracked-files=all`) |
| Working tree | carries the accumulated uncommitted work of this and all earlier pumps; nothing was reverted, cleaned or checked out |

The baseline status counts included the same two populations at the start of the pump; the delta of
this pump is the files in §6. No `git reset`, `git clean`, restore or deletion was run.

## 3. Confirmed gap inventory

### 3.1 Gap A — CSP rules evaluated header *text*, not header *meaning*

| Field | Content |
|---|---|
| Need | Decide CSP questions (`unsafe-inline` excepted by nonce, shadowed duplicates, fetch-directive fallback, `script-src` vs `script-src-elem`) the way a user agent decides them. |
| Current behaviour (before) | Every CSP rule was a regex over the raw header. `unsafe-inline` anywhere counted, including `img-src`; a wildcard inside a duplicate, ignored directive counted; `script-src(?=\s)` matched `script-src-elem`/`-attr`; `object-src` absence was reported even when `default-src` supplied the fallback; `unsafe-eval` counted in `style-src` and in a `default-src` that `script-src` overrode. |
| Evidence | Probes recorded in the session log; the differential gate's first run failed 3,496/3,705 against the oracle, and after the first repair pass still failed on the shadowed-duplicate and `script-src-elem` shapes. |
| Impact | False positives (protected policies reported) and false negatives (`unsafe-inline` scoped to a non-script directive was not the question the rule claimed to answer) across 9 rules, 3 of them carrying eval cases. |
| Repair sufficient? | No. A regex cannot express first-wins duplicates, comma-separated policy intersection or the fallback chain. |
| Why a new component | The semantics are a grammar, not a string shape: policies, directives, source lists, inheritance and shadowing. Any regex fix would move the same defect around. |
| Proposed original design | `scripts/lib/csp.mjs`: split on `,` (policies), `;` (directives), parse `name source…`, keep the **first** occurrence of a directive name, classify fetch vs non-fetch directives, inherit fetch directives from `default-src`, and expose header-level predicates used by both the rules and the test oracle. |
| I/O and failure behaviour | Input: a header value (or the header list). Output: policy tree and boolean predicates. Invalid input never throws: unknown directive names are kept, a segment whose first token is not a directive name is dropped, an absent header returns "no policy". |
| FP/FN risk | FP: a directive the parser drops is then invisible (mitigated: only malformed segments drop, and the gate pins it). FN: multi-policy intersection cannot be seen through a single-value regex; pinned in suite E. |
| Required tests | Grammar units, predicate units, curated rule rows, generated policies, limitation pins. |
| Provenance / rights | CSP Level 3 behaviour is a public standard; the parser, predicates, names and tests are DROBON-authored. No third-party implementation, rule text or corpus was consulted. |
| Status | **IMPLEMENTED_AND_VERIFIED**, with one pinned limitation. |
| Residual risk | Comma-separated policy lists are enforced as an intersection; a single-value regex sees the union. Nine rules stay conservative; the disagreement is asserted, not hidden. |

### 3.2 Gap B — Set-Cookie flags were read as keywords, not attributes

| Field | Content |
|---|---|
| Need | Decide whether a response establishes a cookie with `Secure`, `HttpOnly` and `SameSite`, per HTTP state management rules. |
| Current behaviour (before) | `cookieHasFlag` split on `;`, trimmed, and compared the whole token. Correct for padding, wrong for flag attributes that carry a value and for headers a user agent discards. |
| Evidence | Direct probes through `evalDastCheck`: `id=1; Secure=0` → rule 004 fired (FP), `id=1; HttpOnly=1` → rule 006 fired (FP), `SessionToken` (no `=`) → rules 004/006/008 fired although no cookie is stored (FP). |
| Impact | Three rules, one of them (`SameSite`) also sensitive to whether an ignored value counts as the attribute. |
| Repair sufficient? | No. "Attribute identity", "flag value is ignored", "last duplicate wins" and "discard the whole header" are model decisions; a token comparison cannot express them. |
| Why a new component | The same parsing is needed by any future cookie question (prefix rules, expiry, `SameSite=None` without `Secure`), and it must be testable independently of the rules. |
| Proposed original design | `scripts/lib/set-cookie.mjs`: `parseSetCookie` returns `{ok,name,value,attributes,flags,sameSite,evidence}`; quoted spans are not split; attribute names are lower-cased; duplicates resolve last-wins; flag attributes ignore their value; `SameSite` resolves `declared`/`unrecognised`/`absent`; discard reasons are explicit (`empty`, `control-character`, `no-name-value-pair`, `not-a-string`). |
| I/O and failure behaviour | Input: one header value string. Output: model or `{ok:false,reason}`. Discarded headers store nothing, so the rules do not report them. |
| FP/FN risk | FP removed: `Secure=0`, `HttpOnly=1`. New FN risk: a discarded header is no longer reported by these rules (it is an application defect, but not evidence of an unprotected cookie); pinned by an eval case and asserted in the gate. |
| Required tests | Parser units, predicate units, curated rule rows, generated model→text→parse→rule pairs, limitation pins. |
| Provenance / rights | RFC 6265 §5.2/§5.3 behaviour is a public standards fact. Parser design, predicate names and tests are DROBON's own. |
| Status | **IMPLEMENTED_AND_VERIFIED**, with pinned limitations. |
| Residual risk | One header value is one cookie (folded multi-cookie values are not un-folded). Cookie-prefix enforcement (`__Secure-`, `__Host-`) is browser policy and is deliberately not modelled. |

### 3.3 Remaining gaps (confirmed, not closed this pump)

| # | Capability | Status | Confirmed by | Blocking reason / next step |
|---|---|---|---|---|
| G1 | Redirect validation and URL normalisation | **PARTIALLY_IMPLEMENTED** | `DPK-DAST-056` compares hostnames; `DPK-DAST-050` still uses `^//` and fires on same-host scheme-relative redirects | `DPK-DAST-050` is a permanent id; retire/rewrite needs owner approval. `OWNER_DECISION_BLOCKED`. |
| G2 | Cross-header correlation | **OWNER_DECISION_BLOCKED** | Evaluator reads one observation; proposals `docs/DAST_CHECK_TYPE_EXTENSION_PROPOSAL.md` and `docs/DAST_CORRELATION_EXTENSION_PROPOSAL.md` | No vocabulary entry, no schema change without owner approval; not simulated. |
| G3 | Request/response pair analysis | **OWNER_DECISION_BLOCKED** | Same evaluator signature; no request model in the schema | Same decision gate. |
| G4 | MIME / media-type and content-context checks | **PARTIALLY_IMPLEMENTED** | `contentType` is validated and reserved; no v1 check reads it; `X-Content-Type-Options` rules exist | Needs a check-type proposal (new vocabulary entry) → owner decision. |
| G5 | Empty / invalid header values | **IMPLEMENTED_AND_VERIFIED** (Batch 12) | `missing-response-header` treats an all-empty header as missing; regression rows in `test-packs` | — |
| G6 | Secrets contextual validation | **PARTIALLY_IMPLEMENTED** | 97 secrets rules with candidate/veto model; veto behaviour deliberately conservative | Evidence-gated backlog (unquoted assignments, ADO `Password=`); no owner gate. |
| G7 | SCA dependency identity and relationship model | **MISSING_CAPABILITY / OWNER_DECISION_BLOCKED** | 0 SCA packs; no advisory data; Main App runs `VULN_INTEL_PROVIDER=none` with a Null provider | Building matching without lawful advisory data would fabricate intelligence. Design doc only, then owner decision. |
| G8 | SAST breadth objective (66 new / 1,000) | **PARTIALLY_IMPLEMENTED** | 950 SAST rules; objective not a quota | Continues across pumps; no padding with duplicates. |
| G9 | Dataset licence / redistribution rights | **RIGHTS_BLOCKED** | No `LICENSE` file by instruction; assets have provenance records but no legal permission | Legal/owner decision. An originality PASS is not a licence. |
| G10 | Main App loader consumption | **NOT_VERIFIED** | The App contains 0 references to Dataset paths | App-side work is read-only for this session. |
| G11 | Severity / confidence reasoning beyond the fixed scale | **PARTIALLY_IMPLEMENTED** | Severity is authored per rule from a closed set; no score is computed | Any CVSS-like score needs version + inputs + basis; not attempted. |
| G12 | Deduplication of rules/patterns/records | **IMPLEMENTED_AND_VERIFIED** | `dedup-report`: 100 files, 84 items, 9 tuples, **0 conflicts** | — |
| G13 | CWE mapping integrity | **IMPLEMENTED_AND_VERIFIED** | `validate-cwe`, `validate-packs`, 63 CWE entries; no unmapped rule | — |
| G14 | Provenance and lineage | **IMPLEMENTED_AND_VERIFIED** (per asset) | Every pattern/record carries provenance; `originality-report --check` PASS; `rules without record 0` | — |
| G15 | Remediation quality | **IMPLEMENTED_AND_VERIFIED** (structure) | 1,138 records carry remediation; evidence and remediation are separate fields | Human review per rule remains open. |

G1–G3 and G7–G10 are the blockers this pump deliberately did not work around. None of them was
simulated, stubbed or faked with a single-header rule.

## 4. What was built

### 4.1 `scripts/lib/csp.mjs` (new)

An original CSP grammar model and header-level predicates:

* `parseCsp(header)` — comma-separated policies, semicolon-separated directives, `name source…`,
  first-wins duplicate directive names, fetch vs non-fetch classification.
* `effectiveSources(policy, directive)` — the directive's sources, or the `default-src` fallback for
  a fetch directive.
* Predicates used by the rules: `headerHasDefaultSrcWildcard`, `headerHasScriptSrcWildcard`,
  `headerHasConnectSrcWildcard`, `headerHasFrameAncestorsWildcard`, `headerScriptAllowsPlaintext`,
  `headerScriptAllowsData`, `headerObjectSrcUnconstrained`, `headerAllowsInlineScripting`,
  `headerAllowsEval`, `headerIsReportOnly`.
* Deliberate non-goals are recorded in the file: nonce/hash *quality* is not judged; report-only
  policies are identified but the rules that do not consult it say so; policy intersection is
  exposed but not silently smoothed over.

### 4.2 `scripts/test-csp-semantics.mjs` (new)

A differential gate, now part of `npm test`:

| Suite | Content | Assertions |
|---|---|---|
| A | parser unit tests (policies, duplicates, malformed segments, unknown directives) | 26 |
| B | predicate tests | 16 |
| C | curated rule-vs-oracle rows | 42 |
| D | generated rule/policy pairs: LCG seed `0x5eed1234`, 400 policies × 9 rules | 3,600 |
| E | pinned multi-policy intersection limitation | 22 |
| **Total** | | **3,706; PASS** |

Suite D generates policies from a declarative model, renders them to header text, then runs the
real evaluator (`evalDastCheck`) and compares against the independent oracle. Rendering is driven by
the model so a shared parser/renderer assumption cannot make both sides agree while both are wrong.

### 4.3 `scripts/lib/set-cookie.mjs` (new)

An original RFC 6265 attribute model:

* `parseSetCookie(raw)` → `{ok, name, value, attributes, flags:{secure,httpOnly}, sameSite:{state,value,effective}, evidence}` or `{ok:false, reason}`.
* Quoted spans are not split; attribute names are lower-cased; unknown attributes are retained with
  `known:false`; duplicates resolve **last-wins** (§5.3); `Secure`/`HttpOnly` ignore their value;
  `SameSite` resolves `declared` / `unrecognised` / `absent`.
* `cookieHasFlag`, `cookieIsDiscarded`, `cookieDiscardReason`.

`scripts/validate-packs.mjs` now delegates the `cookie-missing-flag` branch to this model and skips
headers a user agent would discard.

### 4.4 `scripts/test-cookie-semantics.mjs` (new)

| Suite | Content | Assertions |
|---|---|---|
| A | parser units: identity, last-wins, quoting, discard reasons | 27 |
| B | flag predicates (16 rows) | 16 |
| C | curated rule rows, each also required to exist verbatim in the shipped rule file | 34 |
| D | generated model → header → parse → rule pairs (LCG seed `0x5e7c00c1`, 300 models × rule + round-trip) | 600 |
| E | pinned limitations (folded header, no clock, `SameSite=None` not judged, prefix rules not modelled) | 4 |
| **Total** | | **681; PASS** |

Suite C's "shipped in the rule file" assertion is deliberate: it prevents the gate from drifting
into testing a semantics the rules do not implement.

## 5. Rules changed

Nine CSP rules were re-expressed against the model. Rule ids, CWE mappings and severities were
preserved except where a rule was retyped to say something true.

| Rule | Before | After |
|---|---|---|
| `DPK-DAST-021` `unsafe-inline` | any `unsafe-inline` token anywhere | inline-capable directives only (`script-src*`, `style-src*`, `default-src`), suppressed by a nonce/hash in the same directive, token boundary required |
| `DPK-DAST-022`, `-070`, `-086`, `-092` wildcard | regex could read a shadowed later duplicate | first-occurrence guard: a wildcard in an ignored duplicate no longer counts |
| `DPK-DAST-061` `unsafe-eval` | quoted token anywhere, including `style-src` | `script-src`/`script-src-elem` when declared; otherwise `default-src` — a `script-src` override suppresses the fallback reading |
| `DPK-DAST-093`, `-095` scheme sources | `script-src(?=\s)` also matched `script-src-elem`/`-attr` | directive-name boundary `script-src(?=[\s;]\|$)` |
| `DPK-DAST-075` `object-src` | `response-header-missing-directive` fired even when `default-src` supplied the fallback | retyped `response-header-matches` with a fallback-aware pattern; title "Content-Security-Policy without object-src or default-src" |

Three cookie rules (`DPK-DAST-004`, `-006`, `-008`) changed behaviour through the evaluator, not
through their patterns:

| Rule | Defect removed | Regression evidence |
|---|---|---|
| `-004` | `Secure=0` reported as unprotected | rule test row + `EVAL-DAST-144` |
| `-006` | `HttpOnly=1` reported as unprotected | rule test row + `EVAL-DAST-144` |
| `-004/-006/-008` | a discarded header (`SessionToken`) reported as an unprotected cookie | rule rows + `EVAL-DAST-145` |
| `-008` | (decision) only a recognised `Strict`/`Lax`/`None` value counts as the attribute; an ignored value is not evidence | rule test row `SameSite=` → `true` |

The `-008` decision deserves the note: a user agent ignores an unrecognised `SameSite` value and
applies its own default. That default is browser policy, not a fact carried by this response, and
pre-default browsers do not apply it. The rule therefore keeps reporting the cookie. The previous
test asserting this behaviour was preserved, not weakened.

### 5.1 Two header-semantics defects found while auditing the same family

Reading every rule whose semantics depend on a header *value* surfaced two more defects, both
confirmed with direct evaluator probes before any edit:

| Rule | Confirmed behaviour (before) | Correction | Evidence |
|---|---|---|---|
| `DPK-DAST-024` HSTS `max-age` | `max-age="300"` was not reported. RFC 6797 §6.1 allows only an unquoted delta-seconds, so a quoted value makes the directive unparseable and user agents ignore it: the response has **no** HSTS protection. A false negative. | Pattern gained a quoted branch: any quoted `max-age` value is reported, regardless of the number inside, because the protection is absent rather than short. Unquoted ranges are unchanged. | 3 new rule rows (`"300"`, `"31536000"`, `"86400"; includeSubDomains`), `EVAL-DAST-147` |
| `DPK-DAST-047` COOP | Typed `response-header-missing-directive` with directive `same-origin`: it fired on any value that was not `same-origin`, including `noopener-allow-popups`, a valid cross-origin isolation mode (false positive), and it also fired when the header was absent, duplicating `DPK-DAST-012`. | Retyped to `response-header-matches` over a value-shape pattern: reports `unsafe-none`, `same-origin-allow-popups` and unrecognised tokens; `same-origin` and `noopener-allow-popups` are isolation modes and are not reported; an empty value is left to `DPK-DAST-012`. Title, description, limitation and remediation rewritten (the generated COOP description had inherited unrelated redirect/wildcard text). | 4 rule rows, `EVAL-DAST-146` (negative), and the existing `EVAL-DAST-032`/`-064` still pass |

Both changes are inside the existing seven check types. No id was retired or rescoped. The COOP
retype removes a duplicate trigger rather than creating one: the "header absent" case is now owned
solely by `DPK-DAST-012`.

## 6. Files changed in this pump

| File | Purpose |
|---|---|
| `scripts/lib/csp.mjs` | new — CSP grammar model and predicates |
| `scripts/test-csp-semantics.mjs` | new — CSP differential gate (3,706 assertions) |
| `scripts/lib/set-cookie.mjs` | new — Set-Cookie attribute model |
| `scripts/test-cookie-semantics.mjs` | new — cookie differential gate (681 assertions) |
| `scripts/validate-packs.mjs` | delegate `cookie-missing-flag` to the model; skip discarded headers |
| `data/asset-cells/dast.json`, `dast-3.json`, `dast-5.json`, `dast-10.json`, `dast-11.json`, `dast-12.json` | CSP cell patterns, tests, limitation and title text; `dast.json` also carries the HSTS `max-age` cell |
| `data/asset-cells/dast-2.json` | COOP cell retyped to `response-header-matches` with new tests and authored title/description/limitation/remediation |
| `packs/dast/v1/rules/DPK-DAST-004/-006/-008.json` | legacy hand-authored rule files: limitation text and near-miss test rows |
| generated `knowledge/patterns`, `knowledge/records`, `knowledge/remediation` | regenerated by `node scripts/generate-assets.mjs`; 1,138 / 1,138 / 1,138 |
| `data/eval-cases/EVAL-DAST-082.json` | corrected from positive to negative with the reason recorded |
| `data/eval-cases/EVAL-DAST-140…147.json` | new cases: nonce suppression, duplicate directive, object-src fallback, `style-src` `unsafe-eval`, flag values, discarded header, `noopener-allow-popups`, quoted HSTS `max-age` |
| `scripts/test-eval.mjs` | TP pin 1,161 -> 1,162 for the new positive case |
| `package.json` | `test` chain now runs both semantic gates |
| `docs/PACKS.md` | check-type table row for `cookie-missing-flag`, cookie parsing note, DAST Batch 14 entry |
| `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md` | new "Header semantic models" layer row; refreshed eval and `test-packs` counts |
| `docs/COVERAGE_MAP.json`, `docs/CURRENT_INVENTORY.json`, `docs/CAPABILITY_COVERAGE_MATRIX.md` | machine-regenerated |

No rule id was retired, repurposed or rescoped. No new check type. No schema change.

## 7. Evidence

### 7.1 Commands and results (all run after the last edit)

| Command | Exit | Result |
|---|---|---|
| `node scripts/test-csp-semantics.mjs` | 0 | PASS 3,706/3,706 (42 curated, 3,600 generated) |
| `node scripts/test-cookie-semantics.mjs` | 0 | PASS 681/681 (17 curated, 600 generated) |
| `npm test` | 0 | 19,668 `ok -` lines; `pack-tests` 4,734/4,734; `asset-tests` 9,122/9,122; `eval-tests` 43/43; `doc-drift` 119/119; `current-state` 153/153; determinism 5/5 |
| `node scripts/run-eval.mjs` | 0 (report written) | 1,248 cases, 1,237 assessed, 11 UNASSESSED, TP 1,162, FP 1, FN 0 |
| `node scripts/validate-packs.mjs` | 0 | PASS 1,141 files, 0 errors |
| `node scripts/validate-assets.mjs` | 0 | PASS 2,276 files, 0 errors |
| `node scripts/coverage-report.mjs --check` | 0 | PASS |
| `node scripts/eval-coverage-report.mjs` | 0 | 1,138/1,138 rules (SAST 950/950, secrets 97/97, DAST 91/91) |
| `node scripts/dedup-report.mjs` | 0 | 100 files / 84 items / 9 tuples / **0 conflicts** |
| `node scripts/originality-report.mjs --check` | 0 | rules without record 0, rules without pattern 0, patterns without record 0 |
| `node scripts/test-determinism.mjs` | 0 | 5/5; tree digest `6799a8fa488528f1…` |
| `node scripts/inventory.mjs --check` | 0 | inventory matches the tree |

### 7.2 Evaluation detail

* Baseline for this pump: the case list as committed before the CSP rewrite (1,240 cases).
* Final: **1,248 cases**, 1,237 assessed, 11 UNASSESSED (pinned, zero contribution).
* **TP 1,162 / FP 1 / FN 0.** The single FAIL is `EVAL-SAST-008`, preserved from earlier pumps.
* DAST subset: 91/91 rules exercised, TP 100, FP 0, FN 0.
* New positives this pump: `EVAL-DAST-142` (`object-src` and `default-src` both absent) and
  `EVAL-DAST-147` (quoted HSTS `max-age` is invalid syntax, so no protection applies). The TP pin in
  `test-eval.mjs` moved 1,161 -> 1,162 accordingly; the remaining new cases are negatives.
* Corrected case: `EVAL-DAST-082` was authored as a positive for the old `object-src` defect. It is
  now a negative, and its `purpose` records the correction and the historical expectation. This is
  a genuine semantic correction with regression evidence, not an expectation weakened to pass:
  the positive behaviour it used to assert is now asserted as a false-positive row inside
  `DPK-DAST-075`'s own tests and in the CSP gate.

### 7.3 Count definitions

| Population | Count | Definition |
|---|---:|---|
| Pack rules | 1,138 | 950 SAST + 97 secrets + 91 DAST, one JSON per rule |
| Patterns / records / remediation | 1,138 / 1,138 / 1,138 | one of each per rule (40 legacy recorded separately) |
| `validate-packs` files | 1,141 | 1,138 rules + 3 `pack.json` |
| `validate-assets` files | 2,276 | 1,138 patterns + 1,138 records |
| Eval cases | 1,248 | one JSON per case, 11 UNASSESSED |
| Distinct rules in positive detections | 1,130 | 942 SAST + 97 secrets + 91 DAST |

These are different populations, not conflicting totals.

## 8. Provenance, rights and originality

* No third-party source code, rule text, catalogue structure, private signature database or test
  corpus was copied, adapted or consulted for this pump.
* The behaviour encoded in both models comes from public standards (RFC 6265 §5.2/§5.3; CSP
  Level 3). Those are technical facts; the parser designs, predicate names, failure models,
  regression suites and rule wording are DROBON-authored and marked as such in the file headers.
* No real vulnerability intelligence was added. No CVE/NVD/GHSA/OSV/KEV/EPSS/advisory data, no
  exploit data, no paid API. All fixtures are synthetic, labelled `testOnly`/`synthetic`, and are
  excluded from intelligence counts.
* `docs/OWNER_DECISIONS.json` is unmodified and still validates closed-key (sha256 `a359d3f5…`).
  `D-13` remains inactive.
* **No `LICENSE` file exists.** The repository has provenance and originality evidence, not a legal
  permission to redistribute. `originality-report --check` PASS is a technical check, not a
  licence. The Dataset must not be described as legally exclusive or third-party-free.

## 9. Limitations, risks and open decisions

1. **Multi-policy CSP intersection.** `default-src 'self', default-src *` is enforced as an
   intersection; a single-value regex sees the later wildcard. The model exposes the intersection,
   the rules stay conservative, and the disagreement is pinned in suite E of the CSP gate for
   022/070/086/092. This is a rule-layer limitation, not a claim of correctness.
2. **One header value is one cookie.** A folded multi-cookie value may under-flag. Loaders should
   pass arrays; the limitation is stated on all three cookie rules.
3. **Discarded headers are not reported** by the cookie rules. That is semantically right for this
   rule family, but it leaves a (non-security) application defect undetected by DROBON.
4. **Cookie-prefix enforcement** (`__Secure-`, `__Host-`) is browser policy and is not modelled.
   No rule claims it.
5. **`DPK-DAST-050`** still fires on same-host scheme-relative redirects and is owner-blocked.
6. **Correlation and request/response pairs** remain impossible in the current vocabulary and are
   owner-blocked; nothing in this pump simulates them.
7. **App-loader gate**: the Main App contains no Dataset consumer. Integration is unverified and
   outside this session's write scope.
8. **Rights**: no licence, so redistribution is blocked regardless of technical quality.
9. **`DPK-DAST-024` and `DPK-DAST-047`** are repaired in this pump (§5.1). Their earlier report did
   not document them; this file is the record, and the prior report is left untouched.

## 10. Verdict

**NO-GO.**

The two capabilities this pump built are implemented, executed and regression-tested, and every
gate that can be run in this repository is green. That is not a release verdict:

* SAST breadth objective is not met (950 rules against a 1,000 objective) and is treated as an
  objective, not a quota.
* SCA has 0 packs and no lawful advisory data; building matching would fabricate intelligence.
* No `LICENSE`; rights are unresolved.
* `DPK-DAST-050`, cross-header correlation and request/response analysis are owner-blocked.
* The App-loader gate is unverified.
* `EVAL-SAST-008` still FAILs (known, preserved).

Pump completion is not GO. Count growth is not readiness.
