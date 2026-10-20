# DAST defensive batch — 2026-10-21

Status: **PARTIAL by design** (DAST 280 of the 500 planning target; see §7).
Scope: additive only. No existing rule, test, evaluation case, report or ledger row
was edited to make room for this batch; the 263 rules that existed on 2026-10-20 are
byte-identical, and the 9 retired/withdrawn IDs stayed reserved.

## 1. What this batch is for

The main App (`Drobon`) evaluates an observed HTTP response with a closed vocabulary of
seven DAST check types. Before this batch the pack answered "is a security control
missing?" far better than "is this response hardened, and does it leak internals while
doing its job?" — a question a defender asks on every response they scan, and the one
the App's own engine was built around.

The batch therefore adds detections that a defender can act on without ambiguity:

- a `__Host-` cookie that loses the guarantee its prefix promises;
- a cookie persisted past the 400-day cap browsers enforce, so the author's intent and
  the browser's behaviour disagree silently;
- a Permissions-Policy grant that is a documented no-op (`payment=*`) or an unneeded
  cross-origin grant (`browsing-topics=*`);
- a CSP `frame-ancestors` list that still admits a plaintext parent;
- internal timing and tracing headers that hand an attacker a timing oracle and a
  backend map;
- operations consoles and dev servers (Envoy admin, HAProxy statistics, Selenium Grid,
  pgAdmin, Vite) answering on a public origin;
- markup that quietly downgrades an HTTPS page (`<base href="http://…">`, `<object>`,
  `<embed>`, meta refresh, `javascript:` links).

Every one of them is expressible in the existing seven check types. **No eighth check
type was added, and none of the batch contains an active probe**: only the response the
caller already holds is inspected.

## 2. What was added

17 rules, `DPK-DAST-271 … 289` with `283`/`284` withdrawn before publication (§5).

| Rule | Title | Category | CWE | Severity | Check type | Declared tests (pos/neg) |
|---|---|---|---|---|---|---|
| DPK-DAST-271 | Base element points relative URLs at a plaintext origin | mixed-content | CWE-319 | MEDIUM | response-body-matches | 2/3 |
| DPK-DAST-272 | Envoy administration interface disclosed | debug-exposure | CWE-200 | MEDIUM | response-body-matches | 2/2 |
| DPK-DAST-273 | HAProxy statistics report disclosed | debug-exposure | CWE-200 | MEDIUM | response-body-matches | 2/2 |
| DPK-DAST-274 | Anchor element uses the javascript: scheme | content-injection | CWE-79 | LOW | response-body-matches | 2/3 |
| DPK-DAST-275 | Meta refresh navigates an HTTPS page to a plaintext URL | mixed-content | CWE-319 | MEDIUM | response-body-matches | 2/3 |
| DPK-DAST-276 | Plugin object or embed loads over plaintext HTTP on an HTTPS page | mixed-content | CWE-319 | MEDIUM | response-body-matches | 2/3 |
| DPK-DAST-277 | pgAdmin management interface disclosed | debug-exposure | CWE-200 | MEDIUM | response-body-matches | 2/2 |
| DPK-DAST-278 | Selenium Grid status endpoint disclosed | debug-exposure | CWE-200 | MEDIUM | response-body-matches | 2/2 |
| DPK-DAST-279 | Vite development server serving the application | information-disclosure | CWE-540 | MEDIUM | response-body-matches | 2/2 |
| DPK-DAST-280 | Set-Cookie `__Host-` prefix is not paired with `Path=/` | cookie-flags | CWE-16 | LOW | response-header-matches | 2/4 |
| DPK-DAST-281 | Set-Cookie `Max-Age` exceeds the 400-day browser cap | cookie-flags | CWE-613 | LOW | response-header-matches | 2/3 |
| DPK-DAST-282 | CSP `frame-ancestors` allows a plaintext HTTP parent | csp-weakness | CWE-319 | MEDIUM | response-header-matches | 2/3 |
| DPK-DAST-285 | Permissions-Policy grants the Payment Request API to every origin | security-headers | CWE-693 | LOW | response-header-matches | 2/3 |
| DPK-DAST-286 | Permissions-Policy grants a Privacy Sandbox API to every origin | security-headers | CWE-693 | LOW | response-header-matches | 2/3 |
| DPK-DAST-287 | Server-Timing exposes backend timing to every client | information-disclosure | CWE-200 | LOW | response-header-matches | 2/3 |
| DPK-DAST-288 | X-B3-TraceId exposes internal tracing identifiers | information-disclosure | CWE-200 | LOW | response-header-matches | 2/2 |
| DPK-DAST-289 | X-Runtime exposes per-request processing time | information-disclosure | CWE-200 | LOW | response-header-matches | 2/3 |

Totals: **+17 rules, +79 declared tests** (1 292 → 1 371 across the pack),
+17 patterns, +17 records, +17 remediation entries (1 310 → 1 327 each).

### Predecessor disambiguation

The following existing rules ask a neighbouring question; each new rule was checked
against them and states the difference in its own `limitation` field:

| New rule | Nearest existing rule | Why both are needed |
|---|---|---|
| DPK-DAST-280 (`__Host-` without `Path=/`) | DPK-DAST-264 (`__Host-` with `Domain`) | A `Domain` attribute breaks the prefix outright; a missing `Path=/` breaks it just as silently and is the more common copy-paste error. |
| DPK-DAST-282 (`frame-ancestors http:`) | DPK-DAST-092/200 (wildcard) | 092/200 answer "everyone may frame this"; 282 answers "a plaintext origin may frame this" — a different fix (drop one origin vs drop the wildcard). |
| DPK-DAST-285/286 (policy wildcard) | DPK-DAST-077/270 (camera, geolocation, device features) | Different feature sets, different browser behaviour: `payment=*` is allowed but ignored for cross-origin frames, so the grant looks like a control and is not one. |
| DPK-DAST-287/288/289 (timing, tracing) | none | The pack had no timing/trace-header coverage before this batch. |

## 3. Evaluation

| What | Count | Where |
|---|---|---|
| Independent positive cases, one per new rule | 17 (`EVAL-DAST-515 … 531`) | `data/eval-cases/` |
| Ordinary-response controls naming **all 17** rules as forbidden | 2 (`EVAL-DAST-532`, `533`) | `data/eval-cases/` |
| DAST observation cases after the batch | 528 (280/280 rules with a positive and a negative declared test) | `run-eval` |
| `run-eval` true positives | 1 336 → **1 353**, false negatives 0, false positives 1 (the pre-existing `EVAL-SAST-008`) | `node scripts/run-eval.mjs` |

Expectations were **written before the first run** and never edited to obtain a green
result. One evidence string (`EVAL-DAST-515.mustContain`) was corrected *before* its
first execution because the fixture used double quotes and the declared evidence had a
stray apostrophe; the case then passed on its first real run. The 19 cases are counted
in `docs/CURRENT_INVENTORY.json` and in the completion ledger.

The controls are deliberately adversarial: `EVAL-DAST-532` is a fully hardened HTML
response (strict CSP with `frame-ancestors 'none'`, HSTS with preload, `no-store`, a
`__Host-` cookie with `Path=/` and a one-hour `Max-Age`, no inline `javascript:` URL, no
plaintext `<base>`, no meta refresh, no dev-server script) and `EVAL-DAST-533` is a
hardened JSON API response. A rule that fires on either one is reporting ordinary
hardened behaviour as a weakness, which is exactly the false positive a defender cannot
afford on every page.

## 4. Verification (commands and results)

| Command | Result (2026-10-21) |
|---|---|
| `node scripts/generate-assets.mjs` | 280 DAST rules, 1 327 patterns / records / remediation, 0 quarantined cells |
| `node scripts/test-packs.mjs` | PASS 5 490/5 490 (79 new declared tests included) |
| `node scripts/test-assets.mjs` | PASS 10 636/10 636 (1:1 rule↔pattern↔record↔remediation linkage) |
| `node scripts/validate-dast-overlaps.mjs` | PASS — 349 checks, 130 evidence-subset pairs, 0 unreviewed |
| `node scripts/test-csp-semantics.mjs` | PASS 22 983 assertions (frame-ancestors pairs re-derived) |
| `node scripts/test-cookie-semantics.mjs` | PASS 1 666 assertions (`__Host-`, `Max-Age` matrix) |
| `node scripts/test-eval.mjs` | PASS 43/43 (population pin moved 1 336 → 1 353 with a dated comment) |
| `node scripts/gen-app-conformance.mjs --check` | PASS — 280/280 DAST rules merge; 1 356/1 371 declared tests agree with the App-evaluator profile (15 known divergences on 9 rules, GAP-041) |
| `npm test` | EXIT 0 |

## 5. Candidates rejected before publication

| Candidate | Reason | IDs consumed |
|---|---|---|
| `frame-ancestors` wildcard, second formulation | Asked exactly DPK-DAST-092's question with different regex anchoring. Semantic duplicate, not a new question. | `DPK-DAST-283` reserved, never written |
| `report-uri` deprecation notice | Its evidence set strictly contains DPK-DAST-115's (every plaintext `report-uri` endpoint also trips "the directive is deprecated"), so it is a subset pair the overlap gate would have required a ledger entry for. Withdrawn instead of widening the ledger for a notice. | `DPK-DAST-284` reserved, never written |
| Unknown Permissions-Policy feature token | The only faithful expression needs a 784-character `valuePattern`; the schema limit is 500, and splitting it would have produced several near-duplicate rules. | none (rejected before allocation) |
| `Vary` omission, SRI absence, `WWW-Authenticate` scheme checks | Each is a real question, but none can be decided from a single response without a second observation (what varies, which script, which realm). They stay out rather than becoming speculative rules. | none |

## 6. Known limitations of this batch

- **One positive case per rule.** That proves the detector fires on the declared
  evidence; it does not prove it is precise on the whole space of near-misses. The two
  ordinary-response controls cover the most damaging direction (firing on hardened
  traffic), not every direction.
- **App parity is measured against a profile, not a running App.** The 15 divergences in
  `interop/app-conformance.json` are real and unfixed (GAP-041); the 79 new declared
  tests are evaluated against `scripts/lib/app-evaluator-profile.mjs`, a port of the App
  evaluator's semantics at `9360dd1`, not by driving the App.
- **No browser execution.** `javascript:` links, meta refresh and `<base>` are detected
  lexically. A page assembled by JavaScript at runtime is invisible to these rules.
- **Body checks are bounded.** They inspect the returned body the caller already has; a
  truncated, streamed or compressed-encoded body may hide the marker.
- **Severity is judgement, not CVSS.** `payment=*` and `X-Runtime` are LOW because their
  own harm is limited; they matter as part of a chain, which the pack does not model.

## 7. Position against the 500 target

| Target | State after this batch |
|---|---|
| 500 DAST checks | **280 authored (56 %)**, 220 unauthored. Not claimed. |
| Every new check semantically distinct | yes — checked against every existing rule's positive observations; two candidates withdrawn |
| Every new check tested positively and negatively | yes — 79 declared tests, 19 independent evaluation cases |
| Passive observation contract | unchanged — 7 check types, no request-side observation, no replay |

The honest continuation is families that still have no coverage at all (`WWW-Authenticate`
schemes, cache-key semantics, `Content-Disposition` handling, multipart/boundary
contradictions), each of which requires a second observation or a request-side fact and
therefore needs an owner decision before it can be authored inside the closed contract.
Stretching the current header families toward 500 would produce exactly the near-duplicate
padding this repository refuses.
