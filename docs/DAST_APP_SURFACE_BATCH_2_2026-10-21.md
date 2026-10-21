# DAST app-surface batch 2 — 2026-10-21

Status: **PARTIAL** — DAST 306 of the 500 planning target; **233 of 306 rules are
evaluable inside the Main App** (76.1 %). A second batch designed from the App's real
response surface, not from a count target.

App reference (read-only): `mdraselislam0101-design/Drobon` @
`9360dd1abdf940cc1bffd942aab0702703aaaaef`.

## 1. What this batch covers that the pack did not

The previous batch filled the injection-evidence half of the App-visible surface
(driver errors, traversal files, CRLF artefacts). This batch covers four areas that had
no rule at all, each of them readable from the body or from one of the 11 forwarded
headers:

| Area | Why it was missing | New rules |
|---|---|---|
| Debug output left in a response | Xdebug, Symfony VarDumper, ASP.NET trace viewer and the Node.js inspector were absent; the pack only knew framework exception pages | 305, 307, 308, 303 |
| Cookie attribute contracts | The pack tested flags and `__Host-`, but not misspelt attribute names, public-suffix `Domain`, or `Partitioned` without `Secure` | 309, 310, 311 |
| Policy delivered the wrong way | Every CSP rule read the header; a policy written in a `meta` element is weaker and, for `frame-ancestors`, ignored outright | 313, 314, 315 |
| Host and frame disclosure | `Server` carrying an internal hostname, and a sandbox that defeats itself | 312, 304 |

## 2. The 14 rules

| Rule | Title | Category | CWE | Severity | Check type |
|---|---|---|---|---|---|
| DPK-DAST-302 | Classic ASP.NET error page disclosed | debug-exposure | CWE-209 | MEDIUM | response-body-matches |
| DPK-DAST-303 | ASP.NET trace application disclosed | debug-exposure | CWE-215 | MEDIUM | response-body-matches |
| DPK-DAST-304 | iframe sandbox combines allow-scripts with allow-same-origin | content-injection | CWE-693 | MEDIUM | response-body-matches |
| DPK-DAST-305 | Node.js inspector debugging endpoint disclosed | debug-exposure | CWE-489 | **HIGH** | response-body-matches |
| DPK-DAST-306 | Served source map embeds the original source | information-disclosure | CWE-540 | MEDIUM | response-body-matches |
| DPK-DAST-307 | Symfony VarDumper output disclosed | debug-exposure | CWE-215 | MEDIUM | response-body-matches |
| DPK-DAST-308 | Xdebug variable dump disclosed | debug-exposure | CWE-215 | MEDIUM | response-body-matches |
| DPK-DAST-309 | Set-Cookie attribute name misspelt | cookie-flags | CWE-16 | LOW | response-header-matches |
| DPK-DAST-310 | Set-Cookie Domain is a public suffix | cookie-flags | CWE-16 | MEDIUM | response-header-matches |
| DPK-DAST-311 | Set-Cookie Partitioned without Secure | cookie-flags | CWE-614 | LOW | response-header-matches |
| DPK-DAST-312 | Server header names an internal host | information-disclosure | CWE-200 | LOW | response-header-matches |
| DPK-DAST-313 | Meta CSP frame-ancestors a browser ignores | csp-weakness | CWE-693 | MEDIUM | response-body-matches |
| DPK-DAST-314 | Meta CSP that permits inline script | csp-weakness | CWE-79 | MEDIUM | response-body-matches |
| DPK-DAST-315 | Meta referrer sends full URLs to every destination | information-disclosure | CWE-200 | LOW | response-body-matches |

Totals: **+14 rules, +59 declared tests** (1 419 → 1 478), +14 patterns, +14 records,
+14 remediation entries (1 339 → 1 353 each).

### Why each one is not a restatement

Every rule was run against **every existing rule's positive observations**; none of the
14 matches any of them (checked before the write, in `dry` mode). The overlap gate stayed
at 130 subset pairs, 0 unreviewed. Specific neighbours:

| New rule | Nearest existing rule | Difference |
|---|---|---|
| 302 (classic ASP.NET page) | 127 (ASP.NET Core developer page) | Different product generation and different marker; the Core page never contains this heading. |
| 303 (trace.axd) | 221 (ELMAH log) | Different subsystem and data: the trace viewer lists *other users'* requests; ELMAH lists errors. |
| 304 (sandbox pair) | none | The pack had no iframe attribute analysis. |
| 305 (inspector) | 220/228/250 (generator meta) | RCE-capable debug endpoint, not a version string. |
| 306 (`sourcesContent`) | 069 (source map reference) | 069 notices that a map is referenced; 306 notices that the map ships the original code. |
| 307/308 (VarDumper, Xdebug) | 244 (profiler toolbar), 067 (PHP error with path) | Toolbar and error text are different markers from the dump block. |
| 309 (misspelt attribute) | 003/071 (missing flag), 159/187 (`SameSite` value) | The attribute *name* is wrong, so the flag rules see "absent" and the value rules never run. |
| 310 (public-suffix Domain) | 264 (`__Host-` with Domain) | No prefix involved; the defect is the scope itself. |
| 311 (`Partitioned` without `Secure`) | 265 (`SameSite=None` without `Partitioned`) | The inverse pairing; both cookies are discarded, for opposite reasons. |
| 312 (internal host) | 030 (version in `Server`) | 030 needs a version number; 312 needs a private-suffix hostname, which 030's pattern does not match. |
| 313/314 (meta CSP) | 010/059/060/075/087 and the header CSP family | All header rules; a meta-delivered policy is invisible to them by construction. |
| 315 (meta referrer) | 068/117/157 (`Referrer-Policy` header) | The header is not in the App's forwarded set at all; the meta override is only visible in the body. |

## 3. Evaluation

| What | Count |
|---|---|
| Independent positive cases, one per new rule | 14 (`EVAL-DAST-548 … 561`) |
| Controls naming all 14 rules as forbidden | 2 (`EVAL-DAST-562`, `563`) |
| DAST observation cases after the batch | 558 (306/306 rules with a positive and a negative declared test) |
| `run-eval` true positives | 1 365 → **1 379**, false negatives 0, false positives 1 (pre-existing `EVAL-SAST-008`) |

Control 562 is a hardened page that *does* use a meta CSP — with a nonce and a strict
frame policy — plus a correct `__Host-` cookie and a product-token `Server` header.
Control 563 is a security guide that names every dangerous token in prose (`Http-Only`,
`unsafe-inline`, `frame-ancestors`, `sourcesContent`, `webSocketDebuggerUrl`). Both must
produce zero findings: a detector that fires on documentation is worthless to a defender,
and the two meta-CSP rules are the ones most likely to slip into matching prose.

Two fixture corrections were made **before** the first real run, both about evidence
comparison rather than detection: the evaluator checks `mustContain` against the
JSON-serialised observation, so evidence strings containing quotes had to be replaced
with quote-free substrings (`allow-scripts allow-same-origin`, `sourcesContent`,
`sf-dump-1234`, `unsafe-url`). No pattern was changed to make a case pass, and no case was
deleted after the run.

## 4. Verification

| Command | Result (2026-10-21) |
|---|---|
| `node scripts/generate-assets.mjs` | 306 DAST rules, 1 353 patterns / records / remediation, 0 quarantined |
| `node scripts/test-packs.mjs` | PASS 5 594/5 594 |
| `node scripts/test-assets.mjs` | PASS 10 844/10 844 |
| `node scripts/validate-dast-overlaps.mjs` | PASS — 375 checks, 130 subset pairs, 0 unreviewed |
| `node scripts/validate-app-dast-reachability.mjs --check` | PASS — 233/306 reachable (76.1 %), 73 unreachable across 47 headers |
| `node scripts/gen-app-conformance.mjs --check` | PASS — 306/306 rules merge; 1 463/1 478 declared tests agree with the App-evaluator profile |
| `node scripts/test-eval.mjs` | PASS 43/43 (population pin 1 365 → 1 379) |
| `npm test` | EXIT 0 — 23 114 assertions |

## 5. Limits

- **Two meta-CSP rules can fire on documentation.** A page that shows a `meta` CSP inside
  a code block is reported; the rule reads markup, not intent. Stated in both rules'
  `fp` field.
- **The public-suffix list is finite** (13 well-known suffixes). A private or country
  suffix outside it is not detected; the rule says so.
- **The inspector rule proves reachability of the endpoint, not an attached debugger.**
- **No App code was changed.** Reachability is still 73 rules short of the pack, and the
  15 App-evaluator divergences (GAP-041) are untouched.
- **One positive case per rule.** Precision is probed by the two controls, not
  exhaustively.
