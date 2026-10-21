# DAST app-surface batch 3 — 2026-10-21

Status: **PARTIAL** — DAST 325 of the 500 planning target; **252 of 325 rules are
evaluable inside the Main App** (77.5 %). A third batch designed from the App's real
response surface, not from a count target.

App reference (read-only): `mdraselislam0101-design/Drobon` @
`9360dd1abdf940cc1bffd942aab0702703aaaaef`.

## 1. What this batch covers that the pack did not

Batches 25 and 26 filled the injection-evidence, debug-output and cookie-contract
areas. A fresh gap scan over all 306 rules found four areas with no rule at all,
each readable from the response body or from the one forwarded header
(`Set-Cookie`) that carries attribute text:

| Area | Why it was missing | New rules |
|---|---|---|
| Markup the browser treats as a trust decision | The pack knew CSP sources and iframe sandbox pairs, but never read `target`, `rel`, `integrity` or the scheme of an anchor's `href` | 316, 329, 332 |
| Credential forms | No rule looked at where a password field sends its value: cross-origin `action`, or a `GET` form that writes the secret into the URL | 319, 320 |
| Secrets that exist only as text | Signing keys, service-account JSON, cloud secret keys, unsigned tokens and webhook URLs were not recognised; the pack only knew private-key files and provider config files | 317, 321, 324, 325, 330, 331 |
| Deployment artefacts and diagnostics rendered as pages | `.DS_Store`, `.htaccess`, Redis `INFO`, webpack's dev client and JSON stack fields were absent, even though the pack had bucket listings and framework error pages | 318, 322, 323, 327, 328, 333 |
| Cookie lifetime | `Max-Age` over the 400-day cap was covered (281); the `Expires` form of the same defect was not | 334 |

## 2. The 19 rules

| Rule | Title | Category | CWE | Severity | Check type |
|---|---|---|---|---|---|
| DPK-DAST-316 | Anchor navigates to a `data:` URI | content-injection | CWE-79 | LOW | response-body-matches |
| DPK-DAST-317 | Django `SECRET_KEY` value served | information-disclosure | CWE-798 | **HIGH** | response-body-matches |
| DPK-DAST-318 | macOS `.DS_Store` served from the web root | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-319 | Password form submits to a third-party origin | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-320 | Password form submits with GET | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-321 | Google Cloud service account key JSON served | information-disclosure | CWE-798 | **HIGH** | response-body-matches |
| DPK-DAST-322 | Apache `.htaccess` served as a response | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-323 | JSON response carries a stack-trace field | debug-exposure | CWE-209 | MEDIUM | response-body-matches |
| DPK-DAST-324 | Token declares an unsigned `alg` value | information-disclosure | CWE-347 | **HIGH** | response-body-matches |
| DPK-DAST-325 | Kubernetes Secret manifest served | information-disclosure | CWE-798 | **HIGH** | response-body-matches |
| DPK-DAST-326 | Presigned object-storage URL in the body | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-327 | Network error text discloses an internal address and port | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-328 | Redis `INFO` output served | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-329 | Cross-origin script without an integrity hash | content-injection | CWE-829 | LOW | response-body-matches |
| DPK-DAST-330 | Incoming webhook URL with its token served | information-disclosure | CWE-798 | MEDIUM | response-body-matches |
| DPK-DAST-331 | Stripe live secret key served | information-disclosure | CWE-798 | **HIGH** | response-body-matches |
| DPK-DAST-332 | Anchor opens a new tab without `rel=noopener` | content-injection | CWE-693 | LOW | response-body-matches |
| DPK-DAST-333 | webpack development client served in production | debug-exposure | CWE-489 | MEDIUM | response-body-matches |
| DPK-DAST-334 | `Set-Cookie` `Expires` exceeds the 400-day cap | cookie-flags | CWE-613 | LOW | response-header-matches |

Totals: **+19 rules, +76 declared tests** (1 478 → 1 554), +19 patterns, +19 records,
+19 remediation entries (1 353 → 1 372 each).

### Why each one is not a restatement

Every candidate was run against **every existing rule's positive observations** before
it was written. Five candidates were dropped at that step rather than ledgered:

| Dropped candidate | Why |
|---|---|
| `Set-Cookie` `Partitioned` without `SameSite=None` | Its evidence is a strict subset of DPK-DAST-311's positive fixture; the overlap gate rejects evidence subsets |
| `Set-Cookie` with a `__Secure-`/`__Host-` prefix but no `Secure` | Fired on the positive fixtures of 264 and 311 |
| `Set-Cookie` without a `Path` attribute | Fired on eight existing fixtures (004/006/008/071/187/190/281/309), all of which omit `Path` by design |
| URL carrying `user:password@`, and connection-string passwords | Both fired on DPK-DAST-260's Docker-Compose fixture, whose `environment` block contains a credential URL |
| `script-src` naming a scheme-less host, `frame-ancestors https:` | The first failed the ReDoS lint (nested quantifier) and the second restates 092 at a different spelling |

For the 19 that landed, the nearest neighbour in each family is stated in the rule's own
`limitation` and `fp` fields; the overlap gate stayed at **130 subset pairs, 0
unreviewed** (394 checks).

## 3. Evaluation cases

21 new cases in cohort `dast-app-surface-3-2026-10-21`:

- `EVAL-DAST-564` … `EVAL-DAST-582` — one positive per rule, each fixture being the
  rule's own first positive observation;
- `EVAL-DAST-583` — a hardened account page (new-tab anchor with `rel="noopener
  noreferrer"`, integrity-pinned script, same-origin POST password form, cookie with
  `Path`, an in-cap `Expires`, `Secure`, `HttpOnly`, `SameSite=Strict`) that forbids all 19;
- `EVAL-DAST-584` — a security handbook that *names* every dangerous token without
  rendering a single violation, also forbidding all 19. This is the keyword-versus-shape
  control: a rule that fires here is matching vocabulary.

Expectations were authored before the first run. One anchor had to be corrected:
`EVAL-DAST-567` originally asserted `mustContain: 'action="/login"'`, and the evaluator
compares against the JSON-serialised observation, where the quotes are escaped — it was
re-pinned to the quote-free `/login`. No pattern was changed to make a case pass, and no
case was deleted after the run.

## 4. Verification

| Command | Result (2026-10-21) |
|---|---|
| `node scripts/generate-assets.mjs` | 325 DAST rules, 1 372 patterns / records / remediation, 0 quarantined |
| `node scripts/test-packs.mjs` | PASS 5 670/5 670 |
| `node scripts/test-assets.mjs` | PASS 10 996/10 996 |
| `node scripts/validate-dast-overlaps.mjs` | PASS — 394 checks, 130 subset pairs, 0 unreviewed |
| `node scripts/validate-app-dast-reachability.mjs --check` | PASS — 252/325 reachable (77.5 %), 73 unreachable across 47 headers |
| `node scripts/gen-app-conformance.mjs --check` | PASS — 325/325 rules merge; 1 539/1 554 declared tests agree with the App-evaluator profile |
| `node scripts/run-eval.mjs` | 1 398 TP / 0 FN / 1 documented FP (`EVAL-SAST-008`); 1 695 cases, 1 684 assessed, 11 unassessed |
| `node scripts/test-eval.mjs` | PASS 43/43 (population pin 1 379 → 1 398) |
| `npm test` | EXIT 0 — 23 399 assertions |

## 5. Limits

- **The five dropped candidates are a real gap, not padding avoided.** Three of them
  describe defects that the pack can only see through a neighbouring rule today; fixing
  that needs a per-defect evidence split (a change to existing rules), which this batch
  was not allowed to make.
- **The App surface is unchanged.** 73 rules still read one of 47 headers that the App
  filters out before evaluation; nothing in this batch can reduce that number, because
  every new rule was built on the body or on `Set-Cookie`.
- **Two rules can fire on documentation.** A page that quotes an `.htaccess` block or a
  complete service-account JSON sample is reported; both rules say so in `fp`.
- **Secret-shape rules prove exposure, not liveness.** No rule calls the provider.
- **No App code was changed.** The 15 App-evaluator divergences (GAP-041) are untouched.
- **Distance to 500 remains 175 rules.** Closing it through the App surface means either
  new body evidence that does not restate an existing rule, or the owner widening the
  11-header allowlist in `apps/api/src/scans/dast/{rules,engine}.ts`.
