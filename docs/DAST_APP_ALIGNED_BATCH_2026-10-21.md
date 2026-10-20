# DAST app-aligned batch — 2026-10-21

Status: **PARTIAL** — DAST 292 of the 500 planning target, and the more important
number: **219 of 292 rules are evaluable inside the Main App** (75 %). This batch was
designed by reading the App, not by reading the gap list.

App reference (read-only): `mdraselislam0101-design/Drobon` @
`9360dd1abdf940cc1bffd942aab0702703aaaaef`.

## 1. What the App actually gives a DAST rule

Both DAST engines call `evaluatePackDastCheck()` with a **filtered** response:

| Fact | Value | Source in the App |
|---|---|---|
| Headers forwarded to pack rules | 11 names only | `apps/api/src/scans/dast/engine.ts` (`INSPECTED_RESPONSE_HEADERS`), `activeEngine.ts` (`INSPECTED_HEADERS`) |
| The 11 names | `content-type`, `strict-transport-security`, `x-content-type-options`, `x-frame-options`, `content-security-policy`, `access-control-allow-origin`, `access-control-allow-credentials`, `server`, `x-powered-by`, `set-cookie`, `location` | same |
| Header value clip | 2 048 characters, at most 5 array entries | `boundedResponseHeaders()` / `boundedHeaders()` |
| Body clip | 32 768 bytes, truncation reported | `DAST_MAX_RESPONSE_BYTES`, `ACTIVE_DAST_MAX_RESPONSE_BYTES` |
| Active probes | 5 categories, but only the **first** payload is injected per point | `payloadsForSafety…` `payloadsForBudget(1)` + `payloads.slice(0,1)` in `activeEngine.ts` phase 3 |

Two consequences a dataset maintenance pass must live with:

1. **A rule that reads any other header is dead code inside the product.** A
   `Permissions-Policy` or `Referrer-Policy` rule is a correct rule that can never fire:
   the value is dropped before the evaluator sees it.
2. **The active engine only ever sends the XSS marker.** The SQLi, open-redirect,
   traversal and CRLF payloads in `payloads.ts` are never injected, because the loop
   injects `payloads.slice(0, 1)` for every point. Their detectors therefore never run.
   This is reported as an observation; nothing in the App was changed from here.

## 2. The reachability measurement (new gate)

`scripts/validate-app-dast-reachability.mjs` classifies every DAST rule against the
observed surface and pins the result in `interop/app-dast-reachability.json`:

| Measure | Value |
|---|---|
| DAST rules | 292 |
| Reachable in the App | **219 (75 %)** |
| Unreachable | **73**, spread over **47** header names |
| Wired into | `npm test` and CI (`npm run validate:app-dast-reachability`) |

The largest single unlocks, for the App side:

| Header to forward | Rules that become reachable |
|---|---|
| `Permissions-Policy` | 6 |
| `Refresh` | 5 |
| `Cross-Origin-Embedder-Policy` | 3 |
| `Cross-Origin-Opener-Policy` | 3 |
| `Cross-Origin-Resource-Policy` | 3 |
| `Referrer-Policy` | 3 |
| `X-Permitted-Cross-Domain-Policies` | 3 |
| 40 further headers | 47 (1–2 each) |

The gate fails in both directions: a rule that is unreachable but missing from the
register (a new silent gap) and a rule listed as unreachable that is in fact reachable
(a stale entry). It is the DAST twin of the SAST language gate, and the ledger now
carries it as `app.dast-reachability` (BLOCKED_APP).

## 3. What was added — 12 rules, all reachable by construction

| Rule | Title | Category | CWE | Severity | Check type |
|---|---|---|---|---|---|
| DPK-DAST-290 | SQL Server client exception text disclosed | information-disclosure | CWE-209 | MEDIUM | response-body-matches |
| DPK-DAST-291 | MySQL server or driver error text disclosed | information-disclosure | CWE-209 | MEDIUM | response-body-matches |
| DPK-DAST-292 | Framework data-layer query exception disclosed | debug-exposure | CWE-209 | MEDIUM | response-body-matches |
| DPK-DAST-293 | JavaScript ORM query exception disclosed | debug-exposure | CWE-209 | MEDIUM | response-body-matches |
| DPK-DAST-294 | Unix password database content served | information-disclosure | CWE-22 | HIGH | response-body-matches |
| DPK-DAST-295 | PostgreSQL connection or authentication error disclosed | information-disclosure | CWE-209 | MEDIUM | response-body-matches |
| DPK-DAST-296 | Rails detailed exception page disclosed | debug-exposure | CWE-209 | MEDIUM | response-body-matches |
| DPK-DAST-297 | SQLite driver error text disclosed | information-disclosure | CWE-209 | MEDIUM | response-body-matches |
| DPK-DAST-298 | Symfony exception trace disclosed | debug-exposure | CWE-209 | MEDIUM | response-body-matches |
| DPK-DAST-299 | Windows ini file content served | information-disclosure | CWE-22 | MEDIUM | response-body-matches |
| DPK-DAST-300 | `Location` header carries an encoded line break | content-injection | CWE-113 | MEDIUM | response-header-matches |
| DPK-DAST-301 | `Set-Cookie` header carries an encoded line break | content-injection | CWE-113 | MEDIUM | response-header-matches |

Totals: **+12 rules, +48 declared tests** (1 371 → 1 419), +12 patterns, +12 records,
+12 remediation entries (1 327 → 1 339 each).

Why these and not another header family: the App's own active probes look for five
injection symptoms, and its `ACT-SQLI-01` detector uses one broad alternation
(`SQL syntax|mysql_fetch|ORA-|PostgreSQL.*ERROR|sqlite.*error|unclosed quotation mark`).
The pack can carry the specific families that alternation cannot express, so an App scan
that later injects more than the XSS marker gets a precise finding instead of a generic
"database error" string. Every new rule is silent on the existing broad rule's evidence
only where the mechanism differs — the batch-level check confirmed none of the 12
matches any existing rule's positive observations, and the overlap gate stayed at 130
subset pairs with 0 unreviewed.

## 4. Evaluation

| What | Count |
|---|---|
| Independent positive cases, one per new rule | 12 (`EVAL-DAST-534 … 545`) |
| Controls naming all 12 rules as forbidden | 2 (`EVAL-DAST-546`, `547`) |
| DAST observation cases after the batch | 542 (292/292 rules with a positive and a negative declared test) |
| `run-eval` true positives | 1 353 → **1 365**, false negatives 0, false positives 1 (pre-existing `EVAL-SAST-008`) |

Control 546 is a hardened help page whose prose mentions "database error", "SQL" and "a
framework data layer" — a rule that reads prose instead of evidence fires on it. Control
547 is a JSON problem document whose `code` field names the failure in the team's own
vocabulary (`CART_LOOKUP_FAILED`), which must not be mistaken for a driver class.

One fixture correction was needed *before* the first real run of the Symfony case: the
evidence string contains a backslash-separated class name, and the evaluator compares
`mustContain` against the JSON-serialised observation, where backslashes are escaped. The
case now pins a backslash-free substring (`FatalThrowableError in CartController.php line 41`)
and says so in its own `limitations`. No expectation was weakened to obtain a green run.

## 5. Verification

| Command | Result (2026-10-21) |
|---|---|
| `node scripts/generate-assets.mjs` | 292 DAST rules, 1 339 patterns / records / remediation, 0 quarantined |
| `node scripts/test-packs.mjs` | PASS 5 538/5 538 |
| `node scripts/test-assets.mjs` | PASS 10 732/10 732 |
| `node scripts/validate-dast-overlaps.mjs` | PASS — 361 checks, 130 subset pairs, 0 unreviewed |
| `node scripts/validate-app-dast-reachability.mjs --check` | PASS — 219/292 reachable, 73 documented across 47 headers |
| `node scripts/gen-app-conformance.mjs --check` | PASS — 292/292 rules merge; 1 404/1 419 declared tests agree with the App-evaluator profile (15 known divergences, GAP-041) |
| `node scripts/test-eval.mjs` | PASS 43/43 (population pin moved 1 353 → 1 365) |
| `npm test` | EXIT 0 — 22 904 assertions |

## 6. What this batch does not claim

- **It does not make the App find more.** 73 rules stay invisible until the App forwards
  their headers; the register names the exact list and the count behind each name.
- **Body rules are bounded.** The App clips the body at 32 768 bytes; a marker past the
  clip is invisible to every body check, including all 12 added here.
- **A driver error is not proof of injection.** The rule reports that a message was
  disclosed; it cannot tell a failed connection from a successful probe.
- **One positive case per rule.** Precision on near-misses is covered only by the two
  controls, not by every direction.
- **No App code was edited, and no App test was run.** Everything above is measured
  against the transcribed profile at `9360dd1` plus the committed source lines cited in
  §1.
