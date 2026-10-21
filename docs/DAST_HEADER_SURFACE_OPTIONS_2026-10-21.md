# Can every DAST rule be carried by one header? — 2026-10-21

Short answer: **not at the rule level, but yes at the transport level.** A single
synthesised response header can carry every response header the pack reads, and then all
398 rules become evaluable inside the App. That change lives entirely in the App; this
document states the contract, the exact numbers behind it and what each option costs.

Measured against `mdraselislam0101-design/Drobon` @ `9360dd1` and this tree
(DAST 398 rules, 2026-10-21).

## 1. What the pack actually reads today

| Rules | Evidence they read |
|---|---|
| 219 | response body only |
| 178 | one or more response headers (150 `response-header-matches`, 16 `missing-response-header`, 8 `response-header-missing-directive`, 3 `cookie-missing-flag`, 1 `response-header-host-differs`) |
| 1 | the request URL (`http-url`) |

Those 178 header rules touch **57 distinct header names**:

| Group | Headers | Rules |
|---|---|---|
| Forwarded by the App today | 11 (`content-type`, `strict-transport-security`, `x-content-type-options`, `x-frame-options`, `content-security-policy`, `access-control-allow-origin`, `access-control-allow-credentials`, `server`, `x-powered-by`, `set-cookie`, `location`) | **102 reachable** |
| Filtered before evaluation | 46 (largest: `Permissions-Policy` 6, `Refresh` 5, `COEP`/`COOP`/`CORP` 3 each, `Referrer-Policy` 3, `X-Permitted-Cross-Domain-Policies` 3) | **73 unreachable** |

`interop/app-dast-reachability.json` lists all 47 header actions with the rule count each
one would unlock; the sum is exactly the 73 unreachable rules.

## 2. Why one header cannot hold the rules themselves

Three classes of rule have no single-header expression, and rewriting them would break
their meaning rather than their plumbing:

1. **A rule about a header must read that header.** `Content-Security-Policy` sources,
   `Set-Cookie` attributes, `Location` targets and `Strict-Transport-Security` directives
   are values on their own header. `Set-Cookie` cannot tell you what the policy is.
2. **A missing-header rule is undecidable when the header is not forwarded.** DPK-DAST-016
   asks "is HSTS absent?". If the App forwards only 11 headers, absence is
   indistinguishable from "not forwarded", so the answer is unknown, not "present".
3. **Cross-header rules need both sides.** `response-header-host-differs` compares
   `Location` against the request host, and the CORS rules compare
   `Access-Control-Allow-Origin` against the same request context.

So the pack cannot be collapsed into one header by editing the pack. The collapse has to
happen where the response is captured.

## 3. The one change that does work: a header bag

Have the App serialise the headers it already holds into **one** forwarded header and let
the evaluator rehydrate the map before running pack checks.

```
x-drobon-response-headers: {"content-type":["text/html; charset=utf-8"],
                            "permissions-policy":["camera=()"],
                            "set-cookie":["sid=abc; Path=/; Secure", "__Host-x=1; Path=/"]}
```

| Property | Requirement |
|---|---|
| Direction | built **server-side** from the response the App already received; never accepted from the target |
| Contents | response headers only — never `Authorization`, `Cookie` or any request header |
| Encoding | JSON object, lowercased names, values as arrays, preserving the App's existing 5-entry cap per name |
| Size | today's cap is 2 048 chars per value; a bag needs its own limit (16 KB is enough for the 47 headers the pack reads, with truncation recorded rather than silent) |
| Integrity | if the bag is truncated, the evaluator must treat the missing names as *unknown*, not absent, or the missing-header rules invert |
| Freshness | one bag per response, same lifetime as the observation it belongs to |

**What it unlocks: 398 of 398 rules reachable (100 %), from one forwarded header**, and it
also makes every future header rule reachable without another App change. It does not
change a single pack file: the evaluator keeps reading `permissions-policy` etc. from the
rehydrated map.

Acceptance test after the App change: bump `APP_PROFILE.commit` in
`scripts/lib/app-evaluator-profile.mjs`, describe the bag in `APP_DAST_SURFACE`, then
`node scripts/validate-app-dast-reachability.mjs --write` must report 398/398 with an empty
`headerActions` list. Until that runs, this document claims a projection, not a fact.

## 4. The other two options, priced honestly

| Option | App change | Reachable today | Costs |
|---|---|---|---|
| A. Header bag (above) | one serialiser + evaluator rehydration | **398/398** | needs a size limit and an "unknown vs absent" rule |
| B. Widen `ALLOWED_RESPONSE_HEADERS` to the 46 missing names | list change plus per-header bounds | **398/398** | every new header name needs another App release; the list ages as the pack grows |
| C. Retire the 73 blocked rules | none | **325/325 (100 % of what remains)** | the pack loses 73 real checks: 6 permissions-policy, 5 refresh, 3 each for COEP/COOP/CORP, and 46 more. The "100 %" would be true only because the denominator shrank — the exact relabelling the project's honesty rules forbid |

Option C is listed because it is the only option available with no App change, and it is
the one this repository will not take on its own: shrinking the pack to make a percentage
look complete is a coverage loss, not a fix.

## 5. What this repository does with the answer

- The pack keeps writing rules against the header the finding belongs to. A rule that
  reads a header the App cannot see is recorded as unreachable in
  `interop/app-dast-reachability.json` and in ledger dimension `app.dast-reachability`,
  and it is **not** rewired into body evidence to fake reachability — that would create
  false positives on pages that merely mention a policy.
- `GAP-048` stays open as an owner decision with the three options above. The dataset side
  is complete: measurement, per-header unlock counts and the contract in this document.
- If the owner picks A or B, the only dataset work is the profile bump and re-running the
  gates; no rule text changes.

## 6. Limits of this analysis

- The projection assumes the App can forward a value larger than its current 2 048-char
  per-value bound; a bag that is truncated without an "unknown" marker would make the
  16 missing-header rules unreliable.
- Header names are counted from the rules as written; a rule that reads two headers is
  counted once in the 178, so the per-header counts sum higher than the rule count.
- Nothing here changes the 15 known evaluator divergences (GAP-041); those are value
  semantics inside the evaluator, not header plumbing.
