# Authenticated DAST design — what the App must add to see behind a login

Status: **design, not implemented.** Nothing in this document exists in the Main App at
`9360dd1`; the Dataset side already carries everything it would need. This is the spec for the
App-side change that turns "public page hygiene checker" into "internet-banking scanner", and
it is deliberately written so that the owner can price it before anyone writes code.

App reference (read-only): `mdraselislam0101-design/Drobon` @ `9360dd1`.
Related: `docs/BANK_THREAT_COVERAGE_2026-10-21.md` (what stays out of scope even after this),
`docs/BANK_RULE_CHECKLIST.md` (the 437 rules this design makes usable on authenticated pages),
`DROBON_REMAINING_WORK.csv` rows `GAP-042` (loader), `GAP-045` (active boundary), `GAP-048`
(header surface).

---

## 1. Why authentication is the single biggest gap

The engine today makes at most **3 requests** to **one URL**, follows at most **2 same-host
redirects**, and never logs in (`apps/api/src/scans/dast/engine.ts`). Every rule that matters
for a bank — statement pages, transfer confirmations, card management, admin back office —
sits behind a login. Consequences measured today:

| Fact | Number | Source |
|---|---|---|
| DAST rules authored | 510 | `packs/dast/v1/rules` |
| Evaluable through the current App surface | 437 | `interop/app-dast-reachability.json` |
| **Usable on authenticated pages today** | **0** | the engine has no session concept |
| Rules that become meaningful once a session exists | up to 437 | same rules, authenticated observations |
| Business-logic findings still impossible afterwards | all | see §7 |

So this is not "polish the scanner". It is the difference between scanning a brochure site and
scanning the product a customer actually banks in.

## 2. The three ways to do it, priced

| Option | What it means | Coverage | Risk | Verdict |
|---|---|---|---|---|
| **A. Recorded session replay** (cookie + one extra header injected into the existing probe) | Customer or tester pastes a session cookie; the engine sends it on the 3 bounded requests | Smallest change; ~1 page per scan | Session values in the product's memory and logs | **Recommended first step** |
| **B. Scripted login** (engine posts the bank's own login form) | Requires credentials, CSRF handling, MFA handling, and a bank-specific login adapter per target | Multi-page, but fragile and per-bank work | Holds real credentials; needs MFA strategy; high blast radius | **Rejected for a bank pilot** — the maintenance and custody burden lands on us |
| **C. Bring-your-own-session, customer-driven crawl** | Customer runs a browser extension / HAR export; the App ingests a list of URLs plus their session cookies and scans them | Best coverage per engineering hour; the customer keeps their credentials | PII inside HAR exports must be stripped before upload | **Recommended second step** |

Option A is the only one that fits inside the current architecture (one target, bounded
requests, no credential storage). Option B is how commercial scanners do it, and it is exactly
why they are expensive: per-target login adapters never stop needing maintenance.

## 3. Minimal contract for Option A

### 3.1 Request shape (App)

```ts
interface DastSessionInput {
  /** Cookie header value the browser would send. Never parsed, never logged. */
  cookieHeader: string;          // e.g. "sid=…; csrf=…"
  /** Optional single extra header some banks use for their WAF/tenant routing. */
  extraHeaders?: Record<string, string>;  // max 3 names, 512 chars each
  /** Optional page the session was taken from, used only for the Referer. */
  originUrl?: string;
}
```

Rules for the implementation:

1. **In memory only.** The value is held for the duration of one scan, never written to the
   database, never included in the scan record, never echoed in an error message.
2. **Redaction first.** Reuse the existing `safeHeaderSummaries` path: the session cookie is
   summarised as `Set-Cookie: N header(s), values redacted` — the same rule already applied on
   the response side.
3. **Scope bound.** The session is only ever sent to the host it was issued for. A redirect
   that leaves that host drops the session and continues unauthenticated (fail closed, not
   open).
4. **Budget unchanged.** Still ≤3 requests, ≤2 redirects, 32 KB body, 15 s deadline. An
   authenticated scan must not become an unbounded crawl.
5. **Two-person gate.** A scan that carries a session requires an explicit `authenticated: true`
   flag plus the existing consent record; the UI must say the target will receive real
   authenticated traffic.

### 3.2 What the Dataset must add

**Nothing structural.** The 510 rules are already written as observation predicates and do not
care whether the response was authenticated. Two small additions are worth doing anyway:

| Addition | Why | Size |
|---|---|---|
| `surface: "public" \| "authenticated" \| "both"` on each rule | Lets the App hide rules that can only fire on a public page (e.g. `Server` banner on an API) and lets a report say which class of page produced the finding | one field per rule, derivable from the rule's category and check type |
| An authenticated observation fixture per bank-critical rule | Proves the rule still fires when the page is a statement screen, not a brochure | ≈20 extra declared tests, not 437 |

Neither is required for Option A to work; both are cheap and stop the dataset from being
"public-only in practice while claiming to be general".

### 3.3 What must never be added

- **No credential storage.** Not encrypted at rest, not "for convenience" — a bank pilot ends
  the first time a scanner database contains customer sessions.
- **No session replay inside the dataset.** Fixtures stay synthetic; a real session cookie in a
  test fixture is a live credential and would be redacted and refused by the leak scanner
  anyway (`test-secret-candidates`).
- **No silent scope widening.** The target policy already blocks private ranges, link-local and
  reserved suffixes (`apps/api/src/scans/dast/target.ts`); an authenticated scan must reuse it
  unchanged.

## 4. What this unlocks, measured

Assuming Option A ships unchanged in budget:

| Before | After |
|---|---|
| 1 URL, public responses only | 1 URL **per scan**, but any URL the customer authorises, including post-login pages |
| 437 rules evaluable on public pages | the same 437 rules evaluable **on authenticated pages** |
| Cookie/session rules fire only on pre-login responses | `Secure`/`HttpOnly`/`SameSite`/`__Host-`/session-in-URL checks now run on the session that actually matters |
| Statement/PII rules almost never fire (pages need a session) | `DPK-DAST-511/513/514/515/516/517/518` become reachable in practice |
| 0 findings behind login | findings behind login, **one page per scan** |

Note the last row: authentication does **not** give coverage, it gives **reach**. A bank with
40 authenticated pages needs 40 authorised scans, or Option C to enumerate them.

## 5. Safety model (non-negotiable for a bank)

| Control | Requirement |
|---|---|
| Authorisation | Written scope naming host(s), window and contact; stored with the consent record, not in a chat |
| Mode | Passive only against production — the checks read responses, they do not inject |
| Rate | ≤3 requests per scan, no parallelism, ≤1 scan per target per minute (bank WAFs treat scanners as attackers) |
| Data handling | Session values never persisted; response bodies hashed or discarded after evaluation; findings carry evidence strings, not full bodies |
| Kill switch | A per-target and a global stop that aborts in-flight scans |
| Audit | Every authenticated scan logs who ran it, against which host, with which scope id — without the session value |
| Exit | Deleting a session must be one action, and a scan must not outlive it |

## 6. Definition of done (App side)

1. `DastSessionInput` accepted by the engine, redacted in every log and every finding.
2. A test that a redirect to another host drops the session (fail-closed proof).
3. A test that the session never appears in the scan record, the API response or an error.
4. A test that the request budget is unchanged (±0 requests).
5. `GAP-042` items 1/3/4 (schema validation, ReDoS budget, load-time test execution) closed
   **before** authenticated scans are enabled — a slow or invalid pack must not run against a
   bank with a live session attached.
6. `GAP-048` decided, so `Set-Cookie` and `Location` are not the only session-relevant headers
   the evaluator can see.

## 7. What authentication still does not fix

| Blind spot | Why authentication does not help |
|---|---|
| **Authorization / IDOR** | Needs two identities and a comparison; one session proves nothing about what another customer can read |
| **Business logic** (limits, double-spend, OTP skip, beneficiary swap) | No rule language can express "the transfer should have been refused" |
| **Injection depth** | Still GET-only, still ≤10 synthetic payloads in active mode — and active mode against a bank's production is out of scope (`GAP-045`) |
| **TLS / certificates** | The observation model has no certificate fields |
| **Runtime defence** | WAF effectiveness, rate limits, DDoS, bot management are not observable from a response |
| **Fraud and account takeover** | Device, behaviour and mule detection are not HTTP-visible |
| **Coverage** | One URL per scan; a session does not enumerate the site |

A bank that buys only this still needs: patching, WAF, an authorised pentest with two test
identities, and a SOC. This document makes the scanner *worth deploying*; it does not make it a
defence.

## 8. Cost sketch (engineering, App repo)

| Work item | Estimate |
|---|---|
| `DastSessionInput` + redaction + fail-closed redirect handling | 1–2 days |
| Scope/consent wiring + audit row | 1 day |
| Tests (5 named above) | 1–2 days |
| `surface` field in the Dataset + 20 authenticated fixtures | 1 day (Dataset) |
| Option C (HAR import + PII strip) | 1–2 weeks, separate decision |

Total for Option A: **≈1 week App + 1 day Dataset.** That is the cheapest real capability gain
available to this product, and it is entirely inside the owner's control.
