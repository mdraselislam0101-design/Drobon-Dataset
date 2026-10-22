# Can these packs protect a bank website? — 2026-10-21

**Short answer: no.** A scanner observes and reports; it does not block, patch or defend.
What this repository gives a bank is a **detection layer of 510 passive checks (437 of them
reachable inside the Main App today)**, and that layer is real but narrow. Anyone who says a
rule pack "protects" a bank is describing a firewall as a smoke detector.

This page exists so the claim can never be made by accident: it separates **what the packs
can see**, **what they structurally cannot see**, and **what a bank must run instead** for
actual protection.

App reference (read-only): `mdraselislam0101-design/Drobon` @ `9360dd1`.

---

## 1. What the packs can see (and how much)

Counts recomputed from `packs/dast/v1/rules` on 2026-10-21 (510 rule files):

| Bank-relevant weakness family | Rules | Detects | Blind to |
|---|---|---|---|
| Security headers, CSP, response contracts | 46 + 43 + 7 | Missing/weak HSTS, CSP, XFO, COOP/COEP/CORP, Referrer-Policy | Whether a browser actually enforces them for this user |
| Cookie and session hygiene | 19 + 2 | `Secure`/`HttpOnly`/`SameSite`, `__Host-` prefix, expiry/`Max-Age` conflicts | Server-side session fixation, missing rotation after login |
| CORS | 15 | Wildcard origin with credentials, reflected origin, null origin | Whether an attacker can reach the credentialed endpoint |
| Personal and financial data in responses | 26 | Card PAN, IBAN, Aadhaar, NID, SSN/SIN/NI, passport/MRZ, IMEI, VIN, salary, TIN, coordinates, bulk lists, **account+balance, statements, CVV, PIN, OTP, recovery answers** | Data that never reaches an HTTP response (database at rest, exports by mail) |
| Credentials and tokens in responses | 38 | JWT/API keys/passwords/connection strings, hashes, session ids in JSON and **in URLs** | Secret storage, key rotation, leaked secrets in source or CI |
| Information and debug disclosure | 161 + 88 + 5 | Config artefacts, backups, consoles, stack traces, source files, `.git`/`.env` | Anything behind authentication |
| Transport and mixed content | 14 + 5 | `http://` targets, subresources over plaintext | Certificate validity, cipher suites, TLS version, HSTS preload status |
| Clickjacking, markup trust, injection surfaces | 8 + 8 | Framing controls, `data:`/protocol-relative sinks, `target=_blank` | Stored XSS, SQLi, business-logic abuse |
| Open redirects | 8 | Redirect targets built from request data | Whether the redirect is chained into a phishing flow |
| Caching of sensitive pages | 3 | `Cache-Control`/`Pragma` absent on sensitive responses | CDN and proxy configuration outside the response |

**Total 510 rules, 437 reachable in the product, 73 blocked by the 11-header response surface
(`GAP-048`).** On top of the DAST family the repository carries 950 SAST and 97 secrets rules;
those inspect a bank's *own code* before it ships, which is where most banking defects are
actually found.

## 2. What the packs structurally cannot see

| Blind spot | Why | Consequence for a bank |
|---|---|---|
| **Anything behind login** | The engine never authenticates; it sends at most 3 requests and does not log in | Net-banking, transfer, statement, admin and card-management screens are **invisible** |
| **Business logic** | No rule can express "transfer limit bypass", "OTP skip", "double-spend", "beneficiary swap" | The failures that actually move money are out of scope |
| **Authorization (IDOR)** | Requires two identities and a baseline | A bank could pass every rule and still let customer A read customer B's statement |
| **Injection depth** | Active mode is bounded: GET only, ≤10 synthetic injections, no POST bodies | No real SQLi/XSS confirmation, no authentication-bypass probing |
| **TLS and certificates** | The observation model has no certificate, cipher or protocol fields | Expired, weak or misissued certificates are never reported |
| **Runtime defence** | Passive observation of one response | No WAF effectiveness, no rate-limit test, no DDoS, no bot detection, no malware on the customer device |
| **Fraud and account takeover** | Not observable in an HTTP response | Device fingerprinting, impossible-travel, mule accounts, social engineering |
| **Supply chain** | Advisory ingestion is blocked by the production-data lock (`GAP-001`: 0 of 100,000) | No CVE matching for the bank's dependencies beyond the 102 frozen GHSA seed records |
| **Real-site precision** | Every test is a synthetic fixture | The false-positive rate on a live bank estate is **unmeasured** |

## 3. Where the honest numbers sit

| Measure | Value | Note |
|---|---|---|
| Authored DAST rules | 510 | 500 planning target + 10 bank-surface rules added 2026-10-21 |
| Reachable inside the App | 437 (85.7 %) | The other 73 need the App header allowlist (`GAP-048`) |
| Independent evaluation cases | 1,888 | Synthetic observations; TP 1,583, FN 0, FP 1 (documented `EVAL-SAST-008`) |
| Declared DAST tests | 2,182 | 15 diverge from the App evaluator (`GAP-041`) |
| Real-world effectiveness | **not measured** | No live bank, no production corpus; never extrapolate the synthetic numbers |
| Licence status | **no grant** | `G6 = BLOCKED_OWNER_DECISION`; the corpus cannot be distributed or sold yet |

## 4. What actually protects a bank website

Ordered by how much damage they prevent, with the honest note of who owns each:

| Layer | What it does | Owner | Is it in this repository? |
|---|---|---|---|
| Patching and vulnerability management | Removes the known flaw before it is used | Bank IT | **No** |
| WAF + rate limiting + bot management | Blocks or slows the request in flight | Bank infrastructure | **No** |
| Secure SDLC: SAST + SCA + secrets scanning in CI | Catches the flaw before deployment | Bank engineering | **Partly** — 950 SAST + 97 secrets rules exist; SCA intel is locked (`GAP-001`) |
| Authenticated DAST / pentest | Finds authorization and business-logic defects | Bank security team | **No** — needs App work first |
| MFA, transaction signing, tokenisation, HSM | Limits the value of a stolen credential | Bank product | **No** |
| Logging, SIEM, SOC, incident response | Detects and contains an attack in progress | Bank operations | **No** |
| Backups, DR, segmentation | Survives the attack | Bank IT | **No** |
| **Passive response hygiene checks (this pack)** | Reports the observable weaknesses above, cheaply and without sending payloads | This repository | **Yes — that is the whole contribution** |

The pack sits at the **bottom** of that list by impact and at the **top** by safety: it sends
no payloads, needs no credentials and cannot damage a target. That is exactly why it is useful
as a first filter — and exactly why it cannot be sold as protection.

## 5. What must be fixed before a bank pilot (App side, not dataset side)

| Gap | What it blocks | Owner |
|---|---|---|
| `GAP-048` | 73 DAST rules cannot fire — the App forwards only 11 response headers | App code change / owner decision |
| `GAP-040` | 160 SAST rules cannot fire — 66 language ids have no App family | App catalog |
| `GAP-041` | 15 declared DAST tests disagree with the App evaluator | App evaluator |
| `GAP-042` | Loader implements 2 of 6 checklist steps (no schema validation, no ReDoS budget, no load-time tests) | App loader |
| `GAP-047` | The App's own test suites fail at `9360dd1` | App |
| `GAP-045` | Active DAST exists in the App while both repos' boundaries say it is out of scope | Owner decision |
| `G6` / `GAP-002` | No licence grant: the corpus cannot be distributed to a bank today | Owner |

Dataset-side blocking work: **none.** The three open dataset rows are evidence-gated breadth
(`GAP-016`), a language alias (`GAP-014`) and a denylist ruling (`GAP-024`); none of them
stops a pilot.

## 6. Legal and authorization (before any bank is touched)

- Scanning a bank website **without written authorization is unauthorized access** and is a
  criminal risk under Bangladesh's ICT Act 2006 and equivalent law elsewhere. A signed scope,
  a named contact and a time window are prerequisites, not formalities.
- Even with authorization, run **passive mode only** against production; keep active mode for a
  staging copy the bank controls.
- Every finding must be phrased as **"observed evidence, exploitation not attempted"** — the
  pack reports evidence, never confirmed exploitability.

## 7. Bottom line

> The packs can tell a bank **which weaknesses are visible in its public responses** — and the
> 2026-10-21 bank batch adds the banking-specific ones (OTP, PIN, CVV, session-in-URL,
> account+balance, statement export, BIC pair). They cannot stop an attacker, cannot see
> behind a login, and cannot judge business logic. A bank needs patching, a WAF, an
> authenticated pentest and a SOC for that. Present this as **a detection filter that is safe
> to run**, never as protection.

Verification for every number on this page:
`node scripts/test-current-state.mjs`, `node scripts/validate-capability-coverage.mjs`,
`node scripts/validate-app-dast-reachability.mjs --check`,
`node scripts/gen-app-conformance.mjs --check`, `node scripts/run-eval.mjs`.
