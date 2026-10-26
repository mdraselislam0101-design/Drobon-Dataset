# App-feature benchmark — our features, our engines, our user types (2026-10-25)

> `scripts/app-feature-benchmark.mjs` generates this page from `docs/APP_FEATURE_LEDGER.json` and
> `DROBON_PAID_TOOL_BENCHMARK.csv`; `--check` runs inside `npm test`.

**Deliverable work — 39 of 39 complete = 100%.** These are the requirements the
dataset can finish on its own. The other 13 are owned by the owner (licence, production intelligence,
product boundary, flow-schema adoption) or by the Main App repo; they are scored 0 and listed in §3 with
their real numbers, never folded into the 100%.

## 1. Per user type

| User type | Deliverable features | **Our score** | Comparable | Ours on those | GHAS | Snyk | Semgrep | Burp Pro | Gated (scored 0) |
|---|---|---|---|---|---|---|---|---|---|
| DEVELOPER | 17 | **100.0%** | 14 | 100.0% | 100.0% (n=14) | 92.9% (n=14) | 100.0% (n=14) | 50.0% (n=14) | 8 |
| STUDENT | 11 | **100.0%** | 7 | 100.0% | 100.0% (n=7) | 100.0% (n=7) | 100.0% (n=7) | 71.4% (n=7) | 6 |
| SECURITY_PROFESSIONAL | 25 | **100.0%** | 16 | 100.0% | 93.8% (n=16) | 96.9% (n=16) | 93.8% (n=16) | 50.0% (n=16) | 11 |
| PENTESTER | 15 | **100.0%** | 10 | 100.0% | 80.0% (n=10) | 100.0% (n=10) | 80.0% (n=10) | 70.0% (n=10) | 6 |

## 2. Per engine and user type

**SAST (App engine)**

| User type | Deliverable | **Score** | Comparable | Ours on those | GHAS | Snyk | Semgrep | Burp Pro |
|---|---|---|---|---|---|---|---|
| DEVELOPER | 4 | **100.0%** | 2 | 100.0% | 100.0% (n=2) | 50.0% (n=2) | 100.0% (n=2) | 100.0% (n=2) |
| STUDENT | 0 | — | 0 | — | — | — | — | — |
| SECURITY_PROFESSIONAL | 2 | **100.0%** | 1 | 100.0% | 100.0% (n=1) | 50.0% (n=1) | 100.0% (n=1) | 100.0% (n=1) |
| PENTESTER | 0 | — | 0 | — | — | — | — | — |

**SCA (App advisory seam)**

| User type | Deliverable | **Score** | Comparable | Ours on those | GHAS | Snyk | Semgrep | Burp Pro |
|---|---|---|---|---|---|---|---|
| DEVELOPER | 3 | **100.0%** | 2 | 100.0% | 100.0% (n=2) | 100.0% (n=2) | 100.0% (n=2) | 0.0% (n=2) |
| STUDENT | 1 | **100.0%** | 0 | — | — (n=0) | — (n=0) | — (n=0) | — (n=0) |
| SECURITY_PROFESSIONAL | 8 | **100.0%** | 4 | 100.0% | 100.0% (n=4) | 100.0% (n=4) | 100.0% (n=4) | 0.0% (n=4) |
| PENTESTER | 2 | **100.0%** | 0 | — | — (n=0) | — (n=0) | — (n=0) | — (n=0) |

**Secrets (App engine)**

| User type | Deliverable | **Score** | Comparable | Ours on those | GHAS | Snyk | Semgrep | Burp Pro |
|---|---|---|---|---|---|---|---|
| DEVELOPER | 4 | **100.0%** | 4 | 100.0% | 100.0% (n=4) | 100.0% (n=4) | 100.0% (n=4) | 0.0% (n=4) |
| STUDENT | 1 | **100.0%** | 1 | 100.0% | 100.0% (n=1) | 100.0% (n=1) | 100.0% (n=1) | 0.0% (n=1) |
| SECURITY_PROFESSIONAL | 4 | **100.0%** | 4 | 100.0% | 100.0% (n=4) | 100.0% (n=4) | 100.0% (n=4) | 0.0% (n=4) |
| PENTESTER | 3 | **100.0%** | 3 | 100.0% | 100.0% (n=3) | 100.0% (n=3) | 100.0% (n=3) | 0.0% (n=3) |

**DAST (App passive engine)**

| User type | Deliverable | **Score** | Comparable | Ours on those | GHAS | Snyk | Semgrep | Burp Pro |
|---|---|---|---|---|---|---|---|
| DEVELOPER | 0 | — | 0 | — | — | — | — | — |
| STUDENT | 0 | — | 0 | — | — | — | — | — |
| SECURITY_PROFESSIONAL | 1 | **100.0%** | 1 | 100.0% | 0.0% (n=1) | 100.0% (n=1) | 0.0% (n=1) | 100.0% (n=1) |
| PENTESTER | 4 | **100.0%** | 2 | 100.0% | 0.0% (n=2) | 100.0% (n=2) | 0.0% (n=2) | 100.0% (n=2) |

**Cross-engine (findings, remediation, reports, learning)**

| User type | Deliverable | **Score** | Comparable | Ours on those | GHAS | Snyk | Semgrep | Burp Pro |
|---|---|---|---|---|---|---|---|
| DEVELOPER | 6 | **100.0%** | 6 | 100.0% | 100.0% (n=6) | 100.0% (n=6) | 100.0% (n=6) | 83.3% (n=6) |
| STUDENT | 9 | **100.0%** | 6 | 100.0% | 100.0% (n=6) | 100.0% (n=6) | 100.0% (n=6) | 83.3% (n=6) |
| SECURITY_PROFESSIONAL | 10 | **100.0%** | 6 | 100.0% | 100.0% (n=6) | 100.0% (n=6) | 100.0% (n=6) | 100.0% (n=6) |
| PENTESTER | 6 | **100.0%** | 5 | 100.0% | 100.0% (n=5) | 100.0% (n=5) | 100.0% (n=5) | 100.0% (n=5) |

## 3. Gated — not ours to deliver (scored 0, listed in full)

| Requirement | Engine | Owner | Why it is gated | Real score |
|---|---|---|---|---|
| R-SCA-01 — npm advisory records match DependencyCoordinate(ecosystem,npm,name,version) | SCA | Owner | subreq (c) production breadth: 0/100,000 verified-production | 0.667 |
| R-SCA-02 — pypi advisory records match pypi coordinates | SCA | Owner | (c) breadth 0/100,000 | 0.667 |
| R-SCA-09 — staged fail-closed importer: pagination, cursor guard, dry-run, summary metrics, retry bounds | SCA | Owner | live run not performed (production lock); dry-run unproven against live API | 0.000 |
| R-SCA-10 — production advisory breadth toward the 100,000 planning target | SCA | Owner | owner decision / production authorization (see docs/BLOCKER_REGISTER.json) | 0.000 |
| R-SCA-11 — redistribution/license authorization for third-party advisory content | SCA | Owner | no LICENSE file; redistribution UNVERIFIED | 0.000 |
| R-SCA-16 — advisory refresh/re-review cadence | SCA | Owner | no cadence policy; seed frozen | 0.000 |
| R-SAST-P-03 — rule reachability under the Main App language catalog | SAST | Main App repo | 160 rules have no App language family (GAP-040): 5 gha rules unexpressible by decision + ~150 subformat tags | 0.840 |
| R-SAST-P-04 — flow/taint-level rules expressible in pack format | SAST | Owner | app taint flows (DG-SAST-048..050) have no pack representation | 0.500 |
| R-AUD-04 — app loaders for lessons/templates/engagements | CROSS | Main App repo | no loaders (SCOPE rows 16-18) | 0.000 |
| R-REM-02 — app merge-loader for knowledge/remediation | CROSS | Main App repo | no loader (SCOPE row 15) | 0.000 |
| R-REP-02 — SCA dependency findings + advisory provenance | CROSS | Owner | G: production intelligence not authorized (seed-only provenance) | 0.857 |
| R-REP-05 — Severity/CWE/confidence mappings (vs full CVSS/OWASP/prioritization) | CROSS | Owner | CVSS+OWASP+KEV/EPSS prioritization absent (lock + no fields) | 0.571 |
| R-REP-06 — Exploitability findings | CROSS | Owner | no exploitability engine; KEV/EPSS feeds locked | 0.000 |

Owner-gated: 10 · App-gated: 3.

## 4. Re-scores against the 2026-10-16 snapshot

| Feature | Was | Now | Evidence |
|---|---|---|---|
| R-SAST-P-09 | 0.000 (BLOCKED_APP_IMPLEMENTATION) | 1.000 (CLOSED_VERIFIED) | GAP-005 RESOLVED 2026-10-21: the App loads all 1,000 DPK-SAST rules and 4,043/4,043 declared tests reproduce. |
| R-SAST-P-10 | 0.000 (BLOCKED_MISSING_REQUIREMENT) | 1.000 (CLOSED_VERIFIED) | GAP-016 CLOSED 2026-10-21: the 1,000-rule SAST target is authored (docs/ENGINE_CAPACITY_2026-10-21.md). |
| R-SEC-P-06 | 0.000 (BLOCKED_APP_IMPLEMENTATION) | 1.000 (CLOSED_VERIFIED) | GAP-006 RESOLVED 2026-10-21, re-measured 2026-10-25 at 1,000 rules: 4,660/4,660 declared tests reproduce through the App converter. |
| R-DAST-P-04 | 0.000 (BLOCKED_APP_IMPLEMENTATION) | 1.000 (CLOSED_VERIFIED) | GAP-007 RESOLVED 2026-10-21: the App loads and evaluates the DAST pack; parity and reachability measured separately. |
| R-SAST-P-03 | 0.707 (BLOCKED_APP_IMPLEMENTATION) | 0.840 (BLOCKED_APP_IMPLEMENTATION) | Reachability re-measured 2026-10-25: 840/1,000 rules resolve through the App language catalog (interop/APP_CONFORMANCE.md §3). |

## 5. Method, in four lines

- Denominator: our own requirement rows (`REQUIRED` + `SUPPLEMENTAL`, 52). Weights: 1 per row, no averaging across engines.
- Our score: `VERIFIED_FULL = 1`, `VERIFIED_PARTIAL = passing/total`, every `BLOCKED_*` = 0.
- Vendor score, on the same comparable rows: `1.0` documented full, `0.5` partial/ambiguous, `0.0` documented absent, `UNKNOWN` excluded. Documented presence only — no vendor product was executed.
- 19 of the 52 rows are internal artifact quality (schema, executed tests, ReDoS, provenance, digests); no vendor documentation exists for them, so they are never scored for or against a vendor.

## 6. The deliverable features

| Feature | Engine | Class | User types | Score | Vendor capability used for comparison |
|---|---|---|---|---|---|
| R-SCA-03 — record->ScaAdvisory projection survives app closed guards (id/severity/summary/url bounds) | SCA | comparable | DEVELOPER, SECURITY_PROFESSIONAL | 1.000 | SCA vulnerability intelligence |
| R-SCA-04 — range semantics for 6 pinned range classes (npm semver subset + PEP 440 subset) | SCA | comparable | DEVELOPER, SECURITY_PROFESSIONAL | 1.000 | SCA vulnerability intelligence |
| R-SCA-05 — version-less coordinates never match; multi-file advisories collapse to one id | SCA | comparable | SECURITY_PROFESSIONAL | 1.000 | SCA vulnerability intelligence |
| R-SCA-06 — every real advisory carries source/sourceUrl/retrievedAt/license pointer | SCA | internal | PENTESTER, SECURITY_PROFESSIONAL | 1.000 | — (internal) |
| R-SCA-07 — identity (source,id,ecosystem,package) dedup; splits collapse; conflicts rejected | SCA | comparable | SECURITY_PROFESSIONAL | 1.000 | SCA vulnerability intelligence |
| R-SCA-08 — synthetic fixtures are labelled fixture:true, DROBON-SAMPLE ids, never production-promotable | SCA | internal | SECURITY_PROFESSIONAL | 1.000 | — (internal) |
| R-SCA-12 — datasetStatus honesty: NO_DATA_LOADED/DATASET_UNAVAILABLE; zero advisory fabrication | SCA | internal | DEVELOPER, PENTESTER, SECURITY_PROFESSIONAL, STUDENT | 1.000 | — (internal) |
| R-SCA-15 — intel integrity/versioning: SHA manifests + reproducible tree digest | SCA | internal | SECURITY_PROFESSIONAL | 1.000 | — (internal) |
| R-SAST-P-01 — SAST rule-pack schema validity (drobon.pack.sast/v1) | SAST | comparable | DEVELOPER, SECURITY_PROFESSIONAL | 1.000 | SAST custom rules |
| R-SAST-P-02 — every SAST rule has >=1 positive and >=1 negative executed test | SAST | internal | DEVELOPER | 1.000 | — (internal) |
| R-SAST-P-05 — every pack rule CWE resolves to knowledge/cwe entry | SAST | internal | SECURITY_PROFESSIONAL | 1.000 | — (internal) |
| R-SAST-P-06 — remediation entry per pack rule | CROSS | comparable | DEVELOPER, STUDENT | 1.000 | Remediation guidance/autofix |
| R-SAST-P-07 — ReDoS-safe rule patterns (linear-time contract) | SAST | internal | DEVELOPER | 1.000 | — (internal) |
| R-SAST-P-08 — rule-id stability: no reuse of retired ids (26 reserved) | SAST | internal | - | 1.000 | — (internal) |
| R-SAST-P-09 — app-side pack loader consuming DPK-SAST-* | SAST | comparable | DEVELOPER | 1.000 | SAST custom rules |
| R-SAST-P-10 — 1,000-rule SAST planning target | SAST | internal | - | 1.000 | — (internal) |
| R-SEC-P-01 — secrets rule-pack validity + executed tests | SECRETS | comparable | DEVELOPER, PENTESTER, SECURITY_PROFESSIONAL | 1.000 | Secrets detection |
| R-SEC-P-02 — redaction contract: all rules redact:true; tests carry no live values | SECRETS | comparable | DEVELOPER, PENTESTER, SECURITY_PROFESSIONAL, STUDENT | 1.000 | Secrets detection |
| R-SEC-P-03 — placeholder denylist veto semantics (case-insensitive) | SECRETS | comparable | DEVELOPER | 1.000 | Secrets detection |
| R-SEC-P-04 — evidence-only (header/carrier) rule contract | SECRETS | comparable | SECURITY_PROFESSIONAL | 1.000 | Secrets detection |
| R-SEC-P-05 — provider-class breadth (42 committed classes) | SECRETS | comparable | PENTESTER, SECURITY_PROFESSIONAL | 1.000 | Secrets detection |
| R-SEC-P-06 — app-side secrets pack loader (DPK-SEC-*) | SECRETS | comparable | DEVELOPER | 1.000 | Secrets detection |
| R-DAST-P-01 — DAST rule-pack over 7 closed check types; evaluator parity | DAST | comparable | PENTESTER, SECURITY_PROFESSIONAL | 1.000 | DAST passive analysis |
| R-DAST-P-02 — malformed-observation robustness (evalDastCheck total) | DAST | internal | PENTESTER | 1.000 | — (internal) |
| R-DAST-P-03 — passive-only boundary preserved in pack content | DAST | internal | PENTESTER | 1.000 | — (internal) |
| R-DAST-P-04 — app-side DAST pack loader (DPK-DAST-*) | DAST | comparable | PENTESTER | 1.000 | DAST passive analysis |
| R-CWE-01 — CWE knowledge entries: own-words + pinned MITRE URL | CROSS | internal | SECURITY_PROFESSIONAL, STUDENT | 1.000 | — (internal) |
| R-CWE-02 — all app-referenced CWEs resolve (15 app + 2 pack-only) | CROSS | internal | SECURITY_PROFESSIONAL, STUDENT | 1.000 | — (internal) |
| R-CWE-03 — CWE version pinning | CROSS | internal | SECURITY_PROFESSIONAL | 1.000 | — (internal) |
| R-AUD-01 — student lesson content with practice-validated examples | CROSS | internal | STUDENT | 1.000 | — (internal) |
| R-AUD-02 — assessment templates (never pre-authorize) | CROSS | internal | SECURITY_PROFESSIONAL | 1.000 | — (internal) |
| R-AUD-03 — pentester engagement aids (passive-only, banned-phrase lint) | CROSS | internal | PENTESTER | 1.000 | — (internal) |
| R-REP-01 — SAST findings report with source evidence (A contract B fields C intel D exec E evidence F e2e G prod-auth) | CROSS | comparable | DEVELOPER, SECURITY_PROFESSIONAL, STUDENT | 1.000 | Evidence + report exports |
| R-REP-03 — Secrets findings with safe evidence handling | CROSS | comparable | DEVELOPER, PENTESTER, SECURITY_PROFESSIONAL, STUDENT | 1.000 | Evidence + report exports |
| R-REP-04 — DAST findings with request/response evidence (passive) | CROSS | comparable | PENTESTER, SECURITY_PROFESSIONAL | 1.000 | Evidence + report exports |
| R-REP-07 — Remediation recommendations tied to findings | CROSS | comparable | DEVELOPER, STUDENT | 1.000 | Remediation guidance/autofix |
| R-REP-10 — Technical summary section of persisted report | CROSS | comparable | DEVELOPER, PENTESTER, SECURITY_PROFESSIONAL, STUDENT | 1.000 | Evidence + report exports |
| R-REP-12 — Forensic/evidence report (integrity digests, point-in-time) | CROSS | comparable | PENTESTER, SECURITY_PROFESSIONAL | 1.000 | Evidence + report exports |
| R-REP-13 — UserType-specific report views (4 journeys) | CROSS | comparable | DEVELOPER, PENTESTER, SECURITY_PROFESSIONAL, STUDENT | 1.000 | Evidence + report exports |

Verify: `node scripts/app-feature-benchmark.mjs --check`. Regenerate: `--write`.
