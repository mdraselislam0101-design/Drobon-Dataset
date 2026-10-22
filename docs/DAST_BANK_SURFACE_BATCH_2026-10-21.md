# DAST bank-surface batch — 2026-10-21

Status: **10 new rules authored, all App-reachable by construction.** DAST **500 → 510**;
reachability **437/510 = 85.7 %** (the 73 header-blocked rules are unchanged, so the
percentage moves only because the denominator grew).

This batch was requested with a banking question: *can these rules stop a hacker from
damaging a bank website?* The short answer is **no, and this batch does not pretend
otherwise** — it adds detection for the banking evidence the pack could already see and did
not name. The separate honesty document for the "protect / prevent" question is
`docs/BANK_THREAT_COVERAGE_2026-10-21.md`.

## 1. The 10 rules

| Rule | Title | Category | CWE | Severity | Why a bank specifically |
|---|---|---|---|---|---|
| DPK-DAST-510 | Account number carried in a link URL | credential-exposure | CWE-598 | MEDIUM | Account numbers in links persist in history, logs and Referer headers |
| DPK-DAST-511 | Bank account number served together with a balance | privacy-exposure | CWE-359 | HIGH | Account + balance is the pair fraud teams use to target high-value accounts |
| DPK-DAST-512 | Payment form submits card fields with GET | credential-exposure | CWE-598 | MEDIUM | Card values land in URLs, access logs and proxy logs |
| DPK-DAST-513 | Card verification value rendered into a form field | privacy-exposure | CWE-359 | HIGH | A printable CVV means it was stored — a direct card-data violation |
| DPK-DAST-514 | One-time passcode served in a response | credential-exposure | CWE-522 | HIGH | An OTP in a payload removes the second factor it exists to provide |
| DPK-DAST-515 | Card PIN value served in a response | credential-exposure | CWE-522 | HIGH | PIN + PAN allows cash withdrawal; the PIN cannot be rotated without reissuing |
| DPK-DAST-516 | Security answer rendered into a form field | credential-exposure | CWE-522 | MEDIUM | The recovery answer bypasses the password and the OTP together |
| DPK-DAST-517 | Session identifier carried in a URL | credential-exposure | CWE-598 | MEDIUM | URL rewriting hands the authenticated session to logs and shared links |
| DPK-DAST-518 | Account statement exported as a CSV row set | privacy-exposure | CWE-359 | MEDIUM | A statement export is a ready-made fraud dataset |
| DPK-DAST-519 | SWIFT/BIC code served with an account reference | privacy-exposure | CWE-359 | MEDIUM | The beneficiary pair behind payment-diversion fraud |

Every one reads the response body only — no new header dependency, so **all 10 are
reachable inside the Main App** and the unreachable set stays at 73.

## 2. Candidates dropped before writing

| Candidate | Why it was not written |
|---|---|
| OTP in `Location` | Its evidence is already the question `DPK-DAST-507` asks (bare token in a redirect query string) |
| `autocomplete` allowed on password fields | Legitimate password-manager behaviour; the false-positive rate would be unacceptable and the finding is not evidence of a defect |
| `WWW-Authenticate: Basic` on a banking endpoint | `WWW-Authenticate` is not one of the 11 headers the App forwards, so the rule could never fire inside the product |
| Card PAN in an HTML comment | Already covered by `DPK-DAST-502` (credential in an HTML comment) |
| Bulk account-number list | The evidence overlaps the existing bulk-PII family (`DPK-DAST-481/482`) and the overlap gate treats it as a subset |
| "TEST MODE" banner on a payment page | Not evidence of a defect on its own; the pack requires an observable failure mode |

## 3. Verification

| Gate | Result |
|---|---|
| `node scripts/generate-assets.mjs` | 6,183 files written, `quarantined: []` |
| `node scripts/validate-packs.mjs` | PASS — 1,560 files, 0 errors |
| `node scripts/test-packs.mjs` | PASS — 6,410/6,410 (each new rule: positive + negative declared tests) |
| `node scripts/test-assets.mjs` | PASS — 12,476/12,476 (linkage 1,557 rule ↔ 1,557 pattern) |
| `node scripts/validate-dast-overlaps.mjs` | PASS — 579 checks, 130 subset pairs |
| `node scripts/validate-app-dast-reachability.mjs --check` | 437/510 reachable (85.7 %), 73 blocked across 47 headers |
| `node scripts/run-eval.mjs` | cohort `dast-bank-surface-2026-10-21`: **12 cases, 10 TP, 0 FN, 0 FP**; dataset totals 1,888 cases, TP 1,583, FN 0, FP 1 |
| `node scripts/test-doc-drift.mjs` · `test-current-state.mjs` · `validate-capability-coverage.mjs` | 120/0 · 157/0 · 710/0 |
| `node scripts/gen-app-conformance.mjs --check` | 15/2,182 declared DAST tests diverge (all on rules ≤ 190, unchanged) |
| `node scripts/completion-ledger.mjs` | OK — 21 dimensions reproduce |

The two negative controls (`EVAL-DAST-776`, `777`) name **all 10 new rule ids** as forbidden:
a hardened account page with a masked number, and a help page that discusses passcodes,
PINs, CVVs and BIC codes in prose without serving one.

## 4. What this does *not* change

- **510 authored is still not 510 evaluable.** 73 rules need the App header decision
  (`GAP-048`); 437 are reachable today.
- **A scanner detects weaknesses; it does not stop an attack.** Nothing in this batch can
  block a request, patch a library or respond to an intrusion. See
  `docs/BANK_THREAT_COVERAGE_2026-10-21.md` §4 for the layers a bank actually needs.
- **No live bank was scanned.** Every fixture is synthetic; no request was sent.
- **No licence.** The corpus remains `NOT_ELIGIBLE_NO_LICENSE` (G6) until the owner decides.
