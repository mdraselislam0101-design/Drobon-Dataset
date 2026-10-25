# DAST capability-aligned expansion — tranches 2 and 3 (500-target pump) — 2026-10-20

Repository: `mdraselislam0101-design/Drobon-Dataset` · branch `arena/a4caaeb8-drobon-dataset`
· HEAD `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged for the whole pump).

Method: Dataset-only, one cumulative run. The Main App was read-only; **no git object was
written** (no commit, branch, tag, push, reset, clean or restore). This report is new; the earlier
`docs/DATASET_CAPABILITY_ALIGNED_COMPLETION_AUDIT_2026-10-20.md` and
`docs/DAST_CAPABILITY_ALIGNED_500_2026-10-20.md` are kept unchanged as history and remain correct
for the state they describe.

---

## 1. Repository, branch, HEAD and worktree

| Item | Before this run | After this run |
|---|---|---|
| Branch | `arena/a4caaeb8-drobon-dataset` | unchanged |
| HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` | unchanged |
| Worktree entries | 4,863 (2,461 M / 2,402 ??) | 5,464 (2,461 M / 3,003 ??) |
| `LICENSE` | absent | absent (invariant kept) |
| `docs/OWNER_DECISIONS.json` | untouched | untouched (`git diff` empty) |

The 601 new entries are: 2 cell batches (`data/asset-cells/dast-19.json`, `dast-20.json`),
99 rules, 99 patterns, 99 records, 99 remediation entries, 198 evaluation cases, 4 CWE entries and
this report, together with the regenerated count-bearing documents. The per-type list is what the
run wrote; the 601 figure is the measured `git status` delta (5,464 − 4,863), and the per-type list above is
what the run wrote. Nothing was deleted: the
only removals in the repository remain the 4 evaluation cases and 8 generated files withdrawn in
the earlier pump for the two rules retired as `DPK-DAST-151`/`-154`.

## 2. Verified capability evidence used

The scanner contract used here is the repository's own evaluator, `evalDastCheck()` in
`scripts/validate-packs.mjs` (L349). It implements exactly **seven** check types:

`response-header-matches` · `missing-response-header` · `response-header-missing-directive` ·
`cookie-missing-flag` · `response-header-host-differs` · `http-url` · `response-body-matches`

Each observation is `{url, status, headers, body, contentType}` with a closed key vocabulary; the
evaluator trims header values (RFC 7230 §3.2.4), matches every header/body pattern case-insensitively,
never throws on a malformed observation, and gates `requireScheme` on the observation URL. The
Contract (`docs/DATASET_APP_CONTRACT.md`) documents these as the supported DAST surface. No new check
type was proposed, enabled or simulated. No App code was read this run; the capability statements
above come from the Dataset's own contract and evaluator, not from a new App inspection.

## 3. Actual starting and final counts

| Item | Before | After | Delta |
|---|---|---|---|
| DAST rules (detections) | 153 | **252** | **+99** |
| Distinct check types used | 7 | 7 | 0 |
| Headers with at least one rule | 47 | **54** | +7 |
| DAST rule tests | 812 | **1,208** | +396 |
| DAST evaluation cases | 289 | **487** | +198 |
| Pack rules (950 SAST + 97 secrets + DAST) | 1,200 | **1,299** | +99 |
| Patterns / records / remediation | 1,200 each | **1,299 each** | +99 |
| CWE entries | 63 | **67** | +4 |
| Evaluation cases (all cohorts) | 1,390 | **1,588** | +198 |
| Retired reservations | 29 | 29 | 0 (no ID retired this run) |

## 4. Unique DAST detection count and the exact counting method

**252 distinct detections.**

One detection = **one rule file** `packs/dast/v1/rules/DPK-DAST-*.json` = a triple of
**(check type, target, semantic condition)**:

- *check type* — one of the seven above;
- *target* — the response header name, the `Set-Cookie` attribute, or the body marker set;
- *semantic condition* — the property asserted about that target (a value shape, a token, a
  scheme, a missing directive, a body fingerprint).

Two rules that share a header but ask different questions are two detections (e.g.
`Content-Security-Policy` `img-src` wildcard vs `img-src` `http:` scheme). Two rules that report the
same evidence under different wording are one detection; one such pair was found in this run and
withdrawn before it reached the tree (see §9).

## 5. Supporting objects, counted separately and never summed

| Ledger | Count | Unit |
|---|---|---|
| Detections | 252 | rule file |
| Evidence definitions | 252 | one closed-key `check` object per rule |
| Patterns | 1,299 | `knowledge/patterns/*.json` (1:1 with all rules) |
| Records | 1,299 | `knowledge/records/*.json` |
| Remediation entries | 1,299 | `knowledge/remediation/*.json` |
| Rule tests | 1,208 | positive and negative observation examples inside the rules |
| Evaluation cases | 487 DAST (1,588 all cohorts) | `data/eval-cases/EVAL-DAST-*.json` |

**252 detections are not 252 + 1,208 + 487.** The tests and cases are evidence *for* the
detections, not additional detections, and are never added to the headline number.

## 6. Per-category coverage and justified exclusions

| Category | Rules | What the tranche added |
|---|---|---|
| information-disclosure | 60 | 12 sensitive-artefact disclosures, generator meta tags, API description |
| debug-exposure | 57 | 21 management/debug consoles and debug toolbars |
| security-headers | 43 | COEP/CORP/XPP/Permissions-Policy token validity, obsolete headers |
| csp-weakness | 36 | 8 directive `http:` schemes, 2 `'unsafe-hashes'`, `'wasm-unsafe-eval'`, `data:` fallback |
| cors | 15 | multi-origin, bare scheme, userinfo, invalid Max-Age, credentials token, Authorization, TRACE |
| transport-security | 14 | Secure cookie over plaintext |
| cookie-flags | 8 | Max-Age, duplicate SameSite, relative Path |
| open-redirect | 7 | Location script scheme, Refresh `data:` |
| response-headers | 6 | multipart without boundary |
| cache-control | 3 | public + no-store contradiction, invalid Expires |
| mixed-content | 2 | — (unchanged) |
| http-methods | 1 | — (unchanged) |

Excluded, with reasons, in §13. The largest exclusions are whole families that need check types
this scanner does not have.

## 7. Positive, negative and boundary evaluation

| Measure | Value |
|---|---|
| Rule tests | 1,208 total — **542 positive**, **666 negative** |
| Every rule has ≥1 positive and ≥1 negative test | yes (validator floor: `tests` 2..N) |
| Evaluation cases | 487 DAST — **254 positive + 233 negative** cases |
| Cases that pass | all 487 |
| Boundary/malformed coverage | each positive fixture is paired with a near-miss negative that keeps the surface (same header present with a benign value, or the body with the markers removed); every rule also has a "hostile but different surface" negative (a different header, or a normal page) |

The near-miss negatives are not cosmetic: the pre-write harness fails a candidate whose negative
still matches, and it found 51 such mismatches across tranches 2–3 before any file was written.

## 8. False positives, false negatives, unassessed

| Measure | Value |
|---|---|
| True positives | **1,325** |
| False negatives | **0** |
| False positives | **1** — the documented `EVAL-SAST-008` mutation case, preserved |
| UNASSESSED | **11** — the pinned independent-evaluation cases, untouched |
| Precision on the assessed population | 1,325 / 1,326 = **0.9992** |

Additionally, all 99 new rules were run against four benign observations (a sign-in page, a JSON API
response, a fully hardened page, and a redirect with a correct cookie) — **0 false-positive hits**.
That check is a scratch harness result, not a committed gate; the committed equivalents are the
negative tests inside each rule.

## 9. Duplicate, overlap, provenance and regex safety

- **Regex safety** — every pattern passes `lintRedos()`; the scratch harness found **51** rejected or
  mismatched patterns in tranches 2–3 (14 and 37) and every one was rewritten rather than loosened.
  The lint itself was not edited.
- **Duplicate signal** — the harness compared every candidate `check` object against the then-current
  corpus: 0 byte-identical. The committed gate re-checks this on every run.
- **Evidence-subset gate** (`validate-dast-overlaps.mjs`): **321 checks, 128 subset pairs**, of which
  **123** are EXPECTED_ABSENCE_COVERAGE (the wider rule observes a missing header/directive) and **5**
  carry reviewed ledger entries (1 `BLOCKED_PENDING_OWNER_DECISION`, 4 `REVIEWED_RETAINED`).
  **The 128 pairs are the same set as before this run** — the 99 new rules added no subset pair.
- **One candidate was withdrawn before any repo write**: `hsts-preload-without-includesubdomains`
  (every case it reports is already reported by `DPK-DAST-049`, which flags HSTS without
  `includeSubDomains`). No ID was consumed, so the retired-reservation list is unchanged at 29.
- **Gate blind spot found and reported, not hidden**: the overlap gate skips rules with no header, so
  body-fingerprint rules are never compared with each other programmatically. For those, the scratch
  harness ran the reverse test (does any existing body rule fire on all positives of a candidate) —
  0 hits — and the 62 body rules are additionally reviewed for marker distinctness. This is a known
  limitation of the gate, recorded here rather than papered over.
- **Provenance** — every rule comes from a cell in `data/asset-cells/dast-19.json` or `dast-20.json`
  with `framing: 'custom'`; patterns, records and remediation are generated from those cells and
  carry the manifest lineage. Evaluation cases carry
  `provenance.expectationAuthoredBeforeFirstRun: true`, `synthetic: true`, `testOnly: true`.
- **Leak pre-screen interaction** — the generator refused two cells (`body-private-key-block`,
  `body-aws-credentials-file`) because their fixtures contained PEM and `AKIA`-shaped material
  outside `packs/secrets`. That guard is correct: the fixtures were rewritten to name the file
  shapes without carrying key material, and the rules match the **key names and PEM markers**, not
  secret values. No fixture contains a credential.

## 10. Test commands, exit codes and final measurements

All run after the final edit, from the repository root.

| Command | Exit | Result |
|---|---|---|
| `npm test` | **0** | 22 gates, **22,135 `ok` lines, zero FAIL/NOT OK** (run last, after every edit including this report) |
| ↳ `scripts/test.mjs` | 0 | 600/600 |
| ↳ `scripts/test-packs.mjs` | 0 | 5,378/5,378 (DAST 252 rules, 1,208 tests) |
| ↳ `scripts/validate-dast-overlaps.mjs` | 0 | 321 checks, 128 pairs, PASS |
| ↳ `scripts/test-assets.mjs` | 0 | 10,412/10,412 |
| ↳ `scripts/test-csp-semantics.mjs` | 0 | 22,983 assertions |
| ↳ `scripts/test-cookie-semantics.mjs` | 0 | 1,968 assertions |
| ↳ `scripts/test-consistency.mjs` | 0 | 230/230 |
| ↳ `scripts/test-eval.mjs` | 0 | 43/43 |
| ↳ `scripts/test-doc-drift.mjs` | 0 | 120/120 |
| ↳ `scripts/test-current-state.mjs` | 0 | 155/155 |
| ↳ `scripts/validate-capability-coverage.mjs` | 0 | 695/695 |
| ↳ determinism | 0 | 5/5 |
| `node scripts/generate-assets.mjs` | 0 | sast 928 · secrets 89 · dast 252 · patterns 1,299 · records 1,299 · remediation 1,299 · `quarantined: []` |
| `node scripts/validate-packs.mjs` | 0 | PASS (1,302 files, 0 errors) |
| `node scripts/validate-assets.mjs` | 0 | PASS (2,598 files, 0 errors) |
| `node scripts/validate-cwe.mjs` | 0 | PASS (67 files, 0 errors) |
| `node scripts/run-eval.mjs` | 0 | 1,588 cases · 1,577 assessed · 11 UNASSESSED · TP 1,325 · FP 1 · FN 0 |

**Two real harness defects were found by this growth and fixed at the source, not worked around:**

1. `scripts/test-eval.mjs` raised `maxBuffer` on **both** full-run reads of `run-eval`. The second
   read still used Node's 1 MiB default and died with `spawnSync ENOBUFS` once the report grew past
   it. A transport limit was fixed; no expectation was relaxed.
2. `scripts/test-consistency.mjs` `runToString()` had the same 1 MiB limit and died the same way on
   the 1,299-rule manifest. Same fix, same reasoning.

Neither change alters what is asserted.

## 11. Owner decisions and unresolved blockers (unchanged)

| Blocker | State | Consequence |
|---|---|---|
| BLK-001 / BLK-002 — no `LICENSE`, no written redistribution grant | open | publication stays **NO-GO** |
| OD-1 — `DPK-DAST-050` overlap with `DPK-DAST-056` | open | ledger entry stays `BLOCKED_PENDING_OWNER_DECISION` |
| D-13 | inactive, file untouched | the 40-record condition is closed; the decision is an owner act |
| GAP-005/006/007 — App pack loaders | open | the 252 rules are not reachable at runtime; no App integration is claimed |
| SCA production intelligence | `RIGHTS_BLOCKED` | no advisory matching data |

## 12. Main App and git — explicit confirmations

- **Main App not modified**: no file in `mdraselislam0101-design/Drobon` was created, edited or
  deleted this run; the App clone used for earlier capability reads was not opened.
- **No git operation** was performed: no commit, branch, tag, push, pull request, merge, reset,
  clean, restore or history rewrite. `HEAD` is unchanged and the worktree changes are left
  uncommitted, as the constraints require.

## 13. The 500 target: what is delivered, and what is not countable

**252 of 500 (50.4%).** The target is not met and is not claimed.

The remaining 248 are not "missing rules that someone forgot to type". They fall into families that
are blocked by the scanner contract, by evidence, or by rights — each would be a fabricated detection
if written today:

| Blocked family | Why it cannot be counted now | What would unblock it |
|---|---|---|
| Request/response correlation (e.g. `Authorization` echoed into `Location`, cache key chaos, `Vary` missing beside a reflected origin) | the evaluator sees one response and has no request object; a single-header rule would guess | a check type that carries the request |
| Preflight semantics / exploitable CORS | needs the request `Origin` and the actual request, not just the response headers | request-context observation |
| Session-cookie reasoning (is this cookie a session cookie? prefix enforcement `__Host-`/`__Secure-`) | the response has no session, no jar and no clock; the repo's own cookie model states prefix enforcement is not applied | a session/jar model in the contract |
| TLS protocol, cipher, certificate-chain findings | cannot be inferred from an HTTP response | TLS inspection capability |
| Authenticated, stateful, multi-step flows (auth bypass, CSRF exploitability, session fixation) | requires authenticated crawling and state | authenticated scanning capability |
| Active injection (SQLi/XSS/SSRF proof, payload reflection) | requires sending payloads; this Dataset is passive-observation only | active engine, explicitly out of scope |
| Browser execution (DOM XSS, CSP bypass proof, mixed-content blocking proof) | requires a browser engine | browser-execution capability |
| `script-src-attr`/`style-src-attr` `'unsafe-inline'` | withdrawn earlier as an evidence subset of `DPK-DAST-021` | owner decision to rescope `DPK-DAST-021` |
| `hsts-preload-without-includeSubDomains` | withdrawn this run: evidence subset of `DPK-DAST-049` | owner decision to split `DPK-DAST-049` |
| Duplicate-cookie folding, header smuggling | the parser cannot distinguish a folded header from one string with the same bytes | a stricter header model in the contract |

What *could* still be authored legitimately inside today's contract is a further set of per-product
body fingerprints and per-header value rules. They were deliberately **not** mass-produced: past
roughly this point the marginal detection repeats an existing question about a different product
name, and the pump's own rule is that a detection counts only when it is semantically distinct and
useful. Padding the number would be exactly the manufactured completeness the brief forbids.

## 14. Verdict

**PARTIAL.**

- 252 capability-justified, tested, evaluated, overlap-reviewed DAST detections exist; every
  repository gate is green after the final edit.
- The 500 target is **not reached** (50.4%) and the gap is enumerated above with the capability or
  decision that blocks each family.
- The Dataset as a whole cannot be called COMPLETE: the license/rights grant, the App pack loaders
  and the SCA intelligence gate are all outside this pump's authority.
- Publication: **NO-GO** (no license, `BLK-001`/`BLK-002` open).
- App integration: **NOT VERIFIED and not claimed**.

Decisions needed next, in order: (1) owner license/rights grant; (2) OD-1 for `DPK-DAST-050`;
(3) owner closure of D-13; (4) engineering decision on GAP-005/006/007, which is what would make any
of these 252 rules runnable; (5) if more detections are wanted, the honest next step is a contract
change for request context, not more single-header rules.
