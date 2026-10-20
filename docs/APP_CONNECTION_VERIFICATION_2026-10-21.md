# Main App ↔ Dataset connection — independent verification (2026-10-21)

**Verified by:** read-only review + an executable probe of the Main App at
`9360dd1` (shallow clone in this sandbox, `npm ci` + `npm run build --workspace
@drobon/shared`, both exit 0), against this repository's tree at branch
`arena/9155a3b1-drobon-dataset` (`24c929b`). Dataset suite re-run here:
`npm test` → 695 passed, 0 failed.

| Repository | Revision verified | Notes |
|---|---|---|
| `mdraselislam0101-design/Drobon` (Main App) | **`9360dd101`** (main, 2026-10-20T20:45Z) | 6 commits ahead of the revision this repo pinned (`c32c797`, 2026-10-14) |
| `mdraselislam0101-design/Drobon-Dataset` (this repo) | `24c929b` / main `fb2eab0` | counts re-derived from the tree |

**Headline:** the connection is **real and working** — the App now loads
`vuln-intel`, all three rule packs, remediation, CWE and the audience datasets
from `DATASET_PATH` through a filesystem provider, and SCA matching produces
verified advisories. It is **not finished**: the App ships **zero** embedded
rules now, 16 App tests fail at `9360dd1`, 9 of the App's DAST checks disagree
with this repository's own executable semantics, 160 SAST rules can never fire
because 66 pack language ids have no App family, and 1,310 remediation entries are
loaded but never surfaced.

---

## সারসংক্ষেপ (Bengali summary)

- কানেকশন **কাজ করছে**: 100 অ্যাডভাইজরি, 950/97/263 রুল, 1310 remediation, 68 CWE,
  6 lesson, 3 template, 2 engagement — সব লোড হয়; SCA ম্যাচিং প্রমাণসহ কাজ করে।
- কিন্তু **অ্যাপে এখন নিজের কোনো রুল নেই** (SAST/Secrets/DAST/Lesson সব খালি) ⇒
  ডিফল্ট সেটিংয়ে (`VULN_INTEL_PROVIDER=none`) অ্যাপ **কিছুই Detect করে না**।
- **16টি অ্যাপ টেস্ট ফেল** (api 785/801, shared 182/183) — ডকে 812/812 লেখা।
- DAST-এ ৯টি রুলের ১৫টি declared test অ্যাপের সাথে মেলে না (cookie মডেল সরলীকৃত)।
- ৯৫০ SAST রুলের মধ্যে **১৬৭টি অ্যাপে কখনো চলবে না** (ভাষা-আইডি ক্যাটালগে নেই)।
- ১,৩১০ remediation লোড হয় কিন্তু **কোথাও দেখানো হয় না** (dead path)।
- Active DAST (crawl + payload) যোগ হয়েছে — দুই রিপোর লিখিত সীমার সাথে সাংঘর্ষিক।

---

## 1. What the App changed (6 commits, 2026-10-20)

| Commit | Title |
|---|---|
| `ff1e11c` | feat(web): premium paid-tool polish |
| `e83f8c0` | feat(dataset): connect Drobon-Dataset via filesystem provider seam |
| `0218c34` | feat(dataset): unlock all UserType engines + SAST/DAST/SCA packs via dataset filesystem |
| `e65d048` | dataset decoupling: delete embedded data from main app (paid-tool parity) |
| `f299eb7` | feat(dast): add Passive + Active Safe DAST skeleton (crawl+injection, consent-gated, bounded) |
| `9360dd1` | Merge PR #5 |

Diff `c32c797...9360dd1`: 63 files, +3,858 / −2,953. New: `apps/api/src/external/`
(9 files: service, packProvider, packIntegration, evaluator, knowledge,
lessonProvider, routes, types), `apps/api/src/scans/sca/filesystemProvider.ts`,
`sca/range.ts` (541 lines, a copy of this repo's range semantics),
`dast/activeEngine.ts` + `crawler.ts` + `payloads.ts`, `docs/DATASET_CONNECTION.md`.
Deleted: the App's embedded rule content (`sast/rules.ts` −780, `secrets/rules.ts`
−501, `dast/rules.ts` −197, `student/lessons.ts` −360,
`remediationGuidance.ts` −125).

## 2. Verified working (executable probe against this repository)

Probe: `createDatasetService({ datasetPath: this repo, providerId: 'filesystem' })`
+ `getMerged*Rules` + `createFilesystemIntelligenceProvider`.

`GET /dataset/status` equivalent output:

| Category | Status | Count | This repo's tree |
|---|---|---|---|
| vulnIntel | AVAILABLE | **100** | 100 files (⚠ canonical counting = 84 items / 78 ids, see D7) |
| sastPacks | AVAILABLE | **950** | 950 ✅ |
| secretsPacks | AVAILABLE | **97** | 97 ✅ |
| dastPacks | AVAILABLE | **263** | 263 ✅ |
| remediation | AVAILABLE | **1310** | 1310 ✅ |
| cwe | AVAILABLE | **68** | 68 ✅ |
| lessons | AVAILABLE | **6** (DEVELOPER 2 / STUDENT 6) | 6 (2 `lsn_dev_*`) ✅ |
| assessmentTemplates | AVAILABLE | **3** | 3 ✅ |
| engagementTemplates | AVAILABLE | **2** | 2 ✅ |

Merged rule counts: SAST 950, Secrets 97, DAST 263 (no `DG-*` base — see D1).

SCA matching (`assess`), real results:

| Coordinate | Result | Advisories |
|---|---|---|
| `fast-jwt@6.2.4` (npm) | DATASET_AVAILABLE | **6**, unique |
| `msgpack5@6.0.0` (npm) | DATASET_AVAILABLE | **7**, unique |
| `mariadb@2.0.0` (13-file shard package) | DATASET_AVAILABLE | 2, **unique ids** (shard dedup works) |
| `@adonisjs/http-server@5.0.0` (split shard) | DATASET_AVAILABLE | 1 (one id, not two) |
| `django@3.0.0` (pypi) | DATASET_AVAILABLE | 1 |
| `lodash@4.17.21` | DATASET_AVAILABLE | 0 |

Pack-rule conversion parity — every declared test in this repository executed
through the App's converters:

| Family | Declared tests | Mismatches | Verdict |
|---|---|---|---|
| SAST | 3,843 | **0** | converter is faithful |
| Secrets | 441 | **0** | converter is faithful (denylist veto preserved) |
| DAST | 1,292 | **15** (9 rules) | see D3 |

`node scripts/check-boundaries.mjs` → PASS (no dataset files committed in the App).

## 3. Defects found

### D1 — The App now ships *zero* built-in detection (regression + stale docs)

`apps/api/src/scans/sast/rules.ts:48` → `SAST_RULES = []`;
`secrets/rules.ts:97` → `SECRETS_RULES = []`;
`dast/rules.ts` → `evaluateDastObservation()` returns `[]`;
`student/lessons.ts:34` → `const LESSONS = []`;
`remediationGuidance.ts` → `remediationGuidanceForFinding()` always returns
`status: 'UNAVAILABLE'`.

Consequences:

- `.env.example` ships `VULN_INTEL_PROVIDER=none` + empty `DATASET_PATH`. With
  that default the product detects **nothing** (previously 51 SAST + 7 Secrets +
  8 DAST + 4 lessons). The App is now hard-dependent on an external path at first run.
- `docs/DATASET_CONNECTION.md` still claims “`DG-SAST-*` (50 built-in) + `DPK-SAST-*`”,
  “8 built-in `DG-DAST-*`”, “4 embedded + 6 dataset = 10 lessons”, and
  “Without dataset: … embedded-only findings (4 lessons, 50 SAST rules)”. All four
  statements are false at `9360dd1`.

### D2 — App test suites do not pass at `9360dd1` (documented as green)

| Workspace | Documented | Actual (this sandbox, `npm ci` + shared build) |
|---|---|---|
| `@drobon/api` | 812/812 | **785 passed / 801, 16 failed, 6 files** |
| `@drobon/shared` | 183/183 | **182 / 183, 1 failed** |

Failing API files: `sastSemantic.test.ts` (10 — flow rules live in the deleted
embedded set), `secretsEngine.test.ts` (2), `secretsRules.test.ts` (1),
`assistantApi.test.ts` (1), `findingWorkflow.test.ts` (1), `reportsApi.test.ts` (1).
Shared failure: `SCAN_FAILURE_CODES` closed-vocabulary test — the constant gained
`DAST_ACTIVE_CONSENT_REQUIRED` and `DAST_ACTIVE_NOT_ALLOWED` (active-DAST commit)
but `packages/shared/test/scans.test.ts` was not updated.

### D3 — App DAST evaluator diverges from this repository's DAST semantics

Measured with Node-realistic observations (header keys lowercased, arrays
preserved): **15 of 1,292 declared tests disagree**, on 9 rules:

| Rule | Check type | Mismatches / tests | Cause |
|---|---|---|---|
| DPK-DAST-004 | cookie-missing-flag | 3 / 12 | `Secure=0` (flag on), `no-equals-sign` (header discarded), `SameSite=None` without `Secure` (cookie refused) |
| DPK-DAST-006 | cookie-missing-flag | 4 / 12 | `HttpOnly=1`, `=orphan-name`, `SameSite=None` |
| DPK-DAST-008 | cookie-missing-flag | 1 | `SameSite = Strict` (whitespace around `=`) |
| DPK-DAST-002 | missing-response-header | 1 / 6 | header present but **every value blank** must count as missing |
| others (5 rules) | response-header-matches | 5 / 735 | array values joined with `", "` create cross-value matches |

The App's `external/evaluator.ts` is a simplified re-implementation; this
repository's `scripts/lib/set-cookie.mjs` model (browser-accurate discard rules)
was not carried over. Because the App never executes pack-declared tests at load
(D5), these divergences stay invisible in the App's own suite.

### D4 — 160 of 950 SAST rules can never fire (66 pack ids have no App family)

The App gates every rule by `rule.languages.includes(file.family)`
(`sast/engine.ts:324`). Measured against the App's 53-id catalog:

| Bucket | Rules |
|---|---|
| universal (no `languages`) — always run | 11 |
| every declared language id exists in the App catalog | 743 |
| partially unknown ids (run only on the known ones) | 29 |
| **no known id at all — never run** | **160** |

Counting note: the first measurement said 167 because it compared ids literally.
Two of the 68 unknown ids map onto existing App families (`shell` → `shell-posix`,
`gha` → `github-actions`), which resolves the 7 `gha`-only rules; the 29 `shell`
rules were already reachable because each also declares `bash`. The authoritative,
machine-checked numbers are in `docs/APP_LANGUAGE_ID_MAPPING.md` (gate:
`scripts/validate-app-language-ids.mjs`): 115 ids used, 47 direct, 2 aliased,
66 needing a new App family, 160 rules unreachable.

Unknown ids used by this repository’s packs (top): `shell` (29 rules), `sshd`
(14), `k8s` (13), `nginx` (10), `tcl` (9), `vba` (7), `gha` (7), `properties`
(6), `apache`/`basic`/`pascal`/`compose` (5 each), `ini`/`postgres` (4 each) …
68 distinct ids in total. Note the near-miss classes: this repo says `shell`,
the App says `shell-posix`/`bash`; this repo says `gha`, the App says
`github-actions`. Two mappings alone would restore 36 rules.

### D5 — Loader checklist: 2 of 6 steps implemented

`docs/PACKS.md` §“Loader checklist” requires six behaviours. Status at `9360dd1`:

| # | Requirement | Status |
|---|---|---|
| 1 | Validate packs with this repo’s validator semantics; fail closed on unknown schema/field/check type | **partial** — `external/service.ts` accepts any file with a string `schemaVersion` + string `id`; unknown fields/fields types unchecked; unknown DAST check type silently returns `false` |
| 2 | Gate SAST rules by the App language catalog | ✅ implemented (but see D4) |
| 3 | Re-run bounded-time ReDoS regression over all pack patterns | ❌ missing |
| 4 | Execute every rule’s declared examples at load; refuse failing packs | ❌ missing (D3 is the direct consequence) |
| 5 | Redact Secrets evidence per `redact` / `matchOnlyEvidence` | ✅ implemented (positional redaction, fail-closed) |
| 6 | Surface pack id + version in scan metadata | ❌ missing — `pack.json` is never read; findings carry no dataset version |

### D6 — 1,310 remediation entries are loaded but never surfaced (dead path)

`external/knowledge.ts` (`getRemediationMap`, `getCweMap`) has **no consumer**
anywhere in `apps/`. `remediationGuidanceForFinding()` returns `UNAVAILABLE`
unconditionally, and it is the only function used by
`assistant/service.ts:248` and `routes/reports.ts:207`. So with the dataset
loaded, every finding still shows “Load the dataset for full guidance”.

### D7 — Counting mismatch on the status surface

`vulnIntel.count = 100` (files). This repository’s machine-enforced counting
policy says those 100 files are **84 identity items / 78 advisory ids** (9
multi-file shards). A status endpoint that reports 100 will disagree with every
dataset document and with any customer-facing count.

### D8 — Zero-match SCA policy differs between the two codebases

| Codebase | Zero matches with data loaded |
|---|---|
| This repo (`scripts/sca-engine.mjs:178`) | `ASSESSED` (checked against loaded data) |
| App (`scans/sca/engine.ts:369–375`) | `NOT_ASSESSED` (only matches count as assessed) |

The App’s choice is the more conservative one and is defensible given 84 items of
coverage, but the two must be reconciled in `docs/PROVIDER_MAPPING.md` +
`docs/DATASET_APP_CONTRACT.md`, otherwise an integration test written against one
contract fails against the other.

### D9 — Active DAST conflicts with both repositories’ written boundaries

`dast/activeEngine.ts` (352 lines) + `crawler.ts` + `payloads.ts` (an XSS/SQLi/
redirect/traversal/CRLF payload catalog) send requests beyond the 3-request
passive budget and inject payloads into query parameters. A consent gate exists
(`dastActiveConsent === true`, `dastMode` on the record) — good — but:

- This repo (`docs/SCOPE.md`, `docs/PACKS.md`, `CORPUS_TARGETS.json`
  `dcc-exploit-reserved`) states active DAST / crawling / payload libraries are
  **never** in scope. The App’s own earlier documentation said the same.
- `docs/CAPABILITY_COVERAGE_MATRIX.json` currently marks `DCC-EXPLOIT-RESERVED`
  and active DAST `NOT_APPLICABLE`/“absent by design”. Those rows are now stale
  or the feature must be reverted — either way the write-up must change,
  together with an authorization/consent record and rate-limit evidence.

## 4. This repository’s stale statements (must be corrected)

| Artefact | Says | Reality at `9360dd1` |
|---|---|---|
| `docs/CAPABILITY_COVERAGE_MATRIX.json` (7 rows) | `APP_INTEGRATION_BLOCKED`, “no App loader exists” | loaders exist and run |
| same, `DCC-SAST/DCC-SECRETS/DCC-DAST` `appIntegration` | `CONTRACT_READY_NOT_INTEGRATED` | integrated (with D4/D5 caveats) |
| `docs/DATASET_APP_CONTRACT.md` §5.3 | “Not verifiable (no App loader / no integration test exists)” | verifiable and verified — see §2 |
| `DROBON_REMAINING_WORK.csv` GAP-005…GAP-009 | “dataset rules unreachable at runtime” | reachable; residual work = D4/D5/D6 |
| `docs/CAPABILITY_COVERAGE_MATRIX.json` `app` pinned revision | `c32c797` (2026-10-14) | `9360dd1` (2026-10-20) |
| `docs/FINAL_DATASET_AUDIT_*`/`RELEASE_READINESS_MATRIX.json` | “Main App integration: NOT VERIFIED” | verified in this document |

These were **not** rewritten here: the change requires a new seam inventory at
`9360dd1` (the method in `docs/SCOPE.md`) and a decision about D9 first.

## 5. Revised completion picture

| Dimension | Before (2026-10-20 report) | Now |
|---|---|---|
| Dataset → App integration | **0 %** (no loader) | **~65 %** — all nine categories load, SCA matches verified; missing D3/D4/D5/D6 |
| App detection breadth with dataset mounted | n/a | 950 SAST (783 reachable today) + 97 Secrets + 263 DAST |
| App detection breadth with dataset absent | 51 + 7 + 8 | **0 + 0 + 0** |
| App test health | documented 812/812 | **801 tests, 16 failing** |
| SCA real intelligence | 0 % of 100k | unchanged (84 items, `LICENSE` still absent) |
| Release readiness | NO-GO | still NO-GO; the App now *depends* on an unlicensed corpus at runtime, which makes G6 (licence) blocking for **any** deployment, not only for redistribution |

## 6. Recommended order of work

1. **App (P0):** update `packages/shared/test/scans.test.ts` for the two new
   failure codes; restore the deleted flow-rule coverage or delete the tests that
   assert it; make `npm test` green at the App root again. Do not ship a release
   that documents 812/812 while 16 tests fail.
2. **App (P0):** implement checklist steps 1, 3, 4, 6 (validate with this repo’s
   validator semantics, ReDoS regression, execute declared tests at load, surface
   `pack.json` id+version on findings). Step 4 alone would have caught D3.
3. **App (P1):** port `scripts/lib/set-cookie.mjs` semantics into
   `external/evaluator.ts` (or import equivalent logic) and fix the blank-value
   header rule → clears all 15 DAST mismatches.
4. **Both (P1):** map the 68 missing language ids (start with `shell`→`shell-posix`,
   `gha`→`github-actions`, `k8s`/`dockerfile`/`nginx`/`ini`/`properties`) →
   restores 160 SAST rules.
5. **App (P1):** wire `getRemediationMap`/`getCweMap` into
   `remediationGuidanceForFinding` (and reports/assistant) so 1,310 entries and 68
   CWE references actually reach users.
6. **App (P1):** decide the default. Shipping `VULN_INTEL_PROVIDER=none` with zero
   embedded rules means a silent “no findings” product; either bundle a minimal
   built-in floor again, or fail loudly at startup when no dataset is configured.
7. **Both (P0, legal):** `LICENSE` + attribution. The App now reads this corpus at
   runtime, so the licence question moved from “distribution” to “any deployment”.
8. **Both (P1):** reconcile D8 (zero-match policy) in the two contracts.
9. **Both (P0, policy):** decide D9 — revert active DAST, or write the
   authorization model, amend both repositories’ boundary documents, and record
   consent/rate-limit evidence.

## 7. Reproduce

```bash
# Main App (read-only clone)
git clone --depth 1 https://github.com/mdraselislam0101-design/Drobon.git /tmp/app
cd /tmp/app && npm ci && npm run build --workspace @drobon/shared
npm run test --workspace @drobon/api       # 785 passed / 801 (16 failed)
npm run test --workspace @drobon/shared    # 182 / 183 (1 failed)
node scripts/check-boundaries.mjs          # PASS

# this repository
npm test                                   # 695 passed, 0 failed
node scripts/validate-packs.mjs packs
node scripts/eval-coverage-report.mjs      # 1310/1310 rules
```

Probe scripts used for §2/§3 are reproducible from the App source:
`createDatasetService` + `getMerged*Rules` + `createFilesystemIntelligenceProvider`
+ `convertSastPackToRule`/`convertSecretsPackToRule`/`convertDastPackToRule` +
`evaluatePackDastCheck`, driven over `packs/*/v1/rules/*.json` `tests` arrays.

---

## 8. What this audit changed in this repository (2026-10-21, same day)

The audit's findings were turned into dataset-side corrections and machine gates in
the same working session. Nothing was rewritten to look better; where the fact was
only observable in the App, the row now says so and points at the App ticket.

| Artefact | Change |
|---|---|
| `docs/CAPABILITY_COVERAGE_MATRIX.json` + `.md` (generated) | App pin `c32c797` → **`9360dd1`**; 7 rows moved off `APP_INTEGRATION_BLOCKED`; SAST/Secrets/DAST/Lessons/Templates/Engagements/Interop are now `PARTIAL` with `APP_CONSUMER_VERIFIED_WITH_GAPS`, SCA is `RIGHTS_BLOCKED` + **`INTEGRATED`**, remediation/CWE stay `COVERED_VERIFIED` with the unused-loader gap recorded, and `DCC-EXPLOIT-RESERVED` moved from `NOT_APPLICABLE` to **`OWNER_DECISION_BLOCKED`** because the App now ships active DAST |
| `scripts/validate-capability-coverage.mjs` | partition now sums all eight statuses; new basis `APP_CONSUMER_VERIFIED_WITH_GAPS`; `INTEGRATED` rows must carry App-side executed evidence; the gaps basis may only appear on `PARTIAL` rows (710 assertions) |
| `docs/SCOPE.md` | re-inventory section at `9360dd1`; rows 3–7 and 12–19 re-classified; the new active-DAST seam recorded |
| `docs/DATASET_APP_CONTRACT.md` | §5 re-verified at `9360dd1`, §7 minimum contract updated, **new §9** mapping table (`datasetStatus` vs scan state) + the 100-vs-84 counting note |
| `docs/PACKS.md` | loader conformance status: 2 of 6 checklist steps done, 4 open (with the consequence of each) |
| `README.md` | sibling table no longer says "future consumer"; connection status + defect summary added |
| `docs/RELEASE_READINESS_MATRIX.json` | G6 evidence widened (the missing grant now blocks **any** deployment, since the App reads the corpus at runtime); G3 notes the App-side conformance gap. Statuses unchanged |
| `DROBON_REMAINING_WORK.csv` | GAP-005/006/007 closed (`RESOLVED`) with the verification evidence; GAP-008/009 rescoped; **7 new rows** GAP-040…GAP-047 for language reachability, DAST parity, loader conformance, counting/zero-match, duplicated range semantics, the active-DAST boundary decision, App doc drift and the failing App suites |
| **new gate** `scripts/validate-app-language-ids.mjs` + `data/app-language-catalog.json` + generated `docs/APP_LANGUAGE_ID_MAPPING.md` | 147 assertions: every pack language id must resolve to the App catalog, a declared alias, or an explicit "needs a new App family" entry; stale entries fail; wired into `npm test` |
| `docs/CURRENT_INVENTORY.json` | regenerated (remaining-work register is now 43 rows) |

Deliberately **not** changed: any rule, pattern, record, remediation entry, eval case,
advisory record, owner decision, licence status or release gate status. The dataset
suite stays green.

---

## Limits of this verification

- The App was cloned and tested here, but **no browser/E2E run** and no live
  scan against a real project snapshot was performed; engine behaviour is
  inferred from source + unit-level probes.
- Worker and Web test suites were not run (only `@drobon/api` and `@drobon/shared`).
- The dataset was mounted read-only; nothing in the App repository was modified.
- No claim is made here about real-world detection quality; every number above is
  a count derived from files or from executing declared tests.
