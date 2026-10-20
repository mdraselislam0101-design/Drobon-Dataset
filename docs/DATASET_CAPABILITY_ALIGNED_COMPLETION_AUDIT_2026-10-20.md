# Dataset-only master completion & capability-aligned audit — 2026-10-20

**Scope:** `mdraselislam0101-design/Drobon-Dataset` only. The Main App
(`mdraselislam0101-design/Drobon`) is treated as read-only evidence; no App file,
test, configuration, dependency, database, migration or deployment was touched.
No git write of any kind was performed (no commit, push, branch, tag, PR, merge,
reset or clean).

**Verdict: PARTIAL.** The Dataset-side defects found in this audit are fixed,
regression-gated and verified by a full `npm test` run (exit 0). Dataset
publication stays **NO-GO** (no license), App integration stays **NOT VERIFIED**
(no loader exists in the pinned App revision), and SCA production intelligence
stays **RIGHTS_BLOCKED**. Nothing in this report claims 100 % completion, parity
with commercial tools, or real-world exploitability.

---

## 1. Repository, branch, HEAD and worktree (before → after)

| Item | Before this pump | After this pump |
|---|---|---|
| Repository | `mdraselislam0101-design/Drobon-Dataset` | unchanged |
| Branch | `arena/a4caaeb8-drobon-dataset` | unchanged |
| HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` | unchanged (no commit) |
| Worktree entries (`git status --porcelain`) | 4,620 | 4,639 (2,461 modified, 2,178 untracked) |
| `LICENSE` | absent | absent (invariant kept) |
| `docs/OWNER_DECISIONS.json` | untouched | untouched — `git status` reports no change |
| `docs/BLOCKER_REGISTER.json` open blockers | 4 | 4 (BLK-001…004) |

The worktree was already dirty at pump start (uncommitted output of the earlier
DAST pumps). Because of that, a per-file diff against HEAD cannot isolate this
pump; the authoritative change list is §6, which enumerates every path this
pump wrote.

`git status` counts are file entries, not semantic changes: the generator writes
the whole rule/pattern/record/remediation tree deterministically, so a cell-level
edit shows up as a pack file, a pattern, a record and a remediation file.

## 2. Capability evidence — what the App actually implements, and the limits

Evidence base (all in-repo; nothing inferred from aspirations or vendor
marketing):

- `docs/CAPABILITY_COVERAGE_MATRIX.json` — 33 capability rows; the App revision
  is pinned at `c32c797a549453802bd6d82c5673d2a1728457a3` (2026-10-14). 10 rows
  are Dataset-relevant, 23 are `NOT_APPLICABLE`.
- `docs/DATASET_APP_CONTRACT.md` (now v1.2) — schemas, field guarantees,
  language-tag limitation, GATE-4 (SCA provider design) state.
- `docs/MAIN_APP_DATASET_COVERAGE_2026-10-18.md`, `DROBON_MASTER_COVERAGE_AUDIT.md`,
  `docs/BLOCKER_REGISTER.json`, `DROBON_REMAINING_WORK.csv` — the audit trail that
  recorded the App's engine facts.

App capability as verified in those documents: SAST / Secrets / DAST engines
ship **50 / 6 / 8 hard-coded `DG-*` rules** (code, not data), SCA runs with
`VULN_INTEL_PROVIDER=none` and a Null provider that reports `NO_DATA_LOADED` /
`NOT_ASSESSED`, and **no pack loader exists** (GAP-005 SAST, GAP-006 secrets,
GAP-007 DAST). UserType is presentation only; FREE/PRO is entitlement, so one
shared intelligence core serves every profile.

**Verification limits (stated, not hidden):**

1. No Main App checkout exists in this sandbox during this pump. App facts are
   taken from the pinned in-repo matrix and audit documents, not re-read from App
   source today.
2. App test suites were **NOT_RUN**; nothing here asserts App behaviour.
3. "The App does not consume the Dataset" is an *absence* claim derived from the
   pinned revision plus the blocker register, not a runtime observation.
4. The Dataset-side schemas are validated, but schema-valid is not integrated.

## 3. Current vs final counts, and the method that produced them

Method: `scripts/inventory.mjs` (`computeInventory()`, the same function the
gates call) plus direct file counts; evaluation numbers come from
`scripts/run-eval.mjs` and from a recount over `data/eval-cases` that is now
machine-checked (§5.6).

| Category | Before | After | Note |
|---|---|---|---|
| Pack rules | 1,163 | **1,163** | 950 SAST + 97 secrets + 116 DAST; no rule added or removed |
| Patterns | 1,163 | **1,163** | 1:1 with rules |
| Records | 1,163 | **1,163** | 1:1 with patterns; 0 patterns without a record |
| Remediation | 1,163 | **1,163** | keyed by `ruleId`, 0 orphaned |
| CWE entries | 63 | **63** | rule→CWE mapping corrected for 15 rules (§5.1) |
| DAST check types | 7 | **7** | closed vocabulary unchanged |
| Evaluation cases | 1,316 | **1,316** | 1,305 assessed / 11 UNASSESSED |
| TP / FP / FN | 1,189 / 1 / 0 | **1,189 / 1 / 0** | recall 1.0000, precision 0.9992 |
| Lessons / templates / engagements / vectors | 6 / 3 / 2 / 16 | **6 / 3 / 2 / 16** | unchanged |
| Advisory fixtures (synthetic) | 3 files | **3 files** | production advisory records: 0 |

No count was changed to make a gate green: this pump changed *content quality*
(text, weakness mapping, documentation truth), not corpus size.

## 4. Coverage by capability (the 10 Dataset-relevant rows)

| Capability row | Status in matrix | What this audit did |
|---|---|---|
| `DCC-SAST` | SUPPLEMENTAL + `APP_INTEGRATION_BLOCKED` | Corrected 15 wrong CWE mappings, replaced 15 hedged descriptions and 15 vacuous risk lines; evaluation evidence recounted and now machine-checked. Integration stays blocked (GAP-005). |
| `DCC-SECRETS` | SUPPLEMENTAL + blocked | No content change. Verified fixture hygiene (15 credential-shaped fixtures, all placeholder-constructed, no live-credential shape). Integration blocked (GAP-006). |
| `DCC-DAST` | SUPPLEMENTAL + blocked | Quality-first repair: 14 boilerplate remediations, 13 generic risk texts, 4 overlap limitations, 2 more risk/description repairs, overlap gate wired into `npm test`. Integration blocked (GAP-007). |
| `DCC-REMEDIATION` | REQUIRED + `COVERED_VERIFIED` | Every regenerated entry re-validated; 1,163/1,163 keyed by `ruleId`. |
| `DCC-CWE` | REQUIRED + `COVERED_VERIFIED` | 15 rule→CWE corrections, all targets already resolve in `knowledge/cwe`; gate rejects an unresolvable per-sink CWE before any file is written. |
| `DCC-SCA-VULN` | REQUIRED + `RIGHTS_BLOCKED` | Untouched by design: no lawful advisory source, no production pack, synthetic fixtures stay separated and uncounted. |
| `DCC-LESSONS`, `DCC-ASSESSMENT-TEMPLATES`, `DCC-ENGAGEMENTS`, `DCC-INTEROP` | SUPPLEMENTAL + blocked | Inspected, no defect in scope of this pump; unchanged. |

## 5. Per-category findings and changes

### 5.1 SAST — wrong weakness mapping and degenerate record text (fixed)

**Finding A (high impact):** all 15 `csharp-flag` rules carried `CWE-95`
("Eval Injection") because the class-level CWE was inherited by every sink, even
though the class mixes request validation, certificate validation, SQL building,
deserialisation, cleartext transport, hardcoded keys and debug output. A finding
from `ServerCertificateValidationCallback => true` was therefore filed as code
injection.

Fix: per-sink weakness override, fail-closed against `knowledge/cwe`:

| Rule | Construct | Was | Now |
|---|---|---|---|
| DPK-SAST-486 | `[AllowHtml]` | CWE-95 | CWE-79 |
| DPK-SAST-487 | cert-validation callback → `true` | CWE-95 | CWE-295 |
| DPK-SAST-488 | `customErrors mode="Off"` | CWE-95 | CWE-209 |
| DPK-SAST-489 | `compilation debug="true"` | CWE-95 | CWE-489 |
| DPK-SAST-490 | `EnableSsl = false` (SMTP) | CWE-95 | CWE-319 |
| DPK-SAST-491 | `new SqlCommand("…" + q)` | CWE-95 | CWE-89 |
| DPK-SAST-492 | `new SqlCommand($"…{q}")` | CWE-95 | CWE-89 |
| DPK-SAST-493 | `trace enabled="true"` | CWE-95 | CWE-532 |
| DPK-SAST-494 | `TypeNameHandling.All` | CWE-95 | CWE-502 |
| DPK-SAST-495 | `[ValidateInput(false)]` | CWE-95 | CWE-79 |
| DPK-SAST-496 | `DownloadString("http://…")` | CWE-95 | CWE-319 |
| DPK-SAST-497 | `EnableScript = true` (XSLT) | CWE-95 | CWE-94 |
| DPK-SAST-738 | `decryptionKey="…"` | CWE-95 | CWE-798 |
| DPK-SAST-739 | `validationKey="…"` | CWE-95 | CWE-798 |
| DPK-SAST-740 | `ValidateRequest="false"` | CWE-95 | CWE-79 |

**Finding B (quality):** 35 records carried the vacuous line
`Varies by control; <SEVERITY> severity.` — the same 35 also reused templates
that hedged unrelated mechanisms ("relaxes a security control such as
polymorphic binding, certificate validation or output encoding") or deferred the
judgement ("for {x}, {y} relaxes a hardening control"). A reader learned nothing
about which control the rule reports.

Fix: a documented, fail-closed `sinkOverrides` mechanism (`docs/ASSET_METHODOLOGY.md`
§1.1) plus hand-authored text for every affected cell — 33 SAST cells
(11 `sys-services`, 15 `csharp-flag`, 5 `django-secure`, 2 `rails-secure`) and 2
DAST cells. Result: 1,163/1,163 record descriptions unique, **0** vacuous risk
lines, **0** hedged descriptions. `scripts/test-assets.mjs` now fails if either
pattern returns.

**Not changed (reported, not silently "fixed"):** all 15 `csharp-flag` rules are
`HIGH`. Re-rating them (debug output, `customErrors`, trace are arguably MEDIUM)
is a severity-calibration decision with UI/UX and reporting consequences, so it
is left visible as a decision item (§13) rather than changed inside a completion
pump.

### 5.2 DAST — quality before quantity

- 10 missing-header rules (012, 013, 014, 016, 017, 039, 041, 042, 043, 044) had
  boilerplate remediation ("Emit X on every response. Confirm at the edge and the
  origin.") and a generic "rescan observes the header" verification. Each now
  states the real browser behaviour, a real fix and a real verification step
  (COEP is opt-in isolation; COOP `same-origin` / `same-origin-allow-popups` and
  the OAuth-popup test; CORP `same-origin` on authenticated responses; HSTS after
  TLS on every subdomain; Permissions-Policy empty allowlists; DNS-prefetch `off`;
  NEL needs a Report-To collector; Origin-Agent-Cluster `?1`; Report-To HTTPS
  group; X-Permitted-Cross-Domain-Policies `none` plus removing `crossdomain.xml`).
- 4 weak-value rules (022, 023, 024, 025) shared one template ("A weak value
  grants partial protection at best"). Each now explains its own trap: CSP
  `default-src` wildcard, HSTS preload prerequisites, the unquoted ≥31536000
  requirement (a quoted value is discarded by strict parsers), and the fact that
  `X-Frame-Options: ALLOW-FROM` is ignored by every current browser.
- 13 records got severity rationale instead of "Varies by control"; 016
  (HSTS max-age) and 022 (CSP `default-src` wildcard) were raised to MEDIUM with
  written reasons.
- `DPK-DAST-022`'s title now matches what it matches; the old open item in
  `docs/PACKS.md` ("titled 'wildcard source' but matches only `default-src *`")
  is closed with 8 probes through `evalDastCheck` — 3 positive (`default-src *`,
  `default-src https://*`, `default-src 'self' *`) and 5 negative (`default-src 'self'`,
  `script-src *`, `default-src *.example.com`, `default-src https://cdn.example.com`,
  `img-src *; default-src 'self'`).
- Final shape: 116 rules, 12 categories, 7 check types, 47 distinct headers,
  15 CWEs, severity MEDIUM 62 / LOW 54, 622 executable observation tests
  (262 positive / 360 negative), 0 quarantined.

### 5.3 Shared / reporting / SBOM / audience surfaces

- The capability matrix's evaluation evidence contradicted the tree
  ("1,231 cases", "90/90 DAST", "130 DAST cases"). It now states the measured
  numbers and carries a machine-checked `evaluationCoverage` block per engine.
- Audience/reporting surfaces were pinned to stale counts
  (`remediation 1142`, `954 files`, `65 DAST rules`, `1119 remediation entries`
  in the traceability and remaining-work registers). Fixed.
- Nothing was added to the SBOM, reporting, lesson or engagement surfaces; no
  capability was invented to justify an existing record.

### 5.4 Documentation truth (the "green but stale" defect)

Several current-state documents and, more importantly, **the gates that pin
them** still asserted 2026-10-18 numbers (`954 / 914 / 1119 / 1142 / 1103`).
Because the gate compared a literal against a literal, both drifted together and
stayed green — the worst possible failure mode for a drift gate.

Fixed by deriving every inventory pin from `computeInventory()`:

| File | Change |
|---|---|
| `scripts/test-current-state.mjs` | every inventory literal pin replaced by a computed one (rules, patterns, records, remediation, CWE, secrets); added a DAST-unreachable pin that did not exist |
| `docs/ASSET_METHODOLOGY.md` | title 954/954/914 → 1,163/1,163/1,163; date line states what changed |
| `docs/COVERAGE_MAP.json` | BE-3 moved from `blockedExpansions` to `resolvedExpansions` (condition gone; D-13 still inactive); `test-doc-drift` now requires blocked+resolved ≥ 5 so a resolution cannot become a deletion |
| `docs/CAPABILITY_GAP_MATRIX.md` | 1,119→1,163 rules, linkage 1,142→1,163, remediation 1,142→1,163, `test-eval` 41→43, audiences 1,114→1,174 files |
| `docs/DATASET_APP_CONTRACT.md` | inventory rows 954/914→1,163; contract bumped to **1.2** with a changelog entry (no schema or field guarantee changed) |
| `docs/AUDIENCES.md` | shared-base counts and the resolved 40-pattern gap bullet |
| `DROBON_REMAINING_WORK.csv` | GAP-007 DAST 72→116, GAP-008 remediation 1,119→1,163 |
| `DROBON_REQUIREMENT_TRACEABILITY.csv` | R-SAST-P-06/P-07 (954→1,163), R-DAST-P-01/P-03 (65→116) |
| `docs/SOURCE_RELEASE_GATE.md`, `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md` | current rule/test counts |
| `docs/BLOCKER_REGISTER.json` | BLK-R13 resolution gets a dated SUPERSEDED note (schema and counts untouched) |
| `docs/PACKS.md` | one appended, dated superseding bullet; the 2026-10-16 Pump-5 bullets stay as history |

Frozen and dated documents were deliberately **not** rewritten:
`docs/COMPLETION_MATRIX.json` (`frozenAt: 2026-10-18`),
`DROBON_MASTER_COVERAGE_AUDIT.md` (audit date 2026-10-16),
`docs/MAIN_APP_DATASET_COVERAGE_2026-10-18.md`,
`docs/OWNER_DECISION_PACKET.md`, `docs/ORIGINALITY_REPORT_2026-10-19.md`,
`docs/DATASET_COMPLETION_AUDIT_2026-10-18.md` and the DAST pump reports. Their
numbers are superseded and are listed in §12 so a reader is not misled.

### 5.5 Deduplication and overlap

- Recomputing the same-header relation through the real evaluator
  (`evalDastCheck`) yields **77 subset pairs** in the 116-rule pack: 72
  `ABSENCE_COVERAGE` (an absence rule necessarily fires when a value rule fires),
  5 `EVIDENCE_SUBSET`.
- The 5 are recorded in `docs/DAST_OVERLAP_LEDGER.json` and each widening rule's
  `limitation` names its partner: `050 ⊂ 056` (owner-blocked, OD-1),
  `076 ⊂ 047`, `085 ⊂ 056`, `110 ⊂ 094`, `118 ⊂ 094` (reviewed, retained).
- `scripts/validate-dast-overlaps.mjs` runs in `npm test`: it recomputes the
  relation (185 checks), fails on any unreviewed `EVIDENCE_SUBSET`, fails if a
  ledger entry's limitation text no longer mentions the partner, and rejects two
  rules with identical check JSON. Verified by deleting the `076 ⊂ 047` entry and
  observing `FAIL (1)` → restore → `PASS`.
- No rule was deleted, renamed or repurposed: IDs are permanent. The 15 `.NET`
  rules keep their IDs while their weakness mapping is corrected.
- **26 numeric id divergences** exist between the pattern sequence and the record
  sequence (`DPK-PAT-0005` pairs with `DPK-REC-1126`, etc.). Cell-level identity
  is exact (1,163 distinct cells, 0 cells lacking a record, every record
  referencing exactly one pattern), so this is a cosmetic numbering artefact of
  the legacy allocations, reported rather than renumbered (renumbering would
  rewrite stable IDs).

### 5.6 Evaluation coverage (measured, not asserted)

| Engine | Rules | Rules with a positive case | Rules with a negative case | Cases | Assessed | UNASSESSED |
|---|---|---|---|---|---|---|
| SAST | 950 | **890** | 204 | 797 | 792 | 5 |
| Secrets | 97 | 97 | 97 | 203 | 202 | 1 |
| DAST | 116 | 116 | 116 | 215 | 215 | 0 |

Dataset-wide: 1,316 cases naming all 1,163 rules; 1,103 rules appear in a positive
detection. **60 SAST rules have no positive evaluation case** and 746 have no
negative one — pack-level tests are not a substitute for an independent case, and
that gap is now written into the matrix instead of being hidden behind a corpus
total (`DCC-SAST.remainingWork`).

## 6. Assets added, modified, blocked, excluded

**Added (2):**

- `docs/DAST_OVERLAP_LEDGER.json` — schema `drobon.dast.overlap-ledger/v1`, 5
  reviewed pairs with rationale and action.
- `scripts/validate-dast-overlaps.mjs` — the fail-closed overlap gate.

**Modified (this pump, exhaustive path list):**

- Cell data: `data/asset-cells/dast.json`, `dast-2.json`, `dast-5.json`,
  `dast-10.json`, `dast-11.json` (DAST text/severity/limitation overrides),
  `sast-calls-3.json`, `sast-config-3.json`, `sast-config-4.json` (per-sink text and
  CWE overrides).
- Generated outputs (via `scripts/generate-assets.mjs`, 4,607 files written, 0
  removed, 0 quarantined): 35 records, 15 rule files (CWE), 15 remediation files
  (`standardId`), plus the regenerated determinism set. 1,123 cell rules + 40
  legacy rules = 1,163.
- Generator/tests: `scripts/generate-assets.mjs` (per-sink overrides),
  `scripts/test-assets.mjs` (3 new guards), `scripts/test-current-state.mjs`
  (computed pins), `scripts/test-doc-drift.mjs` (blocked+resolved ledger),
  `scripts/validate-capability-coverage.mjs` (evaluation-coverage recomputation,
  695 assertions), `package.json` (overlap gate in the `test` chain and a
  `validate:dast-overlaps` script).
- Docs/registers: the 11 files listed in §5.4 plus
  `docs/CAPABILITY_COVERAGE_MATRIX.json` / `.md` and `docs/CURRENT_INVENTORY.json`
  (regenerated, not hand-edited).

**Blocked (unchanged, with reasons):** `DPK-DAST-050` (over-broad
protocol-relative pattern; retire/rewrite/keep is an owner decision),
header-list check type, multi-header correlation, request/response pairs,
cookie-prefix/domain/lifetime checks (all would require a new check type outside
the closed seven), SCA production matching data (no lawful source).

**Excluded on purpose:** any new DAST rule (quantity was not the gap), any new
SAST class, any new check type, any App-side change, any real advisory import,
any severity re-rating (§5.1), any destructive cleanup of the 26 numbering
divergences.

## 7. Provenance and originality

- Every changed sentence is DROBON's own text, written from the rule's own
  mechanism; the standards references (RFC 6265/6797/7034, CSP3, COOP/CORP specs,
  CWE definitions) informed technical correctness only — no external rule text,
  identifier scheme or remediation wording was copied.
- CWE ids are MITRE identifiers used as classification keys; the summaries in
  `knowledge/cwe/` remain the repository's own words with pinned URLs.
- No tool output, signature database or proprietary catalogue structure entered
  the tree. `scripts/originality-report.mjs --check` passed in the full run.
- The `sinkOverrides` CWE values were chosen per construct and validated against
  `knowledge/cwe`; where a construct could map to two weaknesses the narrower one
  was used (e.g. hardcoded machine keys → CWE-798 rather than CWE-320/321, which
  the repository does not carry).

## 8. Verification — exact commands, exit codes, results

Run in this order (canonical commands discovered from `package.json` and docs;
none invented):

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `node scripts/generate-assets.mjs` | 0 | 4,607 files written, 0 removed, 0 quarantined; 1,163 patterns / 1,163 records |
| 2 | `node scripts/validate-dast-overlaps.mjs` | 0 | 185 checks; 77 pairs (72 absence, 5 reviewed); PASS |
| 3 | `node scripts/validate-packs.mjs` | 0 | 1,166 files, 0 errors |
| 4 | `node scripts/test-packs.mjs` | 0 | 4,834/4,834 passed |
| 5 | `node scripts/validate-assets.mjs` | 0 | 2,326 files, 0 errors |
| 6 | `node scripts/test-assets.mjs` | 0 | 9,324/9,324 passed |
| 7 | `node scripts/test-consistency.mjs` | 0 | 222/222 passed |
| 8 | `node scripts/validate-audiences.mjs` | 0 | 1,174 files, 0 errors |
| 9 | `node scripts/test-current-state.mjs` | 0 | 155 passed, 0 failed |
| 10 | `node scripts/test-doc-drift.mjs` | 0 | 120 passed, 0 failed |
| 11 | `node scripts/validate-capability-coverage.mjs` | 0 | 695 passed, 0 failed |
| 12 | `node scripts/inventory.mjs --write` | 0 | snapshot regenerated |
| 13 | `node scripts/render-capability-coverage.mjs --write` | 0 | 33 rows |
| 14 | `node scripts/run-eval.mjs` | 0 | 1,316 cases; TP 1,189 / FP 1 / FN 0; recall 1.0, precision 0.9992 |
| 15 | `npm test` | **0** | 20,087 `ok` lines; every suite PASS; determinism 5/5 (run twice: before and after this report file existed) |
| 16 | `node scripts/test-determinism.mjs` (inside 15) | 0 | reproducible whole-tree digest; `e15070d1…` before this report existed, `e64ee187…` once it was added — the digest covers the report, so the authoritative value is what the command prints for the checked-out tree |

Full-suite breakdown: test 600/600 · pack-tests 4,834/4,834 · audience-tests
3,533/3,533 · asset-tests 9,324/9,324 · consistency 222/222 · rehearsal 78/78 ·
importers 49/49 · agent-policy 91/91 · agent-workflows 57/57 · finding-evidence
31/31 · secret-candidates 35/35 · SCA engine 38/38 · SCA fixtures 177/177 ·
eval-tests 43/43 · doc-drift 120/120 · current-state 155/155 · capability-coverage
695/695 · determinism 5/5.

## 9. Failures, false positives and unassessed cases

**Gates that failed during this pump (all fixed, none bypassed):**

1. `test-assets` failed 4 records against the 80-character description floor after
   the first rewrite (62–73 chars). The texts were lengthened; the floor was not
   lowered.
2. `test-doc-drift` rejected the new `CLOSED_CONDITION_GONE` status because
   `blockedExpansions` has a closed vocabulary. The entry was moved to
   `resolvedExpansions` (its intended home) and the gate now requires
   blocked+resolved ≥ 5 so nothing can disappear.
3. `test-current-state` failed on the `SOURCE_RELEASE_GATE` literal pin — that is
   the defect it was supposed to catch, and the pin is now computed.
4. `test-assets` failed 1 duplicate/hedge assertion before the last two DAST cells
   were given specific text.

**Preserved failure:** `EVAL-SAST-008` — the Python fixture's line-2 docstring
`cursor.execute("SELECT " + user_input)` matches `DPK-SAST-283`, while ground
truth is one issue at line 3. This is a lexical line-regex limitation, the
expectation was **not** edited, and it is the run's single false positive.

**UNASSESSED (11, excluded from scoring):** EVAL-CMD-023/024/025,
EVAL-SAST-004/007/014/015/016, EVAL-SEC-111, EVAL-SQL-027/028 — each ambiguous by
construction (commented-out code, unknown-callee data flow, truncated snippet).
They contribute no TP/FP/FN and were not converted.

**Known quality limits not fixed here:** uniform HIGH severity on the 15 `.NET`
rules; 60 SAST rules without a positive evaluation case; the 26 numeric id
divergences (§5.5); App-side behaviour unverified (§2).

## 10. Legal and owner blockers

| Blocker | State | Consequence |
|---|---|---|
| BLK-001 — no `LICENSE` file | open | Dataset publication **NO-GO**; all rights reserved by default |
| BLK-002 — per-source rights | open | no advisory text may be redistributed |
| BLK-003 — production authorization | open | no production data load |
| BLK-004 — approval/refresh cadence | open | no scheduled refresh |
| D-13 — 40 legacy record-less patterns | **inactive, not activated** | the *condition* is gone (0 patterns without a record); closing the decision is an owner act |
| OD-1 — `DPK-DAST-050` | open | rule stays as-is, documented in the overlap ledger |
| SCA production intelligence | `RIGHTS_BLOCKED` | 0 production packs; App must keep reporting `NOT_ASSESSED` |

`docs/OWNER_DECISIONS.json` was not edited; its schema and 5-key closed
vocabulary are unchanged (4 pending of 5).

## 11. Main App and git — explicit confirmations

- **Main App not modified:** no App clone exists in this sandbox and no command in
  this pump targeted the App repository. All writes are under
  `/home/user/Drobon-Dataset`.
- **No git write:** no commit, push, branch, tag, PR, merge, deploy, reset or
  clean. HEAD is still `ed599c654e972cf517331bb504d65f3e8c2dbcf1` and the branch is
  still `arena/a4caaeb8-drobon-dataset`. The changes are worktree-only, as
  requested.

## 12. Superseded documents (do not read as current)

These keep their historical numbers by design (append-only discipline):
`DROBON_MASTER_COVERAGE_AUDIT.md` (2026-10-16: 950/910, 40-pattern gap),
`docs/MAIN_APP_DATASET_COVERAGE_2026-10-18.md` (DAST 65),
`docs/COMPLETION_MATRIX.json` (frozen 2026-10-18: 954/914),
`docs/DATASET_COMPLETION_AUDIT_2026-10-18.md`,
`docs/OWNER_DECISION_PACKET.md` (§6.11, D-13),
`docs/ORIGINALITY_REPORT_2026-10-19.md`, `docs/EVAL_ID_CAPACITY_AND_FINAL_GAP_CLOSURE_2026-10-19.md`,
`docs/DAST_CHECK_TYPE_EXTENSION_PROPOSAL.md` (90 rules / 1,231 cases),
`docs/DAST_CORRELATION_EXTENSION_PROPOSAL.md`, and the five DAST pump reports.
`docs/PACKS.md` keeps every dated batch entry and now carries one 2026-10-20
superseding bullet.

## 13. Verdict and the exact decisions needed next

**PARTIAL.** Within the Dataset, the DAST category is now internally consistent
(no boilerplate, no vacuous risk text, gated overlap), the SAST weakness mapping
is factually correct for the 15 affected rules, and the current-state documents
and their gates can no longer agree on a stale number. The full suite runs green
from the real generator.

Completion is **not** claimed, because every one of these remains open:

1. **Owner — license/rights (BLK-001/D-1):** without a written grant, publication
   is NO-GO regardless of dataset quality.
2. **Owner — D-13:** record that the 40-pattern exception is closed by the
   generator fix, or keep it parked. Nothing else in the tree depends on it.
3. **Owner — OD-1 (`DPK-DAST-050`):** choose rewrite, retirement, or retention
   with the documented overlap.
4. **Owner/engineering — SCA:** a lawful advisory source is required before any
   production matching data exists; until then the honest state is
   `RIGHTS_BLOCKED` and `NOT_ASSESSED`.
5. **Engineering — App pack loader:** GAP-005/006/007; integration cannot be
   claimed from the Dataset side.
6. **Engineering — SAST evaluation breadth:** 60 rules with no positive case and
   746 with no negative one; this is the largest remaining Dataset-side quality
   gap and it is *not* a DAST-shaped problem.
7. **Engineering — severity calibration:** the 15 `.NET` rules are uniformly HIGH;
   decide per rule and update downstream reporting expectations in one pass.
8. **Engineering (cosmetic) — 26 numeric pattern/record id divergences:** leave,
   or renumber under an approved ID-migration plan. Cell-level identity is exact,
   so nothing is missing today.
