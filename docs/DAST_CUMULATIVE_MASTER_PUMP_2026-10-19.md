# DROBON AEGIS — DAST cumulative master pump (2026-10-19)

**Verdict: DAST work in this pump is VERIFIED; the Dataset as a whole remains
NO-GO.** The pump repaired ten concrete DAST detection defects in place, added
one genuinely distinct rule using the existing 7-type vocabulary, added nine
evaluation cases, and added no schema version, engine, registry or evaluator
branch. The 1,000 DAST + SCA target is **NOT MET** (90 DAST + 0 SCA). No commit,
push, tag, release, deployment, or Main App change was made.

| Field | Value |
|---|---|
| Date | 2026-10-19 |
| Repository | `mdraselislam0101-design/Drobon-Dataset` only |
| Branch | `arena/a4caaeb8-drobon-dataset` (unchanged) |
| HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged) |
| Main App | read-only contract facts only; not modified, not bundled |
| Defects repaired | 10 rule-level defects, same rule identities |
| Rules added | 1 (`DPK-DAST-095`) |
| Evaluation cases added | 9 (`EVAL-DAST-122`…`130`) |
| Final DAST count | **90** (baseline 89) |
| Overall verdict | **NO-GO** |

## 0. Required-item ledger

The brief requires 17 report items. Each is present, with an honest status
label. `UNASSESSED` is never reported as a pass.

| # | Required item | Where | Status |
|---:|---|---|---|
| 1 | Scope, authorization boundaries, preserved work | §1, §13 | VERIFIED |
| 2 | Baseline independently re-established before reliance | §2 | VERIFIED |
| 3 | Gap classification with dispositions | §3 | VERIFIED |
| 4 | Phase C real defects repaired under existing identity | §4 | VERIFIED |
| 5 | Phase D additions and semantic-dedupe rejections | §5 | VERIFIED |
| 6 | Phase E evaluator-extension gate; no silent check type | §6 | BLOCKED (owner gate) |
| 7 | Phase F per-rule positive/negative/boundary evidence | §7 | VERIFIED |
| 8 | Phase G targeted and full-suite regression | §8 | VERIFIED |
| 9 | All validators re-run | §8.1, §9 | VERIFIED |
| 10 | Coverage, inventory, manifest, provenance, originality, dedup | §10 | VERIFIED (with 1 advisory) |
| 11 | Recomputed counts with explicit method | §9 | VERIFIED |
| 12 | FP/FN/unassessed review, preserved expectations | §11 | PARTIALLY_VERIFIED |
| 13 | Dangling references and count-pin consistency | §12.2 | VERIFIED |
| 14 | No weakened assertion, no changed expected result | §12.3 | VERIFIED |
| 15 | Prohibited intelligence, LICENSE, owner-file, App invariance | §13 | VERIFIED |
| 16 | Diff review and exact git state | §14 | VERIFIED |
| 17 | Architecture limitation, 1,000 target, blockers, verdict | §15, §16 | BLOCKED / NO-GO |

## 1. Executive summary

1. **Ten detection defects were repaired in place**, without changing any rule
   id: four CSP wildcard rules that missed the bare `*` token (`DPK-DAST-022`,
   `070`, `086`, `092`), the order-dependent `SameSite=None` rule (`071`), the
   OWS-blind header matcher used by `084`, the protocol-relative userinfo miss
   in `085`, the unquoted-URL misses in `055` and `080`, and the COEP
   `credentialless` false positive in `046`. `022` also had its severity
   corrected from HIGH to MEDIUM.
2. **One genuinely distinct rule was added** — `DPK-DAST-095`, CSP
   `script-src` allowing `data:` scripts — using the existing
   `response-header-matches` check. It is not a variant of the existing
   `script-src *` rule because a scheme source and a wildcard source are
   different CSP grammar productions.
3. **Nine evaluation cases were added** (`EVAL-DAST-122`…`130`) and each was
   executed individually before the full run, with exact rule-id, outcome and
   evidence assertions. They cover the repaired behaviours and the new rule.
4. **No evaluator extension was made.** The two families that need
   multi-header correlation and request/response pairs remain
   `BLOCKED_PENDING_OWNER_DECISION`. A new, additive v1-compatible proposal
   (`docs/DAST_CORRELATION_EXTENSION_PROPOSAL.md`) records the smallest possible
   extension; the older v2 proposal is annotated as superseded, not deleted.
5. **The entire suite is green**: `npm test` exit 0 with **19,512** assertions,
   plus `validate-packs` PASS (1,140 files), `validate-assets` PASS (2,234
   files), and `coverage-report --check` PASS.
6. **The evaluation run still reports one FAIL and eleven UNASSESSED cases.**
   The FAIL is the pre-existing `EVAL-SAST-008` false positive, deliberately
   preserved; the UNASSESSED cases are preserved and explicitly excluded from
   every metric. Neither is presented as a pass.

## 2. Baseline independently re-established

Baseline was measured from the working tree at the start of this pump. No value
in this table was copied from an earlier report.

| Metric | Baseline | Final | Definition |
|---|---:|---:|---|
| DAST rules | 89 | **90** | JSON files in `packs/dast/v1/rules` |
| Pack rule files (SAST+secrets+DAST) | 1,136 | **1,137** | 950 + 97 + 90 |
| Patterns | 1,136 | **1,137** | files in `knowledge/patterns` |
| Records | 1,096 | **1,097** | files in `knowledge/records` |
| Remediation entries | 1,136 | **1,137** | files in `knowledge/remediation` |
| Evaluation cases | 1,222 | **1,231** | files in `data/eval-cases` |
| `npm test` | exit 0, 19,494 assertions | exit 0, **19,512** assertions | full chain |
| Evaluation run | TP 1,151 / FP 1 / FN 0 / 11 UNASSESSED | TP **1,157** / FP 1 / FN 0 / 11 UNASSESSED | `scripts/run-eval.mjs` |
| Tracked modifications | 2,317 `M` | 2,332 `M` | `git status --porcelain` prefix ` M` |
| Untracked files | 1,914 `??` | 1,930 `??` | prefix `??`, default (directory-collapsed) |
| Deleted files | 0 | 0 | no `D` entries |

The six-TP increase is exactly the six new positive evaluation cases
(`122`, `124`, `125`, `126`, `127`, `128`); the three new negatives contribute
no TP. The `+15 M / +16 ??` delta matches the 15 newly modified files and the
16 new files (9 eval cases, 1 asset cell, 1 rule, 1 pattern, 1 record,
1 remediation entry, 1 proposal, this report).

## 3. Gap classification

Every gap found was classified before work started. `OWNER_BLOCKED` and
`SCHEMA_BLOCKED` items were not implemented.

| Gap | Class | Disposition |
|---|---|---|
| CSP wildcard FNs (`022/070/086/092`) | FIX_EXISTING | Token-boundary patterns; 4 regression tests updated and 4 new eval positives |
| `SameSite=None` order dependence (`071`) | FIX_EXISTING | Whole-string negative lookahead; positive + negative eval |
| OWS-padded header values (`084`) | FIX_EXISTING | RFC 7230 OWS trimming in the shared validator + 3 assertions |
| Protocol-relative userinfo redirect (`085`) | FIX_EXISTING | Alternation pattern; positive eval |
| Unquoted `src`/`action` mixed content (`055`, `080`) | FIX_EXISTING | Quote-optional patterns within the ReDoS lint; 2 positives |
| COEP `credentialless` false positive (`046`) | FIX_EXISTING | Exact `unsafe-none` opt-out via `response-header-matches` |
| Severity of CSP wildcard (`022`) | FIX_EXISTING | HIGH → MEDIUM, consistent with the other wildcard rules |
| `script-src` allowing `data:` | ADD_MISSING_COMPONENT | New `DPK-DAST-095` + pattern/record/remediation + 2 eval cases |
| CORS origin + credentials correlation | OWNER_BLOCKED | Documented; no single-header simulation |
| Request/response pair analysis | OWNER_BLOCKED | Documented; engine reads one static observation |
| Cacheable `Set-Cookie` correlation | OWNER_BLOCKED | Same gate |
| CSP enforced-vs-report-only correlation | OWNER_BLOCKED | Same gate |
| `X-AspNetMvc-Version` banner | REJECT_DUPLICATE | Covered by `DPK-DAST-027` |
| `X-Debug-Token-Link` banner | REJECT_DUPLICATE | Covered by `DPK-DAST-063` |
| `Location: http://` downgrade alone | REJECT_DUPLICATE | No new evidence shape beyond `085`/`056` |
| Active `OPTIONS`/`TRACE` probing | NOT_APPLICABLE | Engine sends no request |
| Second `frame-ancestors` rule | REJECT_DUPLICATE | Would repeat `DPK-DAST-010`/`092` |
| Meta-refresh body variant | REJECT_DUPLICATE | `DPK-DAST-094` already reads `Refresh` |
| `style-src *` / `img-src http:` variants | REJECT_DUPLICATE | Cosmetic source-type variants of existing rules |

## 4. Phase C — defects repaired

All repairs keep the existing rule id, title, pattern reference and record
identity. No expected result was edited to make a test pass; each repair adds
or strengthens a test that fails on the old payload.

| Rule | Defect proven before the fix | Repair | Regression evidence |
|---|---|---|---|
| `DPK-DAST-022` | `default-src *` was missed when `*` ended the value or followed another source; host wildcards were at risk of matching | `default-src(?=\s)[^;]*?(?<=\s)\*(?=\s|;|$)`, token-bounded | 4 rule tests + `EVAL-DAST-122` positive |
| `DPK-DAST-070` | Same miss for `script-src` | `script-src(?=\s)[^;]*?(?<=\s)\*(?=\s|;|$)` | 4 rule tests |
| `DPK-DAST-086` | Same miss for `connect-src` | `connect-src(?=\s)[^;]*?(?<=\s)\*(?=\s|;|$)` | 4 rule tests |
| `DPK-DAST-092` | Same miss for `frame-ancestors` | `frame-ancestors(?=\s)[^;]*?(?<=\s)\*(?=\s|;|$)` | 4 rule tests |
| `DPK-DAST-071` | Detection depended on `Secure` appearing before `SameSite=None`; `Secure; SameSite=None` was flagged although protected | Whole-cookie negative lookahead over any attribute order | Rule tests + `EVAL-DAST-123` negative |
| `DPK-DAST-084` | `" * "` with optional whitespace was not matched; hand-rolled trimming in the rule payload | Validator trims RFC 7230 OWS before every header regex; payload stays `^\*$` | 3 new `test-packs` assertions + `EVAL-DAST-125` positive |
| `DPK-DAST-085` | Protocol-relative userinfo target (`//user@host`) was missed | `^[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s@]+@|^//[^/\s@]+@` | Rule tests + `EVAL-DAST-124` positive |
| `DPK-DAST-055` | Unquoted `src=http://…` was missed (quote required) | Optional quote + optional spacing, ReDoS-clean | Rule tests + `EVAL-DAST-126` positive |
| `DPK-DAST-080` | Unquoted `action=http://…` was missed | Optional quote + optional spacing, ReDoS-clean | Rule tests + `EVAL-DAST-127` positive |
| `DPK-DAST-046` | `response-header-missing-directive` flagged `credentialless`, a valid isolation value, and the rule's own test pinned that FP | `response-header-matches` with `^unsafe-none$` — only the explicit opt-out; absent header stays `012`; `credentialless` and `require-corp` are negatives | 5 rule tests + `EVAL-DAST-130` negative; `031`/`064` still correct |

`DPK-DAST-022` severity moved from HIGH to MEDIUM. Rationale: the rule reports a
policy that permits arbitrary sources; it does not itself disclose data or
execute code. The other three wildcard rules (`070`, `086`, `092`) are already
MEDIUM, so the corpus is now internally consistent. Final DAST severity mix:
**50 MEDIUM / 40 LOW / 0 HIGH**.

Two payloads (`055`, `080`) initially tripped the repository's ReDoS lint and
were quarantined by the generator. They were rewritten in lint-safe forms
(`["']?\s*`) and re-probed; the lint was **not** relaxed and no rule was
dropped to obtain a PASS.

## 5. Phase D — additions and dedupe

### 5.1 Added rule

| Field | `DPK-DAST-095` |
|---|---|
| Title | CSP `script-src` allows `data:` scripts |
| Severity / CWE / category | MEDIUM / CWE-693 / `csp-weakness` |
| Check | `response-header-matches`, `Content-Security-Policy`, `script-src(?=\s)[^;]*?(?<=\s)data:(?=\s|;|/|$)` |
| Distinct from | `070` (wildcard source), `002` (header absent), `093` (`http:` source) |
| Negative boundary | `data:` in `img-src` or `default-src` alone is not a match |
| Assets | `DPK-PAT-1164`, `DPK-REC-1124`, remediation `1164`, 5 executable tests |
| Evaluation | `EVAL-DAST-128` positive, `EVAL-DAST-129` negative |

### 5.2 Rejected candidates

The rejections in §3 are deliberate. Cosmetic variants (a second rule for the
same header with a different source keyword), duplicates already covered by
canonical ids, and anything requiring a request to be sent were rejected with
the canonical id cited. No id was consumed speculatively: the next free ids are
`DPK-DAST-096`, `EVAL-DAST-131`, `DPK-PAT-1165`, `DPK-REC-1125`.

## 6. Phase E — evaluator extension gate

No new check type was enabled. `scripts/validate-packs.mjs` still exposes
exactly seven check types and `evalDastCheck` still receives one observation.

Two documents now exist:

- `docs/DAST_CHECK_TYPE_EXTENSION_PROPOSAL.md` — the earlier proposal, whose
  `drobon.pack.dast/v2` framing is now marked **superseded** by the new note at
  the top. Its analysis and negative-test matrix remain valid.
- `docs/DAST_CORRELATION_EXTENSION_PROPOSAL.md`
- `docs/DAST_CUMULATIVE_MASTER_PUMP_2026-10-19.md` (this report) — additive to `v1`: exactly two
  new check-type values (`response-headers-correlate`, `request-response-pair`),
  a closed schema for each, a single owner-gated constant
  (`DAST_CORRELATION_ENABLED`), and a rule that a missing `request` is
  `NOT_ASSESSED`, never a pass. **Nothing in it is implemented.**

Status: **BLOCKED_PENDING_OWNER_DECISION.** The correlation families remain
`SCHEMA_BLOCKED`; no independent single-header rules were used to simulate them.

## 7. Phase F — test evidence

Every changed or added rule was checked for at least two meaningful positives,
at least two negatives, boundary/malformed/missing-input behaviour, exact
evidence assertions and neighbouring-rule regression.

| Rule | Rule tests | Eval coverage | Boundary covered |
|---|---:|---|---|
| `022` | 4 | `122` positive | `https://*.example.com` is not a match; `*` at value end and before `;` matches |
| `070` | 4 | existing positives | wildcard scoped to `script-src` only |
| `086` | 4 | existing positives | scoped to `connect-src` only |
| `092` | 4 | existing positives | scoped to `frame-ancestors` only |
| `071` | 4 | `123` negative | `Secure` before/after `SameSite=None`; missing `Secure` still matches |
| `084` | 4 | `125` positive | padded value, empty value, absent header |
| `085` | 4 | `124` positive | scheme userinfo, protocol-relative userinfo, normal path |
| `055` | 4 | `126` positive | quoted, unquoted, spaced, `http:` only on an `https:` page |
| `080` | 4 | `127` positive | quoted, unquoted, non-`form` element |
| `046` | 5 | `130` negative (plus `031`/`064`) | absent header, `unsafe-none`, `credentialless`, `require-corp` |
| `095` | 5 | `128` positive, `129` negative | `script-src` vs `img-src`/`default-src`, token boundary after `data:` |

All nine new evaluation cases were executed **individually** with
`node scripts/run-eval.mjs --case …` before the full run. All nine passed on
that execution. The full run then reproduced the same outcomes, and a second
determinism run produced byte-identical output.

## 8. Phase G — regression

### 8.1 Targeted suites

| Command | Result |
|---|---|
| `node scripts/validate-packs.mjs packs` | PASS — 1,140 files, 0 errors |
| `node scripts/test-packs.mjs` | PASS — 4,717/4,717 |
| `node scripts/test-assets.mjs` | PASS — 8,988/8,988 |
| `node scripts/test-eval.mjs` | PASS — 41/41 |
| `node scripts/test-doc-drift.mjs` | PASS — 119/119 |
| `node scripts/test-current-state.mjs` | PASS — 153/153 |
| `node scripts/test-consistency.mjs` | PASS — 222/222 |
| `node scripts/validate-assets.mjs` | PASS — 2,234 files, 0 errors |
| `node scripts/coverage-report.mjs --check` | PASS |

### 8.2 Full chain

`npm test` → **exit 0**, **19,512 assertions**, all sub-suites passing:
tests 600, pack 4,717, audience 3,455, asset 8,988, consistency 222,
rehearsal 78, importer 49, agent-policy 91, agent-workflows 57,
finding-evidence 31, secret-candidates 35, sca-engine 38, sca-fixtures 177,
eval 41, doc-drift 119, current-state 153, final 656, determinism 5.

Determinism: 5/5 PASS. The suite prints a whole-tree SHA-256 digest, but that
value is not pinned here: editing this report changes it, so quoting one value
would be a self-invalidating pin. The test's actual assertions — regenerated
file sets identical, every regenerated file byte-identical, checked-in tree
matches — all passed.

## 9. Counts and definitions

| Count | Value | Definition |
|---|---:|---|
| DAST rules | 90 | unique schema-valid files in `packs/dast/v1/rules` |
| Pack rule files | 1,137 | SAST 950 + secrets 97 + DAST 90 |
| Patterns | 1,137 | `knowledge/patterns` files |
| Records | 1,097 | `knowledge/records` files (40 legacy patterns remain record-less) |
| Remediation | 1,137 | `knowledge/remediation` files |
| Evaluation cases | 1,231 | `data/eval-cases` files (130 DAST) |
| Corpus validated total | 2,448 | `docs/CORPUS_TARGETS.json` `totals.validated` |
| DAST check types | 7 | closed vocabulary |
| DAST categories | 12 | `docs/COVERAGE_MAP.json` |
| Repo files (manifest) | 6,157 | every file except `.git/`/`node_modules/` |

DAST check-type tally after the pump: `response-header-matches` 39,
`response-body-matches` 19, `missing-response-header` 16,
`response-header-missing-directive` 11, `cookie-missing-flag` 3, `http-url` 1,
`response-header-host-differs` 1.

## 10. Coverage, inventory, manifest, provenance, originality, dedup

| Check | Result |
|---|---|
| Independent eval coverage | **1,137/1,137** rules (DAST 90/90), 1,231 cases |
| `inventory.mjs --write` | written; `test-current-state` 153/153 |
| `render-capability-coverage.mjs --write` | 33 rows; consistency 222/222 |
| Full-tree manifest | 6,157 entries with size + SHA-256 each; `/tmp/manifest-pump3-final.json` |
| Provenance | every new asset has an authoring origin; no external intelligence imported |
| Originality `--check` | PASS (advisory: repeated remediation on pre-existing `DPK-SAST-896` pairs) |
| Dedup report | 100 advisory files / 84 items / 9 multi-file tuples / **0 conflicts** |
| Dangling pattern/record refs | none; `rules without pattern: 0` |

The manifest is a verification artifact and is deliberately kept outside the
repository. No generated bulk artifact was added to Git.

## 11. Evaluation metrics and preserved expectations

| Population | Cases | Assessed | UNASSESSED | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| All synthetic cases | 1,231 | 1,220 | 11 | 1,157 | 1 | 0 |
| DAST only | 130 | 130 | 0 | 95 | 0 | 0 |

- **One FAIL remains: `EVAL-SAST-008`.** It is a pre-existing false positive
  created by a SAST rule that is known to over-match. It is **not** repaired
  here because changing it is outside this DAST pump's authorization and its
  failure is the honest evidence of that defect. It is not counted as a pass.
- **Eleven UNASSESSED cases remain**: `EVAL-CMD-023/024/025`,
  `EVAL-SAST-004/007/014/015/016`, `EVAL-SEC-111`, `EVAL-SQL-027/028`.
  They are excluded from recall/precision denominators and never reported as
  detections.
- Recall 1.0 in the DAST-only table means *1.0 on this synthetic case set*. It
  is not evidence of real-world detection capability, and no such claim is made.
- Exact-evidence match rate is 100% for the assessed DAST cases: every TP
  carries the declared rule id and evidence substring.

## 12. Consistency, assertions and invariance

### 12.1 Count pins

All live count pins were recomputed and updated together:
`README.md`, `docs/AUDIENCES.md`, `docs/PACKS.md` (Batch 11 plus a new
“Header normalization” note), `docs/CAPABILITY_COVERAGE.md`,
`docs/CAPABILITY_COVERAGE_MATRIX.json` + rendered `.md`,
`docs/CAPABILITY_GAP_MATRIX.md`, `docs/CORPUS_GAP_REPORT.md` (2,448),
`docs/CORPUS_TARGETS.json`, `docs/REQUIREMENTS_MATRIX.json`,
`docs/COVERAGE_MAP.json`, `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md`,
`docs/SCA_RULE_SCHEMA_PROPOSAL.md` (1,040),
`docs/CURRENT_INVENTORY.json`, `scripts/test-doc-drift.mjs`,
`scripts/test-current-state.mjs`, `scripts/test-eval.mjs` (TP 1,157).

`docs/COVERAGE_MAP.json` also carried a stale `cweIds` count (33) that no test
asserted; it is now recomputed from the 90 rules (**41** DAST rules carry a
CWE). The discrepancy was recorded in `docs/PACKS.md` rather than silently
fixed.

### 12.2 Dangling references

`validate-packs` resolves every `patternRefs` entry; there are zero dangling
pattern references. Every evaluation detection names an existing rule and an
existing evidence substring. `test-doc-drift` 119/119 and `test-consistency`
222/222 confirm the documents and the tree agree.

### 12.3 No weakened assertions

- No test was skipped, deleted or reduced; the assertion count rose from 19,494
  to 19,512.
- No expected result was edited to turn a failure green. The one expected change
  was `EVAL-DAST-031`, whose `mustContain` still reads `unsafe-none` and which
  still passes with the repaired `046`.
- `EVAL-SAST-008` and the eleven UNASSESSED cases are preserved exactly.
- Deliberately stale historical pins (1103/1119 strings) were left alone; both
  sides of each such pin still agree.

## 13. Boundaries and invariants

| Invariant | Evidence | Status |
|---|---|---|
| No LICENSE file | `ls LICENSE` → no such file | VERIFIED |
| `docs/OWNER_DECISIONS.json` untouched | no `git status`/`git diff` entry; same bytes as HEAD | VERIFIED |
| No real CVE/NVD/GHSA/OSV/KEV/EPSS/advisory import | no importer executed; no feed file fetched | VERIFIED |
| Synthetic fixtures only | every new case carries `synthetic: true`, `testOnly: true`, provenance “NOT vulnerability intelligence” | VERIFIED |
| Main App untouched | no App checkout modified, no Dataset asset bundled into it | VERIFIED |
| Dataset / App / production DB separation | no loader, adapter or DB change | VERIFIED |
| No secrets or credentials | fixtures contain no real credentials | VERIFIED |
| No commit/push/PR/tag/release/deploy | git state read only | VERIFIED |
| No destructive git | 0 `D`, 0 renames, no reset/clean | VERIFIED |

## 14. Diff review and git state

Final `git status --porcelain` (default): **2,332 `M` / 1,930 `??` / 0 `D`**,
HEAD `ed599c654e972cf517331bb504d65f3e8c2dbcf1`, branch
`arena/a4caaeb8-drobon-dataset`.

`git diff --stat`: 2,332 tracked files changed, 6,083 insertions, 3,609
deletions. These are line-level edits accumulated across pumps (the baseline
already carried 2,317 modified files); there is no whole-file deletion:
every deletion count is an edit inside a preserved file.

New files this pump (16):

- `packs/dast/v1/rules/DPK-DAST-095.json`
- `knowledge/patterns/DPK-PAT-1164.json`
- `knowledge/records/DPK-REC-1124.json`
- `knowledge/remediation/DPK-DAST-095.json`
- `data/asset-cells/dast-12.json`
- `data/eval-cases/EVAL-DAST-122.json` … `EVAL-DAST-130.json` (9 files)
- `docs/DAST_CORRELATION_EXTENSION_PROPOSAL.md`
- `docs/DAST_CUMULATIVE_MASTER_PUMP_2026-10-19.md` (this report)

Modified this pump include the eight asset cells
(`dast.json`, `dast-2/3/4/9/10/11.json`, and the new `dast-12.json`),
`scripts/validate-packs.mjs` (OWS trimming),
`scripts/test-packs.mjs` (3 assertions), the count/matrix pins in §12.1, and
`docs/DAST_CHECK_TYPE_EXTENSION_PROPOSAL.md` (superseded note).

Pre-existing modifications and untracked files from earlier pumps were
preserved. No historical report was overwritten; this is a new dated file.

## 15. Architecture limitation and the 1,000 target

The DAST engine reads **one static observation** (URL, status, headers, optional
body) and evaluates **seven closed check types**. It sends no request, observes
no session, and cannot prove that two headers appeared on the same response or
that a request/response pair behaved a certain way. Those are schema
limitations, not data-authoring gaps, and they are why the correlation families
are blocked rather than “solved” with independent single-header rules.

**DAST + SCA target:** 90 + 0 = **90 / 1,000 (9.0%)**. Status
**NOT MET**. No rule was added to move this number; the only new rule was added
because its evidence shape is genuinely new. The SCA pack schema remains a
separate owner gate, so SCA is **0** and is not merged into DAST to inflate the
figure.

## 16. Blockers and verdict

| ID | Blocker | Status | Minimum decision |
|---|---|---|---|
| `BLK-001` | No LICENSE grant for original content | BLOCKED | Owner license decision |
| `BLK-002` / `GATE-1…4` | Per-source redistribution / production lock not authorized | BLOCKED | Owner/production authorization |
| SCA pack schema | No approved schema for SCA rule packs | BLOCKED | Owner decision (`docs/SCA_RULE_SCHEMA_PROPOSAL.md`) |
| `DAST_CORRELATION_CHECK_TYPES` | Two check types need owner approval | BLOCKED_PENDING_OWNER_DECISION | Owner decision (`docs/DAST_CORRELATION_EXTENSION_PROPOSAL.md`) |
| `GAP-005/006` | Main App has no consumer of `packs/dast` | BLOCKED | App-side loader decision |
| `GAP-AEGIS-01` | SAST 950 vs 1,000 | OPEN | Separate SAST pump |
| `GAP-AEGIS-07` | 11 UNASSESSED evaluation cases | PARTIALLY_VERIFIED | Case-by-case assessment design |
| `GAP-AEGIS-08` | 40 legacy patterns without records; D-13 inactive | OPEN | Owner retention decision |
| `GAP-AEGIS-09` | DAST vocabulary closed at 7 types | BLOCKED | Same correlation decision |
| `GAP-AEGIS-10` | 239 unreachable SAST rules | OPEN | Separate SAST pump |

**VERIFIED:** the ten repairs, the new rule, the nine evaluation cases, all
validators, the full 19,512-assertion suite, the manifest and determinism.

**PARTIALLY_VERIFIED:** aggregate evaluation health — one preserved SAST false
positive and eleven UNASSESSED cases remain.

**BLOCKED:** correlation/request-response check types, SCA packs, license and
rights gates, App integration, the 1,000 target.

**NOT_IMPLEMENTED:** any new check type, any SCA pack, any active probing.

**NOT_ASSESSED:** live-site behaviour, TLS handshake properties,
authorization/IDOR semantics, and the eleven preserved UNASSESSED cases.

**Overall Dataset verdict: NO-GO.** This pump completes the DAST work it can
verify; it does not complete the Dataset, the rights gates, the 1,000 target, or
production readiness.
