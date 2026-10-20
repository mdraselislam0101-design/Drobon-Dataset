# DROBON AEGIS — DAST cumulative master pump, iteration 2 (2026-10-19)

**Verdict: the DAST work in this iteration is VERIFIED; the Dataset remains
NO-GO.** This iteration repaired two shared evaluator defects, added one
backward-compatible optional field to an existing check type, added one genuine
rule, added six evaluation cases, strengthened thirteen rule fixtures, and
recorded one confirmed rule-level defect that cannot be repaired without an
owner decision. No DAST v2, parallel engine, registry or evaluator was created.
No commit, push, PR, tag, release or deployment was made.

| Field | Value |
|---|---|
| Date | 2026-10-19 |
| Repository | `mdraselislam0101-design/Drobon-Dataset` only |
| Branch | `arena/a4caaeb8-drobon-dataset` (unchanged) |
| HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged) |
| Main App | not opened for modification; no file changed |
| Evaluator defects repaired | 2 (shared helpers, all affected rules) |
| Compatible extension | 1 optional field (`requireScheme` on an existing check type) |
| New check types | **0** (vocabulary stays at 7) |
| Rules added | 1 (`DPK-DAST-096`) |
| Evaluation cases added | 6 (`EVAL-DAST-131`…`136`) |
| Rule fixtures strengthened | 13 cells + 3 legacy rule files |
| Final DAST count | **91** (baseline 90) |
| Overall verdict | **NO-GO** |

## 1. Verified baseline (measured, not copied)

| Metric | Baseline | Final | Method |
|---|---:|---:|---|
| DAST rules | 90 | **91** | files in `packs/dast/v1/rules` |
| Pack rules (SAST+secrets+DAST) | 1,137 | **1,138** | 950 + 97 + 91 |
| Patterns | 1,137 | **1,138** | files in `knowledge/patterns` |
| Records | 1,097 | **1,098** | files in `knowledge/records` |
| Remediation | 1,137 | **1,138** | files in `knowledge/remediation` |
| Evaluation cases | 1,231 | **1,237** | files in `data/eval-cases` (136 DAST) |
| Corpus validated total | 2,448 | **2,450** | `CORPUS_TARGETS.totals` recomputed from categories |
| `npm test` | exit 0 / 19,512 assertions | exit 0 / **19,540** | full chain |
| Eval run | TP 1,157 · FP 1 · FN 0 · 11 UNASSESSED | TP **1,160** · FP 1 · FN 0 · 11 UNASSESSED | `scripts/run-eval.mjs` |
| Tracked modifications | 2,332 `M` | 2,362 `M` | `git status --porcelain` |
| Untracked | 1,930 `??` | 1,941 `??` | default (directory-collapsed) |
| Deletions | 0 | 0 | no `D` entries |

The TP delta (+3) is exactly the three new positive cases (131, 132, 134); the
three new negatives add none. The `M` delta (+30) is the 13 regenerated rule
files, 5 regenerated asset-cell files, `scripts/validate-packs.mjs`,
`scripts/test-packs.mjs`, `scripts/test-eval.mjs`, `scripts/test-doc-drift.mjs`,
`scripts/test-current-state.mjs`, and 8 count/matrix documents. The `??` delta
(+11 before this report) is the new cell file, 6 eval cases, 1 rule, 1 pattern,
1 record and 1 remediation entry.

## 2. Gap matrix and dispositions

| Gap | Class | Evidence before the change | Disposition |
|---|---|---|---|
| Cookie flag parsing rejected RFC 6265 optional whitespace | `FIX_EXISTING` | probe: `sid=1; Secure ; HttpOnly` → rule 004 `true` (reported missing Secure) although the flag is present | helper rewritten, 4 new engine rows, rule tests, 1 eval negative |
| Empty header value counted as present | `FIX_EXISTING` | probe: `Content-Security-Policy: ""` → rule 002 `false`; browsers ignore an empty policy | helper rewritten, 8 new engine rows, 2 eval positives |
| `DPK-DAST-074` fixture pinned the empty-value defect | `FIX_EXISTING` | its own test asserted `Content-Type: ""` → `match: false` | fixture corrected, assertion rationale inline |
| Basic-auth challenge over plaintext unrepresentable | `EXTEND_EXISTING` | `response-header-matches` had no scheme scope; `response-body-matches` already had `requireScheme` | optional field added to the existing type |
| Basic auth over http not detected at all | `ADD_MISSING_COMPONENT` | no rule reads `WWW-Authenticate`; 91 titles checked | `DPK-DAST-096` + pattern/record/remediation + 3 eval cases |
| 13 banner rules had no near-miss negative | `FIX_EXISTING` (tests) | every negative omitted the rule's own header, so an over-broad pattern could not fail | empty-value negative added to each |
| `DPK-DAST-050` over-broad (`^//`) | `OWNER_BLOCKED` | probe: `//app.example/home` from `https://app.example/start` → `true`; `DPK-DAST-056` says `false` and covers every true positive | documented, unmodified (§7) |
| CORS `null` origin | `REJECT_DUPLICATE` | `DPK-DAST-058` already matches `^null$` | no rule authored |
| CORS wildcard methods | `REJECT_DUPLICATE` | `DPK-DAST-078` already matches the `*` token | no rule authored |
| CORS origin+credentials / cache+`Set-Cookie` / CSP enforced-vs-report-only | `OWNER_BLOCKED` | one observation, one header per check | proposal retained |
| Request/response pair analysis | `OWNER_BLOCKED` | no request field exists in the observation schema | proposal retained |
| `.env` file contents served | `NOT_APPLICABLE` | a docs page can contain the same `KEY=` text; the body check has no path or media-type scope | consciously not authored |
| Active `OPTIONS`/`TRACE` probing | `NOT_APPLICABLE` | the engine sends no request | not authored |

## 3. Engine defects repaired

### 3.1 Cookie attribute parsing (`DPK-DAST-004`, `006`, `008`)

The old helper tested the flag with `(?:^|;)\s*<flag>(?:;|$)`. RFC 6265 §5.2
allows optional whitespace around attributes, so `sid=1; Secure ; HttpOnly`
left a space before the semicolon and the flag was never recognised — a fully
protected cookie was reported as missing **both** `Secure` and `HttpOnly`.
Measured before the repair:

```
004 want=false got=true  :: session=abc; Secure ; HttpOnly
006 want=false got=true  :: session=abc; Secure; HttpOnly ; SameSite=Lax
```

The helper now splits the cookie into `;`-separated segments, drops the
`name=value` segment, trims each attribute and compares the whole token. It
also rejects a token that sits inside an attribute value (`Path=/Secure`) and
still requires `SameSite` to be an assignment, not a bare word.

### 3.2 Empty field values (`missing-response-header`, 16 rules)

A header whose every value is empty was treated as present. An empty
`Content-Security-Policy:` is discarded by browsers exactly like an absent
header, so a response with no policy at all produced **no** finding — a false
negative across all 16 rules of that type. Measured before the repair:

```
empty("")   DPK-DAST-002 -> false (missing?)
empty("   ") DPK-DAST-002 -> false (missing?)
```

The check now treats `values.every(v => v.trim() === '')` as missing, while a
single non-empty value still suppresses the finding (existing array-value test
unchanged).

### 3.3 The fixture that pinned the defect

`DPK-DAST-074` (Content-Type missing) contained a test asserting that
`Content-Type: ""` on a 204 is **not** missing. That expectation encoded the
defect. The cell now asserts the repaired behaviour on a 200 response, and the
corresponding `test-packs` row was corrected with the rationale written next to
it. This is the only expectation in the repository that changed, and it changed
in the direction of reporting more (never less).

## 4. Compatible extension (no new check type)

`response-header-matches` now accepts the optional `requireScheme` field that
`response-body-matches` already defined and validated:

- values: `"http"` or `"https"`, anything else rejected by the existing check;
- absent → unscoped, i.e. byte-identical behaviour for all 90 pre-existing
  rules (proved by the unchanged evaluation results for every old case);
- present → an observation fetched over the other scheme evaluates `false`
  (out of scope), and an unparseable URL evaluates `false` without throwing;
- no new check type, no schema version, no second registry, no parallel
  evaluator; `DAST_CHECK_TYPES` still has exactly seven entries.

## 5. New rule and assets

| Field | `DPK-DAST-096` |
|---|---|
| Title | Basic authentication challenge sent over plaintext HTTP |
| Severity / CWE / category | MEDIUM / CWE-319 / `transport-security` |
| Check | `response-header-matches`, `WWW-Authenticate`, `(?:^|,)\s*Basic(?:\s|,|$)`, `requireScheme: "http"` |
| Distinct from | 001 (any http URL), 085 (credentials in a redirect target), 063 (debug header) — none reads `WWW-Authenticate` |
| Positives | `Basic realm=…`; `Negotiate, Basic realm=…`; bare `Basic` |
| Negatives | the same challenge over https; `Bearer` over http; no challenge |
| Assets | `DPK-PAT-1165`, `DPK-REC-1125`, `knowledge/remediation/DPK-DAST-096.json`, 6 executable observation tests |
| Evaluation | `EVAL-DAST-134` positive, `EVAL-DAST-135` (https) and `-136` (Bearer) negatives |

## 6. Evaluation evidence

| Case | Variant | Proves |
|---|---|---|
| `EVAL-DAST-131` | positive | empty `Content-Security-Policy` is reported by 002; wildcard rules 022/070/086/092 stay silent |
| `EVAL-DAST-132` | positive | empty `X-Content-Type-Options` is reported by 005; the non-nosniff rule 073 stays silent |
| `EVAL-DAST-133` | negative | a padded, fully flagged cookie is not reported by 004/006/008/071 |
| `EVAL-DAST-134` | positive | http + Basic challenge → 096 |
| `EVAL-DAST-135` | negative | https + Basic challenge → 096 silent |
| `EVAL-DAST-136` | negative | http + Bearer challenge → 096 silent |

All six were executed individually before the full run and all six passed on
that first execution. Full run: **1,237 cases, 1,226 assessed, TP 1,160,
FP 1, FN 0, 11 UNASSESSED, 1 FAIL**.

The single FAIL is the pre-existing `EVAL-SAST-008` false positive (a SAST rule
that over-matches), preserved deliberately — it is outside this DAST pump and is
the honest evidence of that defect. The 11 UNASSESSED cases are unchanged and
are excluded from every denominator.

## 7. Confirmed rule defect left unmodified (owner decision required)

`DPK-DAST-050` — "Weak response control (protocol-relative Location)", pattern
`^//` on `Location`. Measured on the live rule:

```
050  "//app.example/home" -> true     056  "//app.example/home" -> false
050  "//cdn.example/x"    -> true     056  "//cdn.example/x"    -> true
```

`//app.example/home` from `https://app.example/start` is a same-host,
scheme-relative redirect: legitimate, and `DPK-DAST-056` (which compares the
resolved hostname) correctly treats it as no finding. Every true positive of
050 is also produced by 056.

The pattern cannot express "different host" inside a single-header check, so
there are only two honest fixes: retire the rule, or rewrite its identity. Both
change permanent ids/assets and both are permanent, irreversible asset
decisions, so they are owner-gated. **Nothing was changed**, in particular the
rule was not silently narrowed to a cosmetic subset and its expected results
were not edited. Decision request:

> Approve (a) retirement of `DPK-DAST-050` with the id reserved and
> `DPK-DAST-056` cited as the canonical replacement, or (b) a re-scope of the
> id to a different, provable `Location` weakness. Until a decision exists the
> rule remains a known false-positive source and is reported as such.

## 8. Fixture strengthening

Thirteen banner/`\S` rules (027, 028, 029, 031–038, 063, 072) had no negative
case in which their own header was present, so an over-broad pattern could not
have failed. Each cell now also asserts that an empty value is not a
disclosure. Three legacy cookie rules gained an ordering/OWS negative. Corpus
totals: **91 rules, 372 executable observation tests, 194 negatives, 144 of
them near-misses** (previously 176 negatives, 125 near-misses).

## 9. Full validation

| Command | Result |
|---|---|
| `node scripts/validate-packs.mjs packs` | PASS — 1,141 files, 0 errors |
| `node scripts/validate-assets.mjs` | PASS — 2,236 files, 0 errors |
| `node scripts/coverage-report.mjs --check` | PASS |
| `node scripts/inventory.mjs --check` | matches the tree |
| `node scripts/dedup-report.mjs` | 100 files / 84 items / 9 tuples / **0 conflicts** |
| `node scripts/eval-coverage-report.mjs` | **1,138/1,138** rules (DAST 91/91), 1,237 cases |
| `node scripts/originality-report.mjs --check` | PASS (pre-existing repeated-remediation advisory only) |
| `npm test` | **exit 0 — 19,540 assertions** |

Sub-suites: tests 600, pack 4,734, audience 3,458, asset 8,996, consistency
222, rehearsal 78, importer 49, agent-policy 91, agent-workflows 57,
finding-evidence 31, secret-candidates 35, sca-engine 38, sca-fixtures 177,
eval 41, doc-drift 119, current-state 153, final 656, determinism 5.

Determinism: 5/5 PASS (regenerated file sets identical, every regenerated file
byte-identical, checked-in tree matches the generator).

## 10. Count pins reconciled

Updated together and verified by `test-doc-drift` (119/119),
`test-consistency` (222/222) and `test-current-state` (153/153):
`README.md`, `docs/AUDIENCES.md`, `docs/CAPABILITY_COVERAGE.md`,
`docs/CAPABILITY_COVERAGE_MATRIX.json` + rendered `.md`,
`docs/CAPABILITY_GAP_MATRIX.md`, `docs/CORPUS_GAP_REPORT.md`,
`docs/CORPUS_TARGETS.json` (2,450), `docs/REQUIREMENTS_MATRIX.json`,
`docs/COVERAGE_MAP.json` (recomputed: 91 rules, `response-header-matches` 40,
`transport-security` 3, CWE-319 6), `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md`
(1,237 cases / 1,130 distinct rules), `docs/SCA_RULE_SCHEMA_PROPOSAL.md`
(1,041), `docs/CURRENT_INVENTORY.json`, `scripts/test-doc-drift.mjs`,
`scripts/test-current-state.mjs`, `scripts/test-eval.mjs` (TP 1,160).

Deliberately stale historical pins (1103/1119 strings) were left untouched;
both sides of each still agree.

## 11. Boundaries and invariants

| Invariant | Evidence | Status |
|---|---|---|
| No LICENSE file | `ls LICENSE` → no such file | VERIFIED |
| `docs/OWNER_DECISIONS.json` untouched | no status/diff entry | VERIFIED |
| No real vulnerability intelligence | no importer run, no feed fetched, all fixtures synthetic | VERIFIED |
| Main App untouched | no App checkout modified; no asset bundled | VERIFIED |
| No secrets or credentials | fixtures contain no real credentials | VERIFIED |
| No destructive git | 0 `D`, 0 renames, no reset/clean | VERIFIED |
| No commit/push/PR/tag/release | git read-only | VERIFIED |

## 12. Git state

- Branch: `arena/a4caaeb8-drobon-dataset`
- HEAD: `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (unchanged)
- `git status --porcelain`: **2,362 `M` / 1,942 `??` / 0 `D`** (after this report was written)
- `git diff --stat`: 2,362 files changed, 6,610 insertions, 3,621 deletions —
  all line-level edits inside preserved files.
- New files this iteration: `data/asset-cells/dast-13.json`,
  `packs/dast/v1/rules/DPK-DAST-096.json`, `knowledge/patterns/DPK-PAT-1165.json`,
  `knowledge/records/DPK-REC-1125.json`,
  `knowledge/remediation/DPK-DAST-096.json`, `EVAL-DAST-131`…`136`, this report.
- Manifest: full-tree list with size + SHA-256 per file written to
  `/tmp/manifest-pump4-final.json` — **6,169 files** (verification artifact, kept
  out of Git).

## 13. Remaining blockers

| ID | Blocker | Status |
|---|---|---|
| `BLK-001` | No LICENSE grant for original content | BLOCKED |
| `BLK-002` / `GATE-1…4` | Per-source redistribution / production lock | BLOCKED |
| SCA pack schema | No approved schema; SCA packs remain **0** | BLOCKED |
| `DAST_CORRELATION_CHECK_TYPES` | Two correlation check types need owner approval | BLOCKED_PENDING_OWNER_DECISION |
| `DPK-DAST-050` | Confirmed over-broad rule; retirement/rewrite needs owner approval | BLOCKED_PENDING_OWNER_DECISION |
| `GAP-005/006` | Main App has no consumer of `packs/dast` | BLOCKED |
| `GAP-AEGIS-01` | SAST 950 vs the 1,000 planning target | OPEN |
| `GAP-AEGIS-07` | 11 UNASSESSED evaluation cases | PARTIALLY_VERIFIED |
| `GAP-AEGIS-08` | 40 legacy patterns without records; D-13 inactive | OPEN |
| `GAP-AEGIS-09` | DAST vocabulary closed at 7 types | BLOCKED |
| `GAP-AEGIS-10` | 239 unreachable SAST rules | OPEN |
| TARGET-1000 | DAST+SCA = 91 + 0 = **9.1%** of the 1,000 objective | NOT MET |

## 14. Verdict

**VERIFIED:** the two evaluator repairs, the 074 fixture correction, the
`requireScheme` extension (backward compatible, no new type), the new rule and
its assets, the six evaluation cases, the 13 strengthened fixtures, all
validators, the 19,540-assertion suite and determinism.

**PARTIALLY_VERIFIED:** aggregate evaluation health — 1 preserved SAST false
positive and 11 UNASSESSED cases remain.

**BLOCKED:** `DPK-DAST-050` retirement/rewrite, the correlation check types, SCA
packs, license/rights gates and App integration.

**NOT_IMPLEMENTED:** any new check type, any SCA pack, any active probing, any
`.env` rule (no path/media-type scope exists).

**NOT_ASSESSED:** live-site behaviour, TLS handshake properties,
authorization/IDOR semantics, and the 11 preserved UNASSESSED cases.

**Overall Dataset verdict: NO-GO.** Local DAST completion is not the 1,000-rule
target, not Dataset completion, and not a release authorization.

## 15. Next priority-ordered tasks

1. Owner decision on `DPK-DAST-050` (retire with `DPK-DAST-056` canonical, or
   re-scope).
2. Owner decision on `docs/DAST_CORRELATION_EXTENSION_PROPOSAL.md`; if approved,
   implement the validator/evaluator branch and the full negative matrix before
   any correlation rule is authored.
3. Owner decision on `docs/SCA_RULE_SCHEMA_PROPOSAL.md`; SCA stays 0 until then.
4. Resolve the 11 UNASSESSED cases and the 40 record-less legacy patterns
   through explicit decisions, not by lowering evidence standards.
5. Re-verify the Main App contract before any claim of integration.
