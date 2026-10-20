# AEGIS — cumulative gap-closure and in-place Dataset update (2026-10-19)

**Mode:** audit → repair → integrate → verify. Existing valid work preserved; verified defects
fixed in place rather than documented around.

| Field | Value |
|---|---|
| Repository | `mdraselislam0101-design/Drobon-Dataset` |
| Branch | `arena/a4caaeb8-drobon-dataset` |
| Start = end HEAD | `ed599c654e972cf517331bb504d65f3e8c2dbcf1` (no git writes) |
| Worktree at start | 2,315 modified · 1,843 untracked · 0 deleted |
| Worktree at end | 2,315 modified · 1,893 untracked · 0 deleted (32 generated assets + 16 eval cases + 1 corpus + this report) |
| `LICENSE` | absent (BLK-001 invariant preserved) |
| Main App | `c32c797a549453802bd6d82c5673d2a1728457a3`, read-only, untouched |

---

## A. Verified starting baseline

Recomputed from the tree before editing: SAST 950 · secrets 97 · DAST 78 · SCA rule packs 0 ·
patterns 1,125 · records 1,085 · remediation 1,125 · eval 1,200 cases · TP 1,140 / FP 1 / FN 0 ·
SCA 9 fixture corpora / 168 assertions · `npm test` 19,320 assertions exit 0.

**DAST + SCA rule total at start: 78.** (SCA contributes 0 rule packs — `packs/sca/` is empty and
its schema is an owner decision.)

---

## B. What was changed, and why

### B.1 Repaired a verified defect — SCA-CONTRACT-01 (was OPEN, now CLOSED)

**Defect.** `resolveDependencyGraph` de-duplicated a repeated coordinate *before* recording its
`direct` flag, so the surviving node inherited the flag from whichever entry arrived first:

```
[{npm, order-a, 1.0.0, direct:true},  {…, direct:false}] -> direct ["npm:order-a@1.0.0"]
[{npm, order-a, 1.0.0, direct:false}, {…, direct:true}]  -> direct []
```

Both runs were internally deterministic, but the *resolved classification* depended on listing
order — a real determinism defect in a contract whose entire purpose is deterministic,
fail-closed identity resolution.

**Fix (smallest correct change, engine-owned code, no schema change).** The flag is now collected
before de-duplication and applied after the whole listing is read:

```js
if (entry.direct === true) directDeclared.add(key);   // before the duplicate test
…
for (const [key, node] of [...nodes.entries()]) {
  if (directDeclared.has(key) && node.direct !== true) nodes.set(key, Object.freeze({ ...node, direct: true }));
}
```

**Semantics chosen:** direct is a *monotone* property — any declaration that says direct makes the
coordinate a root. This never hides a root, cannot be outvoted by a later duplicate, and leaves
`duplicates` reporting unchanged. It is order-independent in both directions.

**Evidence.** New synthetic corpus `data/sca-fixtures/direct-flags.json` (3 scenarios: direct-first,
direct-last, transitive-only) plus 9 assertions — schema/label/scope integrity for the new corpus,
order independence, byte-identical output under a reordered listing, the transitive-only case, the
duplicate still being reported, and one node per duplicate coordinate.
`test-sca-fixtures` **168 → 177 passed, 0 failed**. Coverage surface grows to **27 SCA
capabilities / 215 assertions** (new capability `duplicate-direct-resolution`).

### B.2 Built missing DAST rules — Batch 9 (8 rules)

Authored as asset cells (`data/asset-cells/dast-10.json`) and produced by the real generator, so
rule, pattern, record and remediation stay referentially intact by construction.

| Rule | Evidence shape | CWE | Severity | Category |
|---|---|---|---|---|
| DPK-DAST-084 | `Access-Control-Expose-Headers: *` | CWE-942 | LOW | cors |
| DPK-DAST-085 | credentials in a `Location` userinfo component | CWE-200 | MEDIUM | open-redirect |
| DPK-DAST-086 | CSP `connect-src *` (exfiltration channel) | CWE-693 | MEDIUM | csp-weakness |
| DPK-DAST-087 | CSP with no `default-src` fallback | CWE-693 | MEDIUM | csp-weakness |
| DPK-DAST-088 | Go panic goroutine dump | CWE-209 | MEDIUM | debug-exposure |
| DPK-DAST-089 | `phpinfo()` page | CWE-489 | MEDIUM | debug-exposure |
| DPK-DAST-090 | Rust panic banner with source location | CWE-209 | MEDIUM | debug-exposure |
| DPK-DAST-091 | Git metadata served (`repositoryformatversion`) | CWE-540 | MEDIUM | information-disclosure |

Each carries 4 executable observation tests (2 positive, 2 negative), one pattern, one record, one
remediation entry and two evaluation cases.

### B.3 Rejected candidates (with evidence, not silence)

| Candidate | Disposition | Evidence |
|---|---|---|
| PEM private key served in a response | **BLOCKED_BY_DESIGN** | The generator's leak pre-screen (`STRICT` shapes) and `test-consistency §13` forbid key-shaped material outside `packs/secrets/`. The rule is technically expressible, but proving it requires embedding a key banner in a fixture. Weakening that guard is an owner/security decision, so the gap is recorded rather than worked around. |
| Oracle / PostgreSQL / SQL Server error-text rules | **Rejected — duplicate** | `DPK-DAST-062` already matches `ORA-\d{5}`, `ERROR: syntax error at or near`, `SQLSTATE[`, MySQL and `PG::SyntaxError`. A second database-error family would fragment one signal. |
| `X-AspNetMvc-Version`, `X-Debug-Token-Link`, `CORP: cross-origin` | **Rejected — near-duplicate / speculative** | Same disclosure as `DPK-DAST-027` / `DPK-DAST-063`; CORP opt-out severity would be invented. |
| CORS origin × credentials, cache × `Set-Cookie`, auth × scheme | **SCHEMA_BLOCKED** | The closed check vocabulary evaluates one header per check. |

---

## C. Cumulative rule count against the 1,000 DAST + SCA target

| Quantity | Start | End | Δ |
|---|---|---|---|
| DAST rules | 78 | **86** | +8 |
| SCA rule packs | 0 | **0** | 0 (owner-gated schema) |
| **DAST + SCA combined** | **78** | **86** | **+8** |
| SAST rules (for context) | 950 | 950 | 0 |

**Target status: NOT MET — 86 / 1,000 (914 short).** This is stated as a measured fact, not a
plan. The remaining distance is *structural*, not a data-entry backlog:

* DAST is bounded by a **closed vocabulary of 7 check types** that each read one header or one
  body. Reaching 1,000 by further DAST authoring would require hundreds of directive permutations
  of the same signal — exactly the trivial-variation padding this pump forbids. The honest
  ceiling of *distinct* observation rules is on the order of tens, and the corpus is already at
  86.
* SCA has **no rule-pack schema at all**. `docs/SCA_RULE_SCHEMA_PROPOSAL.md` is a proposal; the
  owner decision is outstanding; no production advisory data may be imported. Authoring 900 SCA
  rules would require both an approved schema and a rights-cleared corpus — neither exists.

Both are owner/authorisation blockers, recorded in §F. No rule was added to move the number.

---

## D. Verification of the accumulated state

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `node scripts/generate-assets.mjs` | 0 | written 4,447 · removed 0 · quarantined `[]` |
| 2 | `node scripts/validate-packs.mjs` | 0 | PASS (1,136 files, 0 errors) |
| 3 | `node scripts/validate-assets.mjs` | 0 | PASS (2,234 files, 0 errors) |
| 4 | `node scripts/validate-audiences.mjs` | 0 | PASS (1,148 files, 0 errors) |
| 5 | `node scripts/validate-cwe.mjs` | 0 | PASS (63 files, 0 errors) |
| 6 | `node scripts/test-packs.mjs` | 0 | **4,698 / 4,698** |
| 7 | `node scripts/test-sca-engine.mjs` | 0 | 38 passed, 0 failed |
| 8 | `node scripts/test-sca-fixtures.mjs` | 0 | **177 passed, 0 failed** |
| 9 | `node scripts/run-eval.mjs` | 0 | 1,216 cases · **TP 1,148** · FP 1 · FN 0 · 11 UNASSESSED |
| 10 | `node scripts/test-eval.mjs` | 0 | 41 passed, 0 failed |
| 11 | `node scripts/test-consistency.mjs` | 0 | **222 / 222** |
| 12 | `node scripts/test-doc-drift.mjs` | 0 | 119 passed, 0 failed |
| 13 | `node scripts/test-current-state.mjs` | 0 | 153 passed, 0 failed |
| 14 | `node scripts/validate-capability-coverage.mjs` | 0 | 656 passed, 0 failed |
| 15 | `node scripts/coverage-report.mjs --check` | 0 | PASS (27 SCA capabilities / 215 assertions) |
| 16 | `node scripts/inventory.mjs --check` | 0 | matches the tree |
| 17 | `node scripts/manifest.mjs --scope all` | 0 | written, no errors |
| 18 | `node scripts/originality-report.mjs --check` | 0 | PASS (40 legacy patterns · 0 rules without pattern) |
| 19 | `node scripts/dedup-report.mjs` | 0 | 84 items · 9 multi-file tuples · **0 conflict tuples** |
| 20 | `npm test` | **0** | **19,449 assertions**, 18 suites |

`npm test` breakdown: core 600 · packs 4,698 · audiences 3,443 · assets 8,956 · consistency 222 ·
rehearsal 78 · importers 49 · agent-policy 91 · agent-workflows 57 · finding-evidence 31 ·
secret-candidates 35 · sca-engine 38 · sca-fixtures 177 · eval 41 · doc-drift 119 ·
current-state 153 · capability-coverage 656 · determinism 5.

### Failures met and repaired (recorded, not hidden)

1. **Generator quarantine** — the private-key cell was refused by the leak pre-screen. The rule was
   withdrawn (not the guard), and the guard remains active.
2. **4 consistency failures** after generation (README, requirements matrix, corpus totals, audience
   matrix still held 78/1,125/1,085).
3. **15 doc-drift failures** (gap note, capability coverage, SCA proposal, coverage map, coverage
   evidence, remediation count).
4. **6 capability-coverage DCC failures** (declared asset counts).
5. **3 current-state failures** (inventory, audience counts, tripwire line).
6. **1 eval-test failure** (TP pin 1,140 vs actual 1,148).

Every one was a stale declared number; each was corrected at its source of truth and the pin
recomputed from a fresh measurement. No assertion was loosened, skipped or deleted.

### Eval coverage after the change

| Metric | Value |
|---|---|
| Cases (assessed) | 1,216 (1,205) |
| UNASSESSED (never scored) | 11 |
| TP / FP / FN | 1,148 / 1 / 0 |
| Precision / recall | **0.99913** (1,148/1,149) / **1.0** (1,148/1,148) |
| DAST rules with positive coverage | **86 / 86** |
| DAST rules with an explicit negative pair | **58** |
| Negative-control cases | 374 |
| All-domain rules named | 1,125 |

The single false positive remains the preserved `EVAL-SAST-008` docstring trap; recall 1.0 applies
only to this synthetic assessed population.

---

## E. Inventory and documentation reconciled in place

| Artifact | Change |
|---|---|
| `README.md` | 1,133 pack rules (950 + 97 + 86) · 1,133 remediation entries |
| `docs/CORPUS_TARGETS.json` | dast-check 86 · remediation 1,133 · **totals 2,440** · production 0 |
| `docs/REQUIREMENTS_MATRIX.json` | packsDast 86 · patterns 1,133 · records 1,093 · remediation 1,133 |
| `docs/AUDIENCES.md` | shared-base counts and the `matrix-counts` tripwire line |
| `docs/PACKS.md` | Batch 9 log + the SCA-CONTRACT-01 fix record (history preserved, new entries prepended) |
| `docs/CAPABILITY_COVERAGE.md` / `_MATRIX.json` | 86 DAST rules · 1,216 cases · 1,125 rules named · 27 SCA capabilities |
| `docs/CAPABILITY_GAP_MATRIX.md`, `docs/CORPUS_GAP_REPORT.md`, `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md`, `docs/SCA_RULE_SCHEMA_PROPOSAL.md`, `docs/COVERAGE_MAP.json`, `docs/CURRENT_INVENTORY.json` | recount propagated; all pins green |
| `scripts/test-doc-drift.mjs`, `test-current-state.mjs`, `test-eval.mjs` | count pins recomputed (never guessed) |
| Historical reports (2026-10-18 … 2026-10-19 pumps) | **not modified** — superseded facts are corrected in this report, not rewritten in theirs |

---

## F. Remaining gaps, with exact evidence

| ID | Gap | Evidence | Status |
|---|---|---|---|
| **TARGET-1000** | DAST + SCA at 86 / 1,000 | measured above; DAST vocabulary closed at 7 check types, SCA schema proposed only | **OPEN — structural** |
| BLK-001 | No LICENSE | no `LICENSE` file; no grant inferred | BLOCKED (legal) |
| GATE-1…4 | No rights-cleared advisory source | 84 seed items · `verifiedProductionCount` 0 | BLOCKED (rights) |
| SCA-PACKS | SCA rule packs absent | `packs/sca/` empty; proposal unchanged | BLOCKED (owner schema) |
| DAST-KEY | Private-key-in-response rule | leak guard forbids key fixtures outside `packs/secrets/` | BLOCKED_BY_DESIGN |
| DAST-MULTI | CORS credentials × origin, cache × cookie, auth × scheme | closed vocabulary reads one header per check | SCHEMA_BLOCKED |
| DAST-PROBE | Active method/endpoint probing | not authorised | NOT_APPLICABLE |
| SCA-LOCKFILE / SCA-LICENCE / SCA-SBOM | Lockfile consistency, licence expressions, SBOM fields | not modelled in the contract | NOT_IMPLEMENTED |
| GAP-AEGIS-01 | SAST 950 vs 1,000 | unchanged | PARTIAL |
| GAP-AEGIS-02 | 8 SAST short-pattern rules lack a positive eval | `mustContain ≥ 4` versus 2–3-character matches | PARTIAL (owner decision) |
| GAP-AEGIS-06 | App loader absent | Main App unchanged at `c32c797` | BLOCKED (external) |
| GAP-AEGIS-07 | 11 UNASSESSED cases | preserved, never scored | BLOCKED (editorial) |
| GAP-AEGIS-08 | 40 legacy patterns without records; D-13 | unchanged | BLOCKED (owner) |
| GAP-AEGIS-09 | DAST vocabulary closed at 7 | unchanged by design | BLOCKED (owner) |
| GAP-AEGIS-10 | 239 SAST rules unreachable | unchanged | BLOCKED (app catalog) |

---

## G. Dataset / App separation and safety

* Main App untouched; the Dataset pin in `docs/REQUIREMENTS_MATRIX.json` still records `c32c797`.
* No loader, adapter or runtime claim is made; `packs/dast` remains loader-future.
* No new check type, no SCA pack, no schema change, no owner-decision edit, no licence action.
* `docs/OWNER_DECISIONS.json` is byte-identical; D-13 still inactive; no `LICENSE` created.
* Every new fixture is `synthetic: true`, `testOnly: true`, provenance `original-authored`, and is
  excluded from production intelligence counts (`verifiedProductionCount` remains 0).

---

## H. Release decision

**NO-GO.**

| Gate | Result |
|---|---|
| Executable suite | PASS (19,449 assertions, exit 0) |
| DAST integrity and evaluation | PASS (86/86 positive, 58 negative pairs) |
| SCA determinism / fail-closed | PASS (215 assertions, 0 failed; order defect fixed) |
| Provenance / synthetic isolation | PASS |
| DAST + SCA target (1,000) | **NOT MET (86)** |
| SAST target (1,000) | NOT MET (950) |
| Legal / rights / owner schema / App integration | BLOCKED |

---

## I. Exact next actions

1. **Owner decision on the DAST vocabulary** (GAP-AEGIS-09): approve additional observation check
   types (for example multi-header correlation, request/response pairs, or a locked-body heuristic
   contract). Without it, DAST growth is exhausted at distinct rules.
2. **Owner decision on the SCA rule-pack schema** (SCA-PACKS): approve
   `docs/SCA_RULE_SCHEMA_PROPOSAL.md` so SCA can contribute rules at all; advisory content stays
   separately blocked by GATE-1…4.
3. **Owner decision on BLK-EVAL-01** (evidence token ≥4 characters) to close the last 8 SAST
   evaluation gaps.
4. **Owner/security decision on the leak guard** if a private-key-in-response DAST rule is wanted;
   the guard should stay in force until then.
5. Keep BLK-001, GATE-1…4, GAP-AEGIS-06/07/08/10 blocked and re-verify each pump.

Realistically, the 1,000 DAST + SCA target cannot be reached by authoring data alone; it requires
items 1 and 2. That is the honest finding of this pump, and it is why the number is reported as 86
rather than inflated.
