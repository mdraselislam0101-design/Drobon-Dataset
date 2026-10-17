# OWNER DECISION PACKET — Drobon Dataset (PHASE 3, 2026-10-17)

Packet version: **OWNER-PACKET/3.0**. Prepared for: the repository owner.
Every status below was re-verified against the working tree on 2026-10-17
(HEAD `050c5070461111e96e8743d1351deafa54d6ad0f`, worktree clean, remote tip
identical). Nothing in this packet is an approval, a legal clearance, or a
release authorization. Companion machine-readable records:
`docs/BLOCKER_REGISTER.json` (BLK-001..019 open, BLK-R01..R03 resolved),
`docs/OWNER_DECISIONS.json` (5/5 `OWNER_DECISION_REQUIRED`),
`docs/INGESTION_GATES.json` (GATE-1..4), `docs/OWNER_ACTION_REQUIRED.md`
(your register — unchanged by this packet), `docs/SOURCE_RELEASE_GATE.md`,
`docs/LICENSE_DECISION_RECORD.md`, `docs/LICENSE_REVIEW.md` (lay evidence).

**How to reply:** for each decision, fill the `Owner decision:` line with the
option (or your own wording), the **decider**, and the **date**, plus an
`Evidence ref:` if you attach one. Only that flips an owner-gated status. Every
field that would record your answer is deliberately blank. Until you reply,
every owner-gated item stays `BLOCKED_*` — **except** the technical items
resolved by Phase 4 engineering decision (addendum below), which you may still
ratify or override.

---

## P0 — PHASE 4 ADDENDUM (2026-10-17): technical decisions resolved

The Phase 4 brief authorized evidence-backed **technical** decisions (naming,
schema conventions, validation policy) without owner sign-off, while keeping
genuinely owner/rights-holder/counsel/reviewer-dependent items blocked.
Accordingly: **15 technical decisions (D-5..D-19 / BLK-005..019) were resolved
by engineering decision — these are NOT owner approvals and remain ratifiable
by you.** Full rationale + evidence per item: `docs/BLOCKER_REGISTER.json`
`resolvedForRecord` BLK-R05..R19. **D-1..D-4 remain exactly as written below
and are unchanged.** The per-block `Status:` lines for D-5..D-19 are
superseded by this table.

| ID | Phase 4 resolution (2026-10-17) | Kind |
|---|---|---|
| D-5 npm prerelease | current semantics adopted as provider contract (vectors pinned); change needs GATE-4 co-design | decided (keep) |
| D-6 PyPI pre-release | current semantics adopted as provider contract | decided (keep) |
| D-7 DPK-SEC-007 denylist | keep as-is (vetoing `${` could hide real values) | decided (keep) |
| D-8 probe-gap rules | no owner gate on technical authoring; sub-gaps = evidence-gated backlog (GAP-013) | decided (backlog) |
| D-9 hyphenated ids | keep schema fail-closed; widening needs app-catalog co-design (GATE-4); aliases rejected | decided (keep) |
| D-10 DPK-SAST-018 tag | **implemented:** `python` tag removed (HCL-shaped patterns, no Python tests) | implemented |
| D-11 `bash` dual-tag | confirmed (documented, deterministic, tested) | decided (keep) |
| D-12 CROSS_CWE groups | accepted as original mapping aids with documented limits (no MITRE endorsement) | decided (keep) |
| D-13 40 legacy records | keep documented retention exception (count-driven creation = padding) | decided (keep) |
| D-14 `universal` rules | **implemented:** 10 rules now omit `languages` (any-file convention); generator updated; reachability recounted | implemented |
| D-15 shell-posix reach | accept PARTIAL (follows D-9) | decided (keep) |
| D-16 CWE pinning | **implemented:** MITRE CWE 4.20 pinned in DATASET_APP_CONTRACT + per-entry `cweVersion: "4.20"` on all 61 entries (validator-enforced against the repo pin only; no external fetch) | implemented |
| D-17 D5 local labels | keep fail-closed rejection (widening = paired parser+tests backlog) | decided (keep) |
| D-18 generator denylist fix | confirmed (byte-identical, tested) | decided (keep) |
| D-19 SCA schema | keep `packs/sca` at 0 until GATE-4 consumer + D-2 rights exist (no filler) | decided (keep) |

Verification after these changes: full suite + all validators green; corpus
counts at that run unchanged (951/911/951/61/94/65/792; Phase 5 recount
2026-10-17 after DPK-SEC-106/107 = 953/913/953/61/96/65/792); coverage recomputed on the
canonical methodology at that run (72.9% = 37.90/52; SAST engine 69.0%; DEVELOPER
73.6%; Phase 5 recount 2026-10-17 after R-CWE-03 = 74.8% = 38.90/52).
Nothing here touches D-1/D-2/GATE-1..4 or the Production Intelligence Lock.

---

## P1 — 2026-10-17 BLOCKER-RESOLUTION PUMP ADDENDUM: prepared decision packages (nothing decided)

State after this pump: **all statuses unchanged** — OWNER_DECISIONS.json stays
5/5 `OWNER_DECISION_REQUIRED`, GATE-1..4 stay `BLOCKED`, BLK-001..004 stay
open. This pump prepared evidence packages only. A prepared decision is not an
approved decision.

Prepared artifacts (cross-referenced from `docs/BLOCKER_REGISTER.json`
`preparedArtifacts`):

| Deliverable | Location | Serves |
|---|---|---|
| GATE-1 stage-approval evidence template | `docs/INGESTION_PROTOCOL.md` §12 | D-3 / BLK-003 |
| GATE-3 reviewer-readiness checklist + review package + sign-off format | `docs/REVIEW_PACKAGE.md` | D-3 / BLK-003 |
| GATE-4 provider design acceptance requirements (P1–P9) | `docs/DATASET_APP_CONTRACT.md` §9 | D-3 / GATE-4 |
| Source-liveness, revocation, staleness design + cadence record | `docs/INGESTION_PROTOCOL.md` §13 | D-4 / BLK-004 |
| Per-source rights/redistribution checklist | `docs/SOURCE_RELEASE_GATE.md` S1–S6 (existing, cited) | D-2 / BLK-002 |
| Original-content rights checklist | section D below (existing, cited) | D-1 / BLK-001 |
| Remaining-work classification (8-way) | `DROBON_REMAINING_WORK.csv` `classification` column (22 rows) | all |
| Draft license (explicitly NOT APPROVED) | `docs/PROPRIETARY_LICENSE_DRAFT.md` | D-1 |

Open questions this pump made explicit beyond the per-source license/
attribution/redistribution questions already listed in sections B–C —
**retention and staleness questions the owner must also answer**:

| Subject | Retention/staleness question |
|---|---|
| GHSA | If CC-BY-4.0 terms or the advisory-database license ever change, do already-ingested records stay redistributable, or must they be quarantined? (Design default: quarantine until re-cleared — INGESTION_PROTOCOL §13.1) |
| OSV | When a home database's terms are unmapped at batch time, is exclusion sufficient, or must prior records from that home be re-reviewed? |
| NVD | If ever used, how long does the NVD notice obligation persist after any later removal of NVD-derived records? |
| CWE | Does the own-words-plus-links acknowledgment need periodic re-confirmation (e.g. at each CWE version bump)? |
| ORIGINAL_CONTENT | If a grant is later replaced, what happens to copies distributed under the old grant (irrevocable vs prospective)? Owner should state this in the grant. |
| All | Which re-review interval makes rights decisions go stale? (D-CADENCE; default while undecided: single-batch, non-extending) |

## A. Executive decision summary

**Current release verdict (unchanged, re-verified):** `BLOCKED — OWNER/PRODUCTION
AUTHORIZATION REQUIRED` (`docs/RELEASE_READINESS_MATRIX.json` `verdict`;
G6/G16/G17 `BLOCKED_OWNER_DECISION`, G8 `BLOCKED_PRODUCTION_LOCK`; G1–G5,
G7, G9–G15 `PASS` with current-run test evidence — see section E).

**Decisions that block progress** (nothing production-bound moves without
them):

| ID | Question | Status | Who |
|---|---|---|---|
| D-1 | License grant for original DROBON content | BLOCKED_OWNER_DECISION | owner |
| D-2 | Per-source redistribution rights (GHSA / OSV / NVD / CWE / original) | BLOCKED_SOURCE_RIGHTS | owner (+ counsel where needed) |
| D-3 | Production stage authorization (GATE-1) + reviewer capacity (GATE-3) | BLOCKED_OWNER_DECISION + BLOCKED_REVIEWER | owner / named reviewer |

**Rights and provenance blockers:** BLK-001 (no `LICENSE`/`COPYING` file
exists — all-rights-reserved default, `docs/LICENSE_DECISION_RECORD.md` §1);
BLK-002 (all five `docs/OWNER_DECISIONS.json` entries undecided;
`vuln-intel/sources.json` `redistribution: UNVERIFIED` for GHSA and OSV).
Provenance itself is complete (100/100 seed records carry
`source/sourceUrl/retrievedAt/license` pointers; 953/953 original artifacts
carry `origin` lineage) — provenance is **not** the blocker; **rights** are.

**Independent-review requirements:** GATE-3 — a named human reviewer must open
every source URL of any authorized batch (`docs/INGESTION_GATES.json` GATE-3;
`docs/HONESTY.md` checklist). No reviewer is named today.

**Decisions that can be deferred without compromising current work:**
D-5..D-18 (rule-policy cluster, `docs/OWNER_ACTION_REQUIRED.md` §6–§7) — these
change engine semantics or metadata, not rights; deferring them leaves current
behavior pinned and honest. D-4 (cadence) is only needed once multi-batch
production is planned; single-batch mode is the safe default meanwhile.
D-19 (SCA rule-pack schema) gates future authoring only. D-20 is already
RESOLVED_FOR_RECORD (BLK-R03).

**Explicitly prohibited while the gates remain closed:**

1. Importing or activating real CVE/NVD/GHSA/OSV/KEV/EPSS/exploit/SCA/threat
   catalogs beyond the frozen 100-file seed (Production Intelligence Lock).
2. Running any live importer or production ingestion process (importers fail
   closed: `requireGates()` throws — reproduced 2026-10-17).
3. Promoting synthetic fixtures to production, or counting anything except
   per `docs/COUNTING_POLICY.md`.
4. Claiming license-cleared, production-ready, exclusive, or
   independently-verified status for any content.
5. Adding a `LICENSE` file, flipping any `OWNER_DECISIONS.json` status, or
   editing `docs/OWNER_ACTION_REQUIRED.md` / `docs/LICENSE_DECISION_RECORD.md`
   on anyone's behalf except on a genuine written owner reply.
6. Any release, tag, publication, deployment, PR, or production-DB/app change.
7. Copying proprietary vendor rules/signatures/datasets.

---

## B. Owner decision register

Statuses use: `VERIFIED` · `RECOMMENDATION_ONLY` · `BLOCKED_OWNER_DECISION` ·
`BLOCKED_SOURCE_RIGHTS` · `BLOCKED_REVIEWER` · `RESOLVED_FOR_RECORD`
(evidence requirement satisfied and recorded; no owner sign-off required).
`RECOMMENDATION (not an approval)` labels are advice only and decide nothing.

### D-1 · License grant for original DROBON content (BLK-001) — gates GATE-2/G6

1. **ID:** D-1 (BLK-001).
2. **Question:** which explicit license(s) cover original DROBON-authored
   Dataset content, and in what scope?
3. **Current repo value:** no `LICENSE`/`COPYING` file exists (root listing +
   `scripts/validate-matrix.mjs` license tripwire passes only while absent;
   `scripts/test-doc-drift.mjs` pins the invariant).
   `docs/REQUIREMENTS_MATRIX.json`: `licenseStatus: VERIFIED` for **0/23**
   entries (3 `BLOCKED_LICENSE_REVIEW`, 12 `ORIGINAL_UNLICENSED`,
   8 `NOT_APPLICABLE`). `docs/OWNER_DECISIONS.json` `ORIGINAL_CONTENT`:
   `OWNER_DECISION_REQUIRED`, `decidedAt: null`, `decider: null`.
   `docs/PROPRIETARY_LICENSE_DRAFT.md` exists as a draft only.
4. **Options:** (a) choose a data/content license (e.g. CC-BY-4.0) and commit
   the grant file(s); (b) choose a proprietary grant (draft exists);
   (c) declare all-rights-reserved explicitly; (d) dual-license by asset class.
5. **Implications:** legal/compatibility: nothing is redistributable today;
   maintenance: a grant commit must simultaneously update
   `docs/LICENSE_DECISION_RECORD.md` §4, matrix `licenseStatus` values, and
   both tripwires; provenance: unchanged (original content already carries
   `origin`); security: none.
6. **RECOMMENDATION (not an approval):** withheld — this is a legal/business
   choice; evidence cannot pick a license for you.
7. **Dependencies / affected:** whole repo (packs, knowledge, learning,
   assessments, engagements, interop, docs, fixtures); D-2 (third-party rows)
   is independent; GATE-2/G6 follow this.
8. **Backward compatibility / migration:** none required; grant is additive.
   If any third-party text is later added, per-source rows (D-2) stay outside
   the grant.
9. **Evidence needed to validate:** grant file(s) committed; decision recorded
   with decider + date; matrix/NOTICE/LICENSE_DECISION_RECORD updated
   consistently; full suite re-run green.
10. **Who decides:** repository owner (rights holder). Not agent-decidable.
11. **Status:** `BLOCKED_OWNER_DECISION`.
12. **Next action:** owner replies with option + decider + date.
    Owner decision: ______________________  Decider: ____  Date: ____
    Evidence ref: ______________________

### D-2 · Per-source redistribution rights (BLK-002) — GATE-2/G6/G17

1. **ID:** D-2 (BLK-002).
2. **Question:** per external source — may the Dataset redistribute and
   commercially use the material, under what attribution, in which scope?
3. **Current repo value:** `docs/OWNER_DECISIONS.json` — 5 entries (GHSA, OSV,
   NVD, CWE, ORIGINAL_CONTENT) all `OWNER_DECISION_REQUIRED`, all
   `decidedAt/decider: null`. `vuln-intel/sources.json`: GHSA/OSV
   `redistribution: UNVERIFIED`. `docs/LICENSE_REVIEW.md` lay findings exist
   (evidence only). `docs/NOTICE` records third-party positions and grants
   nothing. Full per-source matrix: section C of this packet +
   `docs/SOURCE_RELEASE_GATE.md` S1–S6.
4. **Options:** (a) authorize per source with BY attribution (GHSA path is
   lay-reviewed CC-BY-4.0); (b) authorize a subset, fail-closed exclusion of
   the rest; (c) authorize none.
5. **Implications:** licensing: per-source, never one blanket license (OSV is
   per-home-database terms); provenance: per-record pointers already present;
   maintenance: per-batch license-field resolution stays mandatory
   (`docs/HONESTY.md`); security: no effect on the lock mechanics.
6. **RECOMMENDATION (not an approval):** (a) or (b) for **GHSA only**, and only
   after counsel confirmation that CC-BY-4.0 covers our exact use; no
   recommendation for OSV/NVD beyond "resolve per home terms fail-closed";
   CWE needs only an acknowledgment of the own-words-plus-links scope.
7. **Dependencies / affected:** `sources.json` redistribution fields,
   production batching (0/100,000 today), G17; independent of D-5..D-18.
8. **Backward compatibility / migration:** none — records already carry
   provenance; a refusal simply keeps `redistribution: UNVERIFIED`.
9. **Evidence needed:** per-source verdict + attribution requirements + scope,
   recorded with decider + date; counsel note where obtained; per-batch
   resolution procedure named.
10. **Who decides:** owner, with rights-holder/counsel input for GHSA/OSV/NVD
    legal interpretation. Not agent-decidable.
11. **Status:** `BLOCKED_SOURCE_RIGHTS`.
12. **Next action:** owner issues per-source verdicts (section C table) with
    decider + date; counsel question for GHSA is exactly: "does CC-BY-4.0 as
    published in github/advisory-database permit redistribution of
    reviewed-only advisory records in a commercial SCA product with per-record
    attribution + license link + change notes?"
    Owner decision: ______________________  Decider: ____  Date: ____
    Evidence ref: ______________________

### D-3 · Production stage authorization: GATE-1 + GATE-3 (+ GATE-4 app side) (BLK-003)

1. **ID:** D-3 (BLK-003).
2. **Question:** grant written stage approval for named production batch(es)
   (GATE-1) and name reviewer(s) with capacity to open every source URL
   (GATE-3)?
3. **Current repo value:** `docs/INGESTION_GATES.json` GATE-1 `BLOCKED` ("No
   written approval exists"), GATE-3 `BLOCKED` ("No reviewer commitment
   exists"). Importers exit 1 in production mode;
   `requireGates('docs/INGESTION_GATES.json')` throws "production ingestion
   BLOCKED by 4/4 gates" (reproduced 2026-10-17). Zero real advisories
   imported; `verifiedProductionCount = 0` in all 17 CORPUS_TARGETS categories.
4. **Options:** (a) grant stage approval for one named batch after D-2;
   (b) keep the lock (synthetic rehearsals continue).
5. **Implications:** production: the only path from 0/100,000 upward;
   security: single-batch + dry-run first limits exposure; license: GATE-1
   must cite D-2 outcomes per source.
6. **RECOMMENDATION (not an approval):** (a) only after D-2 lands — single
   batch, dry-run first. (b) is the safe default until then.
7. **Dependencies / affected:** D-2 (must precede), GATE-3 reviewer naming,
   `scripts/import-ghsa.mjs` staged run, GATE-4 (app consumer, external).
8. **Backward compatibility / migration:** none — importer behavior unchanged
   until gates flip; gates file is the single switch.
9. **Evidence needed:** approval text naming stage, source(s), maintainer,
   license basis per source (GATE-1); reviewer identity + capacity statement +
   HONESTY.md checklist acknowledgment (GATE-3).
10. **Who decides:** owner (GATE-1); named reviewer (GATE-3 capacity);
    app maintainers (GATE-4, separate workstream — external dependency).
11. **Status:** `BLOCKED_OWNER_DECISION` (GATE-1) + `BLOCKED_REVIEWER`
    (GATE-3). GATE-4: `BLOCKED` external (Main App workstream; not
    implementable in this repo).
12. **Next action:** after D-2, owner writes stage approval and names
    reviewer(s).
    Owner decision: ______________________  Decider: ____  Date: ____
    Evidence ref: ______________________

### D-4 · Approval expiry / re-review + corpus-refresh cadence (BLK-004)

1. **ID:** D-4 (BLK-004).
2. **Question:** what are the approval-expiry/re-review cadence and corpus
   refresh cadence?
3. **Current repo value:** `docs/OWNER_ACTION_REQUIRED.md` §2 "Policy gap (no
   semantics exist yet)"; until set, any approval is single-batch and
   non-extending (documented default, not an approval).
4. **Options:** (a) explicit cadences (e.g. re-review every N months, refresh
   per batch); (b) declare single-batch-only indefinitely.
5. **Implications:** maintenance/staleness risk of production intelligence;
   no rights impact.
6. **RECOMMENDATION (not an approval):** (a) if production is planned;
   evidence-neutral otherwise.
7. **Dependencies:** D-3 (cadence refines approvals; does not gate the first
   single batch). 8. **BC/migration:** none. 9. **Evidence needed:** written
   cadence policy with decider + date.
10. **Who decides:** owner. 11. **Status:** `BLOCKED_OWNER_DECISION`.
12. **Next action:** owner sets both cadences (or confirms option b).
    Owner decision: ______________________  Decider: ____  Date: ____
    Evidence ref: ______________________

### D-5 · npm prerelease policy (BLK-005; `docs/OWNER_ACTION_REQUIRED.md` §6.2)

1. **ID:** D-5. 2. **Question:** for npm range matching, adopt npm's default
   (prerelease matches only against a comparator with same m.m.p + prerelease
   tag), keep inclusion, or make it configurable?
3. **Current value:** `docs/FORMAT.md` npm-semver subset semantics; behavior
   pinned by `interop/provider-vectors.json` (16 vectors) and engine tests.
4. **Options:** npm default / inclusion / configurable. 5. **Implications:**
   engine semantics + provider contract (`docs/DATASET_APP_CONTRACT.md` §3);
   changing it requires paired engine+vector updates. 6. **RECOMMENDATION (not
   an approval):** none — semantic choice. 7. **Dependencies:** D-9 none;
   GATE-4 app consumer must match whatever is chosen. 8. **BC:** behavior
   change would alter match results; version-pinned vectors must be updated
   together. 9. **Evidence needed:** decision + updated vectors/tests if
   behavior changes. 10. **Who decides:** owner. 11. **Status:**
   `BLOCKED_OWNER_DECISION`. 12. **Next action:** owner replies.
   Owner decision: ______________________  Decider: ____  Date: ____

### D-6 · PyPI pre-release default (BLK-006; §6.3)

1. **ID:** D-6. 2. **Question:** PEP 440 SHOULD exclude pre-releases by
   default — keep inclusion, adopt the default, or per-coordinate flag?
3. **Current value:** `docs/FORMAT.md` PEP 440 subset; engine pins current
   behavior. 4. **Options:** PEP 440 exclusion / inclusion / flag.
5. **Implications:** match semantics; provider parity. 6. **RECOMMENDATION
   (not an approval):** mild lean to exclusion (PEP 440 SHOULD). 7. **Deps:**
   GATE-4 parity. 8. **BC:** result-set change if flipped; tests pin current
   behavior. 9. **Evidence:** decision + paired test updates. 10. **Who:**
   owner. 11. **Status:** `BLOCKED_OWNER_DECISION`. 12. **Next:** owner reply.
   Owner decision: ______________________  Decider: ____  Date: ____

### D-7 · DPK-SEC-007 denylist tuning (BLK-007; §6.5)

1. **ID:** D-7. 2. **Question:** add `${` and `<` to the `<password>` /
   `${DB_PASSWORD}` veto denylist (could also veto real values containing
   `${`)? 3. **Current value:** `packs/secrets/v1/rules/DPK-SEC-007.json`
   denylist as authored; regression tests pin current behavior
   (`scripts/test-packs.mjs` veto mutants). 4. **Options:** add / keep.
5. **Implications:** FP-vs-FN tradeoff; rule change + regenerated cells.
6. **RECOMMENDATION (not an approval):** keep-as-is (veto could hide real
   values). 7. **Deps:** none. 8. **BC:** rule content change; regeneration
   determinism re-pinned. 9. **Evidence:** decision; if changed, cell regen +
   full suite. 10. **Who:** owner. 11. **Status:** `BLOCKED_OWNER_DECISION`.
12. **Next:** owner reply.
   Owner decision: ______________________  Decider: ____  Date: ____

### D-8 · Secrets probe-gap rules (BLK-008; §6.6)

1. **ID:** D-8. 2. **Question:** approve authoring new secrets rules (new
   files) for JDBC `password=`, ADO `Password=`, unquoted `DB_PASSWORD=` /
   `export DB_PASSWORD=`, unquoted YAML `password:`, URIs with symbol
   passwords — or accept the gaps? 3. **Current value:** gaps documented in
   `docs/PACKS.md`; JDBC `password=` already closed (DPK-SEC-103); rule count
   94. 4. **Options:** author approved set / accept gaps. 5. **Implications:**
   new-rule policy: real-evidence rule + tests required; counts change only
   via validated authoring. 6. **RECOMMENDATION (not an approval):** none —
   coverage vs FP-tuning choice. 7. **Deps:** D-7 (shared veto design).
8. **BC:** additive. 9. **Evidence:** decision; if approved, authored via
   cells + generator + tests + recount. 10. **Who:** owner. 11. **Status:**
   `BLOCKED_OWNER_DECISION`. 12. **Next:** owner reply.
   Owner decision: ______________________  Decider: ____  Date: ____

### D-9 · Hyphenated language ids + aliases (BLK-009; §6.7 + §7.3)

1. **ID:** D-9. 2. **Question:** widen the schema regex
   (`^[a-z][a-z0-9]{0,31}$`, no hyphens) to allow `github-actions`,
   `shell-posix`, `android-manifest`, and/or accept alias ids (`gha`, `k8s`,
   `compose`)? 3. **Current value:** hyphenated ids inexpressible; tests pin
   the rejection on purpose; `shell-posix`/`github-actions` reach is
   documented as unreachable in `docs/PACKS.md` reachability section;
   `k8s/compose/gitlab→yaml` aliasing rejected as over-broad (subformat ≠
   family, unlike `hcl=terraform`). 4. **Options:** schema change / keep out /
   alias map. 5. **Implications:** schema + generator + app catalog mapping
   (App-side consumers must agree); maintenance of aliases. 6. **RECOMMENDATION
   (not an approval):** none — contract change; if widened, do it as one
   paired schema+tests+contract commit. 7. **Deps:** D-15 follows this; GATE-4
   consumer mapping. 8. **BC:** widening is additive; aliasing broadens match
   scope (behavior change). 9. **Evidence:** decision; schema migration +
   pinned tests if changed. 10. **Who:** owner. 11. **Status:**
   `BLOCKED_OWNER_DECISION`. 12. **Next:** owner reply.
   Owner decision: ______________________  Decider: ____  Date: ____

### D-10 · DPK-SAST-018 `python` tag (BLK-010; §6.8 + §7.5)

1. **ID:** D-10. 2. **Question:** keep the `python` tag (and add Python-shaped
   tests) or remove the tag? 3. **Current value:**
   `packs/sast/v1/rules/DPK-SAST-018.json` `"languages": ["terraform",
   "python"]`; patterns are HCL-shaped; no Python test exists (re-verified
   2026-10-17). 4. **Options:** remove tag / add Python tests. 5.
   **Implications:** honesty rule — untested language claims are defects;
   removal narrows claimed scope honestly. 6. **RECOMMENDATION (not an
   approval):** **remove the tag** (patterns are HCL-shaped, zero Python test
   evidence). 7. **Deps:** none. 8. **BC:** scope-narrowing only. 9.
   **Evidence:** decision; if removed, cell/regen + recount of language
   coverage claims. 10. **Who:** owner. 11. **Status:**
   `BLOCKED_OWNER_DECISION`. 12. **Next:** owner reply.
   Owner decision: ______________________  Decider: ____  Date: ____

### D-11 · `bash` dual-tag on 25 `shell` rules (BLK-011; §6.9)

1. **ID:** D-11. 2. **Question:** confirm the generator-added `bash` tag on
   the 25 `shell` rules (not present in base `dd487175`)? 3. **Current
   value:** generator `runLineTests` emits `shell`+`bash`; output
   byte-identical on regeneration (determinism digest pinned). 4. **Options:**
   confirm / revert. 5. **Implications:** reach semantics (extensionless
   bash); D-15 interplay. 6. **RECOMMENDATION (not an approval):** confirm —
   low-risk, documented. 7. **Deps:** D-15. 8. **BC:** revert would change 25
   files' metadata. 9. **Evidence:** decision. 10. **Who:** owner. 11.
   **Status:** `BLOCKED_OWNER_DECISION`. 12. **Next:** owner reply.
   Owner decision: ______________________  Decider: ____  Date: ____

### D-12 · CROSS_CWE 13-group review (BLK-012; §6.10)

1. **ID:** D-12. 2. **Question:** accept, revise, or drop the CROSS_CWE
   13-group mapping (CWE-470 is in no group)? 3. **Current value:** mapping as
   authored (Pump 3); owner/CWE review open. 4. **Options:** accept / revise /
   drop. 5. **Implications:** finding-enrichment semantics; CWE honesty.
6. **RECOMMENDATION (not an approval):** none — needs a reviewer with CWE
   context. 7. **Deps:** none. 8. **BC:** drop would retire enrichment fields.
9. **Evidence:** decision + reviewer note. 10. **Who:** owner or named CWE
   reviewer. 11. **Status:** `BLOCKED_OWNER_DECISION`. 12. **Next:** owner
   reply / name reviewer.
   Owner decision: ______________________  Decider: ____  Date: ____

### D-13 · Records for the 40 legacy patterns (BLK-013; §6.11)

1. **ID:** D-13. 2. **Question:** create `DPK-REC` records for the 40 legacy
   patterns (DPK-PAT-0001..), or keep the documented retention exception?
3. **Current value:** 953 patterns, 913 records, exactly 40 patterns without
   a record link (recomputed 2026-10-17, Phase 5, from `relatedPatterns`); exception
   documented in `docs/DATASET_APP_CONTRACT.md` §1. 4. **Options:** create
   (via cells + validate + recount) / keep exception. 5. **Implications:**
   counts move 913→953 only through validated authoring (never padding);
   knowledge depth for early rules. 6. **RECOMMENDATION (not an approval):**
   both honest — create only if the coverage is wanted. 7. **Deps:** none.
8. **BC:** additive. 9. **Evidence:** decision; if created, full recount +
   integrity sweep. 10. **Who:** owner. 11. **Status:**
   `BLOCKED_OWNER_DECISION`. 12. **Next:** owner reply.
   Owner decision: ______________________  Decider: ____  Date: ____

### D-14 · `universal` language id on 10 SAST rules (BLK-014; §7.2)

1. **ID:** D-14. 2. **Question:** omit `languages` on the 10 `universal`-tagged
   rules (matching the App's any-file convention, as DPK-SAST-004 does), or
   keep the unreachable tag? 3. **Current value:** 10 rules carry
   `"universal"` (DPK-SAST-026, -063, -138, -190, -247, -277, -307, -361,
   -409, -448); the App has no `universal` family
   (`rules.ts: languages: undefined` = universal) — re-verified against
   `docs/DATASET_APP_CONTRACT.md` §2. 4. **Options:** omit `languages` (rule
   change) / keep tag (unreachable). 5. **Implications:** runtime
   reachability; contract honesty. 6. **RECOMMENDATION (not an approval):**
   **omit `languages`** — matches the documented any-file convention. 7.
   **Deps:** none. 8. **BC:** metadata change; reachability re-audit. 9.
   **Evidence:** decision; if changed, regen + reachability reconciliation.
10. **Who:** owner. 11. **Status:** `BLOCKED_OWNER_DECISION`. 12. **Next:**
    owner reply.
    Owner decision: ______________________  Decider: ____  Date: ____

### D-15 · `shell-posix` reach for the 25 shell rules (BLK-015; §7.4)

1. **ID:** D-15. 2. **Question:** add `shell-posix` reach (needs D-9) or accept
   PARTIAL reach (extensionless bash only; ordinary `.sh` unreached)?
3. **Current value:** reachability reconciliation recorded in `docs/PACKS.md`;
   `shell-posix` id inexpressible today. 4. **Options:** enable via D-9 /
   accept PARTIAL. 5. **Implications:** honest reach claims. 6. **RECOMMENDATION
   (not an approval):** follows D-9. 7. **Deps:** D-9. 8. **BC:** additive if
   enabled. 9. **Evidence:** decision; if enabled, paired schema work + tests.
10. **Who:** owner. 11. **Status:** `BLOCKED_OWNER_DECISION`. 12. **Next:**
    decide after D-9.
    Owner decision: ______________________  Decider: ____  Date: ____

### D-16 · CWE version pinning (BLK-016; §7.6)

1. **ID:** D-16. 2. **Question:** pin a CWE version for `knowledge/cwe/`
   (relationships read from the 4.20 pages) or leave unpinned? 3. **Current
   value:** no version/hierarchy stored; canonical links pinned per entry.
4. **Options:** pin / leave. 5. **Implications:** drift control for
   cross-references. 6. **RECOMMENDATION (not an approval):** pin reduces
   future drift. 7. **Deps:** none. 8. **BC:** additive metadata. 9.
   **Evidence:** decision; if pinned, recorded per-entry + validator support.
10. **Who:** owner. 11. **Status:** `BLOCKED_OWNER_DECISION`. 12. **Next:**
    owner reply.
    Owner decision: ______________________  Decider: ____  Date: ____

### D-17 · D5 local labels with `-`/`_` (BLK-017; §7.7)

1. **ID:** D-17. 2. **Question:** widen the PEP 440 local-label grammar
   (spec-valid, e.g. `1.0+ubuntu-1`) or keep the fail-closed rejection?
3. **Current value:** `validateRange`/`parsePypiVersion` reject local labels;
   rejection pinned by tests. 4. **Options:** widen (paired parser+tests) /
   keep rejection. 5. **Implications:** spec fidelity vs attack surface;
   maintenance cost of widening. 6. **RECOMMENDATION (not an approval):** keep
   rejection is safe; widening needs paired parser+tests work. 7. **Deps:**
   none. 8. **BC:** widening accepts previously-rejected input. 9. **Evidence:**
   decision; if widened, parser + vector updates. 10. **Who:** owner. 11.
   **Status:** `BLOCKED_OWNER_DECISION`. 12. **Next:** owner reply.
   Owner decision: ______________________  Decider: ____  Date: ____

### D-18 · Confirm generator denylist case-insensitivity fix (BLK-018; §7.1)

1. **ID:** D-18. 2. **Question:** confirm the `scripts/generate-assets.mjs`
   `runLineTests` denylist change (case-sensitive → case-insensitive)?
3. **Current value:** change implemented; generator output byte-identical
   (0 changed files on regen; determinism digest `6cff0b21…` reproduced
   2026-10-17); documented in `docs/PACKS.md`. 4. **Options:** confirm /
   different correction. 5. **Implications:** none beyond tooling semantics.
6. **RECOMMENDATION (not an approval):** **confirm** — documented contract +
   0 changed files. 7. **Deps:** none. 8. **BC:** none. 9. **Evidence:**
   decision. 10. **Who:** owner. 11. **Status:** `BLOCKED_OWNER_DECISION`.
12. **Next:** owner reply.
   Owner decision: ______________________  Decider: ____  Date: ____

### D-19 · SCA rule-pack schema (BLK-019)

1. **ID:** D-19. 2. **Question:** approve the proposed SCA rule-pack schema
   (then author via validator+tests after D-2), or keep SCA rule packs at 0?
3. **Current value:** `docs/SCA_RULE_SCHEMA_PROPOSAL.md` proposal only;
   `packs/sca/` absent (verified 2026-10-17); count stays 0 — no filler.
4. **Options:** approve schema / keep 0. 5. **Implications:** opens an
   authoring path; advisory-derived rules still need D-2. 6. **RECOMMENDATION
   (not an approval):** none — domain-expansion choice. 7. **Deps:** D-2 for
   any advisory-derived content; schema approval itself is independent.
8. **BC:** additive. 9. **Evidence:** decision; if approved, schema + validator
   + tests authored under real-evidence rule. 10. **Who:** owner. 11.
   **Status:** `BLOCKED_OWNER_DECISION`. 12. **Next:** owner reply.
   Owner decision: ______________________  Decider: ____  Date: ____

### D-20 · Shopify `shpat_` provider (was BLK-020) — RESOLVED_FOR_RECORD

1. **ID:** D-20. 2. **Question (historical):** verify the `shpat_` prefix
   against official Shopify docs, then decide category
   `service-token`→`provider-token` and author, or drop the class.
3. **Resolution evidence (2026-10-16, BLK-R03):** official Shopify developer
   docs (`https://shopify.dev/docs/api/shopify-app-remix/latest/guide-custom-apps`)
   show the `adminApiAccessToken` example carrying the `shpat_` prefix, which
   confirms the prefix; rule
   **DPK-SEC-105** authored via `data/asset-cells/secrets-4.json` with
   body-format limitation documented (charset/length not published upstream);
   `shpss_`/`shpca_` excluded as different token types; **category stays
   `service-token`** (the proposed `provider-token` change proved
   unnecessary); fixtures use non-hex bodies after GitHub push-protection
   remediation. 4.–9.: no residual work. 10. **Who:** resolved by evidence +
   in-scope original authoring (no owner sign-off required —
   `docs/LICENSE_DECISION_RECORD.md` §5 allows original content creation).
11. **Status:** `RESOLVED_FOR_RECORD` (recorded `docs/BLOCKER_REGISTER.json`
    BLK-R03). 12. **Next action:** none.

---

## C. Source-rights evidence matrix (D-2 working sheet)

Re-inspected 2026-10-17. Vocabulary: facts are cited; lay readings are
labelled; nothing here is legal advice or a clearance. Final status per
source: `CLEARED_WITH_EVIDENCE` (none today) · `REVIEW_REQUIRED` ·
`RIGHTS_UNRESOLVED` · `NOT_PROPOSED` · `NOT_APPLICABLE` (facts/specs/
comparisons; no redistribution question). Full gate rows:
`docs/SOURCE_RELEASE_GATE.md` S1–S6.

| # | Source / official URL | Content class & state | Terms (as documented) | Evidence / access | Attribution | Redistribution / commercial | Uncertainty | Final status | Decider / required evidence |
|---|---|---|---|---|---|---|---|---|---|
| C1 | GHSA reviewed advisories — `https://github.com/github/advisory-database` | advisory records: 100-file frozen seed **present** (`vuln-intel/{npm,pypi}`), 84 identity items / 78 GHSA ids; expansion **proposed** but locked | CC-BY-4.0 (repo LICENSE.md) — lay read | `docs/LICENSE_REVIEW.md` §1; `vuln-intel/sources.json` `licenseReview`; accessed 2026-10-14 | per-record `provenance.sourceUrl` + `retrievedAt` + CC-BY-4.0 credit per batch | lay read: permitted with BY conditions | lay review ≠ counsel; GitHub API ToU applies to retrieval; per-batch license-field resolution still required | `REVIEW_REQUIRED` | owner (+ counsel): D-2 with decider+date; counsel question quoted in D-2 field 12 |
| C2 | OSV — `https://osv.dev` (`api.osv.dev`) | 0 records imported; importer `scripts/import-osv.mjs` staged, fixture-tested; **proposed** | per-home-database terms (no single license) | `docs/LICENSE_REVIEW.md` §2; `sources.json`; accessed 2026-10-14 | per-record origin + home id | permitted only under each record's home terms | per-entry origin resolution required; blanket license must never be inferred | `RIGHTS_UNRESOLVED` | owner (+ counsel): authorize per-home-terms policy + fail-closed exclusion list |
| C3 | NVD — `https://nvd.nist.gov` (API 2.0) | 0 data, 0 keys, no importer run; roadmap reference only (**not imported**) | U.S. public domain (17 USC) + required notice + API Terms of Use for keys | `docs/LICENSE_REVIEW.md` §3; `NOTICE` §4; accessed 2026-10-14 | product notice: "This product uses data from the NVD API but is not endorsed or certified by the NVD." | lay read: permitted with notice; key needs ToU acceptance | no verified consumer need today | `NOT_PROPOSED` (for any batch today) | owner: confirm need first; only then key + notice + D-2 row |
| C4 | MITRE CWE — `https://cwe.mitre.org` | knowledge layer: 61 entries **present** = own-words summaries + canonical links (no MITRE text copied) | CWE Terms of Use (royalty-free incl. commercial; reproduce notice on copies) | `docs/LICENSE_REVIEW.md` §4; `knowledge/cwe/*` `license` links; accessed 2026-10-14 | canonical link per entry | lay read: permitted with notice | acknowledgment-level decision open; verbatim copying would need re-review | `REVIEW_REQUIRED` (acknowledgment) | owner: confirm own-words-plus-links scope needs no further clearance |
| C5 | Original DROBON content | 954 rules, 954 patterns, 914 records, 954 remediations, 61 CWE summaries, 6 lessons, 3 templates, 2 engagements, 16 vectors, cells/tooling/docs/fixtures — **present** | **no LICENSE file — all rights reserved by default** | `docs/LICENSE_DECISION_RECORD.md` §1; `README.md` License TODO | n/a (own work) | **no grant exists** | none — absence is explicit | `RIGHTS_UNRESOLVED` | owner: D-1 written grant |
| C6 | KEV / EPSS / commercial feeds | **absent** — no importer, schema fields, or records | n/a | `docs/SOURCE_RELEASE_GATE.md` S6 | n/a | n/a | n/a | `NOT_PROPOSED` | any future proposal needs a new S-row + consumer seam |
| C7 | Shopify official docs — `https://shopify.dev/docs/api/shopify-app-remix/latest/guide-custom-apps` | evidence-only: `shpat_` prefix fact used to design DPK-SEC-105; **no data copied** | shopify.dev terms (nominative reference to a public fact) | BLK-R03 record, accessed 2026-10-16 | nominative reference in rule provenance notes | n/a — general security knowledge / public fact | none material | `NOT_APPLICABLE` | none required; re-review only if text were copied |
| C8 | npm semver (`node-semver`) & PEP 440 (PyPA) specs | behavioral specs referenced by `docs/FORMAT.md` range engine; **no text copied** | specification documents | `docs/FORMAT.md`; `interop/provider-vectors.json` pins behavior | spec cited nominatively | n/a — behavioral conformance, facts | none material | `NOT_APPLICABLE` | none |
| C9 | Vendor product docs — GitHub Advanced Security, Snyk, Semgrep, Burp Suite | documented-capability benchmark comparison only (`DROBON_PAID_TOOL_BENCHMARK.csv`); **no rules/signatures/cats copied** | vendor public docs | accessed 2026-10-16, cited per row | comparison cites vendor names nominatively | n/a — comparison/facts only | UNKNOWN vendor details excluded, never scored | `NOT_APPLICABLE` | none; never copy vendor rule text |
| C10 | Main App repo (`mdraselislam0101-design/Drobon`) | internal contract reference (ScaAdvisory shape, `assess` seam) — read-only | internal, same owner | `docs/DATASET_APP_CONTRACT.md` @ app `c32c797` | n/a | n/a (workstream separation) | n/a | `NOT_APPLICABLE` | GATE-4 lives in the app workstream |
| C11 | Synthetic fixtures (DROBON-SAMPLE-001..003) | 3 files **present** (`vuln-intel/*/samples/`) | own work; test-only flag enforced | `sources.json` `fixture` entry | n/a | n/a — never counted in production metrics | none | `NOT_APPLICABLE` | none |

Distinctions preserved: **files (100) ≠ unique advisories (78) ≠ identity
items (84)**; structurally validated ≠ license-verified (0) ≠
production-verified (0). No source is `CLEARED_WITH_EVIDENCE` today. Public
accessibility is not redistribution permission; an SPDX id or URL is not a
grant.

---

## D. Original-content rights checklist (D-1 working sheet)

All rows are claimed original DROBON authorship. Existing evidence is
**lineage/provenance only** — it does not establish a grant.

| Content class | Paths | Authorship/provenance evidence | License/grant today | Missing evidence | Rights-holder action | Scope questions the grant must answer | Verification before GATE-2/G6 |
|---|---|---|---|---|---|---|---|
| Rule packs (954) | `packs/{sast,secrets,dast}/v1/rules/` | `origin: 'original-authored'`; cell lineage `data/asset-cells/` → `scripts/generate-assets.mjs`; determinism digest | none (all rights reserved) | written ownership grant; any employer/contractor assignment statement | owner chooses license(s) + commits grant file(s) | modification · redistribution · sublicensing · commercial distribution · VPS deployment — all currently **NOT covered** | grant file + matrix flip + tripwire update + suite green |
| Patterns (954) / Records (914) / Remediation (954) | `knowledge/{patterns,records,remediation}/` | same lineage; `origin` fields | none | same | same | same | same |
| CWE summaries (61) | `knowledge/cwe/` | own-words summaries + pinned canonical links (no MITRE prose) | none (own words); MITRE Terms govern the links | grant for the summaries themselves | same | nominative use of MITRE names/numbers should be expressly permitted in the grant scope | same + D-2 C4 acknowledgment |
| Lessons (6) / Templates (3) / Engagements (2) | `learning/lessons/`, `assessments/templates/`, `engagements/` | `origin`/ids per schema | none | same | same | same | same |
| Provider vectors (16) | `interop/provider-vectors.json` | original behavior pins referencing real records | none | same | same | vectors reference third-party ids — grant should cover original vector text only | same |
| Cells + generator/tooling | `data/asset-cells/`, `scripts/` | git history + `.manifest.json` | none | same | same | same | same |
| Planning/contract docs | `docs/*`, `README.md`, `NOTICE`, CSV/MD audits | git history | none | same | same | `NOTICE` must stay outside the grant (third-party positions) | same |
| Synthetic fixtures (3) | `vuln-intel/{npm,pypi}/samples/` | `fixture: true` + DROBON-SAMPLE ids | none | same | same | test-only retention | same |
| GHSA seed (100 files) | `vuln-intel/{npm,pypi}/` | **third-party — NOT original** | upstream CC-BY-4.0 (lay) | D-2 C1 owner/counsel verdict | covered by D-2, not D-1 | must remain outside any original-content grant | D-2 row C1 |

**Do-not-do reminders:** do not fabricate signatures, dates, author identities,
or written permissions; do not add a LICENSE asserting rights not granted; do
not remove legitimate attribution; do not promise exclusivity over general
security logic. If evidence cannot be established, status stays blocked (or
`QUARANTINED_ORIGIN_UNVERIFIED` convention applies) — never fabricated
provenance.

---

## E. Release-gate checklist

Mapping of the ten required evaluations to the repository's gate registers.
A gate passes **only** when its evidence exists and is verifiable; a passed
gate never implies another.

| # | Evaluation (brief §12) | Repo gate(s) | Purpose | Entry criteria | Required evidence | Approver | Pass / fail / blocking | State now | What changes it |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Engineering & structural validation | G1–G3 (RELEASE_READINESS_MATRIX) | schemas, rules, tests | repo at baseline | validators + full suite exit 0 | maintainer | fail on any validator/test error | **OPEN (PASS)** — re-run 2026-10-17: 8 validators + vectors PASS, 15,730 tests PASS | regression would close it |
| 2 | Provenance & lineage completeness | G5 | every record attributable | ingestion of any real record | 100/100 seed provenance-complete; lineage 954 = 914 cell + 40 legacy; 0 orphan/quarantined | maintainer | fail on missing provenance | **OPEN (PASS)** | provenance regression |
| 3 | D-1 original-content rights | GATE-2 / G6 | grant for own work | owner decision | grant file(s) + LICENSE_DECISION_RECORD §4 + matrix flips | owner | **blocking** | **CLOSED** — BLK-001 | D-1 reply + grant commit |
| 4 | D-2 source redistribution rights | GATE-2 / G6 | per-source rights | per-source verdicts | section C rows flipped with evidence; counsel notes where obtained | owner (+ counsel) | **blocking** | **CLOSED** — BLK-002 | D-2 reply per source |
| 5 | Stage approval | GATE-1 | lift lock for named batch | D-2 done | written approval: stage, sources, maintainer, license basis | owner | **blocking** | **CLOSED** — no approval exists | approval text + date + decider |
| 6 | Source-rights review gate | GATE-2 | license decision recorded | D-1 + D-2 | completed decision record + tripwires updated consistently + suite green | owner + validator | **blocking** | **CLOSED** — 5/5 undecided | D-1+D-2 landing |
| 7 | Independent reviewer | GATE-3 | human opens every URL | reviewer named | identity + capacity + HONESTY.md acknowledgment | owner / reviewer | **blocking** | **CLOSED** — no reviewer | named commitment |
| 8 | Main App provider design | GATE-4 | verified consumer contract | app design accepted | app-repo design (range policy, zero-match, config-lock) accepted | app maintainers | **blocking (external)** | **CLOSED** — tracked as external dependency; **not implementable in this repo** | app workstream (loaders GAP-005..009, CVSS/prioritization per `docs/DATASET_APP_CONTRACT.md`) |
| 9 | Production ingestion authorization | G8 / GATE-1..4 aggregate | data may flow | gates 3–8 | `requireGates()` passes only with all 4 GATE rows non-BLOCKED | owner | **blocking** | **CLOSED** — fail-closed reproduced | all four gates satisfied |
| 10 | Deployment & publication authorization | G17 | release | G1–G16 PASS + verifiedProductionCount > 0 + release authorization | separate written publication approval | owner | **blocking** | **CLOSED** — verifiedProduction 0/100,000 | gates + batch evidence + explicit publication authorization |

Current aggregate: `docs/RELEASE_READINESS_MATRIX.json` verdict `BLOCKED —
OWNER/PRODUCTION AUTHORIZATION REQUIRED` (asOf 2026-10-16, statuses unchanged
on 2026-10-17 re-verification). Engineering completeness and production
authorization are reported separately and never conflated.

---

## F. Next-step dependency plan (ordered by real dependencies)

1. **D-1** — owner records license choice + commits grant file(s). (No
   production work depends on it except release; run it first because GATE-2
   needs it.) — owner.
2. **D-2** — per-source verdicts (section C), counsel confirmation for the
   GHSA question at minimum; OSV per-home policy; CWE acknowledgment. —
   owner (+ counsel). *Independent of D-1 for decision-making, jointly
   required for GATE-2.*
3. **GATE-3** — name reviewer(s) + capacity. — owner/reviewer. *Can proceed in
   parallel with 1–2.*
4. **D-5..D-18** — policy cluster. *Parallel, non-blocking for rights; each
   affects engine semantics or metadata only; land as small paired
   engine+test commits when decided.* — owner.
5. **D-19** — SCA schema decision (authoring after D-2 for anything
   advisory-derived). — owner.
6. **GATE-1** — written stage approval for **one** named batch, citing D-2
   per-source license basis; D-4 cadence optional for a single batch. — owner.
7. **Authorized staging** — importer `--dry-run` against the authorized
   source, then the first authorized batch with per-record review (GATE-3).
   — maintainer under approval.
8. **GATE-4** — Main App workstream: provider design + loaders + CVSS/
   prioritization per `docs/DATASET_APP_CONTRACT.md` (external; tracked, never
   implemented here). — app maintainers.
9. **Re-run `docs/RELEASE_READINESS_MATRIX.json`** toward G17 only after real
   batch evidence exists; **publication/deployment requires a separate
   explicit authorization** beyond this packet. — owner.

Hard stops preserved: no real-data ingestion before steps 1–3 + 6 land;
engineering tests passing never authorize ingestion; the Production
Intelligence Lock and workstream separation remain active throughout.

---

**What ONE P1 (D-1 or D-2) signature does not unlock:** production data
(needs D-3/GATE-1..3), the policy cluster (D-5..D-18), SCA authoring (D-19),
or publication (G17 + separate release authorization).
**What D-1 + D-2 + GATE-1 + GATE-3 unlock:** a single authorized production
batch (dry-run first), whose evidence can then feed a G17 re-run.
