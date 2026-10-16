# OWNER DECISION PACKET — Drobon Dataset (2026-10-16)

Prepared for: the repository owner. Every item below was re-verified against
the current tree on 2026-10-16. Nothing here is an "approve everything"
request: each decision is separable, and every recommendation is supported by
named evidence or explicitly withheld. Companion machine-readable records:
`docs/BLOCKER_REGISTER.json` (BLK-001..020), `docs/OWNER_DECISIONS.json`,
`docs/OWNER_ACTION_REQUIRED.md` (your register — unchanged by this packet).

**How to reply:** for each decision, name the option (or your own wording),
the **decider**, and the **date**. Only that flips any status. Until then
every item stays `BLOCKED_OWNER_DECISION` / `BLOCKED_PRODUCTION_LOCK`.

---

## P1 — Licensing & redistribution (highest priority; gates G6/G17)

### D-1 · License grant for original content (BLK-001)
- **Affected:** whole repository — there is no `LICENSE`/`COPYING` file (validator tripwire re-checks every run).
- **Current evidence:** `docs/LICENSE_DECISION_RECORD.md` §1 — absence = all-rights-reserved; `REQUIREMENTS_MATRIX.json` shows `licenseStatus: VERIFIED` for **zero** assets.
- **Unresolved question:** which explicit license(s) cover original Dataset content (packs, audiences, CWE summaries, vectors, docs)?
- **License/redistribution implication:** none is granted to anyone until you decide; a public repo without a license is not permission.
- **Production impact:** G6 stays `BLOCKED_OWNER_DECISION`; no production release.
- **Safe options:** (a) choose a data license (e.g. CC-BY-4.0) and commit the grant file(s); (b) declare all-rights-reserved explicitly.
- **Recommended:** not recommended here — legal/business choice, evidence cannot pick a license for you.
- **Decision required:** option + decider + date.
- **Unblocks after:** licenseStatus flip with evidence, G6 path opens (still needs D-2).
- **Remains blocked:** third-party record redistribution (D-2), production authorization (D-3).

### D-2 · Per-source redistribution: GHSA / OSV / NVD / CWE / original (BLK-002)
- **Affected:** `docs/OWNER_DECISIONS.json` — 5 decisions, all `OWNER_DECISION_REQUIRED`, `decidedAt/decider` null; `vuln-intel/sources.json` `redistribution: UNVERIFIED`.
- **Current evidence:** GHSA lay review (CC-BY-4.0, `docs/LICENSE_REVIEW.md`) is **evidence, not authorization** (`docs/PROVENANCE_POLICY.md` §6 firewall). Source URLs/SPDX ids are not grants.
- **Unresolved question:** which sources may be redistributed, under what attribution, in which scopes?
- **License implication:** per-source; OSV is per-home-database terms (never one blanket license).
- **Production impact:** blocks production counting (0/100,000 today) and G17.
- **Safe options:** (a) authorize per source with BY attribution (GHSA path is lay-reviewed); (b) authorize a subset, exclude the rest fail-closed; (c) authorize none.
- **Recommended:** (a) or (b) for GHSA only, *after* counsel confirmation — the evidence supports the BY path for GHSA specifically; no recommendation for OSV/NVD beyond "resolve per home terms".
- **Decision required:** per-source verdict + attribution + decider + date.
- **Unblocks after:** `sources.json` redistribution flip per source, production batches become *possible* (still need D-3).
- **Remains blocked:** anything outside the authorized scope.

## P2 — Production ingestion (gate G8 / Production Intelligence Lock)

### D-3 · Stage authorization: GATE-1 + GATE-3 (+ GATE-4 app side) (BLK-003)
- **Affected:** `docs/OWNER_ACTION_REQUIRED.md` §2–§3; importers exit 1 in production mode without gates; G8 `BLOCKED_PRODUCTION_LOCK`.
- **Current evidence:** staged fail-closed importer exists and is fully tested with mocks (`scripts/import-ghsa.mjs`, `--dry-run` ready); zero real advisories imported; `verifiedProductionCount = 0` in every category.
- **Unresolved question:** written stage approval naming stage, source(s), maintainer, license basis per source (GATE-1); named reviewer capacity — a human opens every source URL (GATE-3); provider design acceptance (GATE-4, app workstream).
- **License implication:** GATE-1 must cite D-2 outcomes per source.
- **Production impact:** the only path from 0/100,000 to verified production.
- **Safe options:** (a) grant stage approval for one named batch after D-2; (b) keep the lock (synthetic rehearsals continue).
- **Recommended:** (a) only after D-2 lands; single batch, dry-run first.
- **Decision required:** approval text + reviewers + decider + date.
- **Unblocks after:** one authorized production batch (per-batch license resolution still applies).
- **Remains blocked:** auto-promotion, bulk unreviewed ingest (forever, by policy).

### D-4 · Approval expiry & corpus-refresh cadence (BLK-004)
- **Affected:** `docs/OWNER_ACTION_REQUIRED.md` §2 policy gap.
- **Unresolved question:** re-review cadence and refresh cadence; until set, any approval is single-batch and non-extending.
- **Safe options:** (a) explicit cadences; (b) declare single-batch-only indefinitely.
- **Recommended:** (a) if production is planned; evidence-neutral otherwise.
- **Unblocks after:** multi-batch approvals become possible. **Remains blocked:** nothing else.

## P3 — Rule policy cluster (14 separable items, `OWNER_ACTION_REQUIRED.md` §6–§7)

Each item: reply with option + decider + date. Full context in the named section.

| # | Decision (BLK) | Options | Evidence-based note |
|---|---|---|---|
| D-5 | npm prerelease policy (BLK-005, §6.2) | npm default / inclusion / configurable | no recommendation — semantic choice |
| D-6 | PyPI pre-release default (BLK-006, §6.3) | PEP 440 exclusion / inclusion / flag | PEP 440 SHOULD exclude — mild lean to exclusion |
| D-7 | DPK-SEC-007 denylist tuning (BLK-007, §6.5) | add `${`/`<` / keep known FP | keep-as-is is the safe default (veto could hide real values) |
| D-8 | Secrets probe-gap rules (BLK-008, §6.6) | author approved set / accept gaps | JDBC gap already closed (DPK-SEC-103) |
| D-9 | Hyphenated ids + aliases (BLK-009, §6.7+§7.3) | schema change / keep out / alias map | tests pin the rejection on purpose |
| D-10 | DPK-SAST-018 `python` tag (BLK-010, §6.8+§7.5) | remove tag / add Python tests | **lean: remove tag** — patterns are HCL-shaped, no Python test exists |
| D-11 | `bash` dual-tag on 25 rules (BLK-011, §6.9) | confirm / revert | generator output byte-identical; confirm is low-risk |
| D-12 | CROSS_CWE 13 groups (BLK-012, §6.10) | accept / revise / drop | needs a reviewer with CWE context |
| D-13 | 40 legacy pattern records (BLK-013, §6.11) | create records / keep exception | both honest; create only via validate+recount |
| D-14 | `universal` on 10 rules (BLK-014, §7.2) | omit `languages` / keep tag | **lean: omit** — matches the DPK-SAST-004 any-file convention |
| D-15 | shell-posix reach (BLK-015, §7.4) | enable via D-9 / accept PARTIAL | follows D-9 |
| D-16 | CWE version pinning (BLK-016, §7.6) | pin / leave unpinned | pin reduces future drift |
| D-17 | D5 local labels `-_` (BLK-017, §7.7) | widen grammar / keep fail-closed | keep rejection is safe; widening needs paired parser+tests work |
| D-18 | Confirm generator denylist fix (BLK-018, §7.1) | confirm / different correction | **lean: confirm** — documented contract + 0 changed files |

## P4 — Domain expansion gates

### D-19 · SCA rule-pack schema (BLK-019, `SCA_RULE_SCHEMA_PROPOSAL.md`)
- **Evidence:** proposal only; `packs/sca/` absent; count stays 0 — no filler.
- **Options:** approve schema (then author via validator+tests after D-2) / keep 0.
- **Unblocks after:** SCA rule-pack authoring path. **Remains blocked:** advisory-derived rules until D-2.

### D-20 · Shopify `shpat_` provider (BLK-020, `PACKS.md` Batch 6)
- **Evidence:** sources disagree (32 hex vs `[a-zA-Z0-9]{32,64}`); quoted changelog URL 404s. Not authored — correct under the real-evidence rule.
- **Options:** verify against Shopify's official docs, then approve category change `service-token` → `provider-token` and author / drop the class.
- **Note:** evidence gathering (reading public docs) may proceed; authoring waits for both evidence and your category decision.

---

**What ONE P1 signature does not unlock:** production data (needs P2), the policy cluster (P3), SCA/Shopify (P4).
**What ALL of P1+P2 unlocks:** a single authorized production batch and, after its evidence lands, a re-run of `docs/RELEASE_READINESS_MATRIX.json` toward G17.
