# LICENSE_DECISION_RECORD.md — license status and required owner decision

Date: 2026-10-14. This record states facts and tracks a pending decision. It grants nothing and is not legal advice.

## 1. Verified status: NO license grant exists

- There is **no `LICENSE`/`COPYING` file** in this repository (verified by direct listing; the requirements-matrix validator re-checks this on every run and fails if a license file appears — the grant commit must update this record, the matrix `licenseStatus` values, and the tripwire together).
- `README.md` ("License") carries an explicit TODO: maintainers must choose data licensing explicitly, and no license is granted by that file's presence.
- Consequence: **nothing in this repository — original or third-party — currently carries reuse, redistribution, or modification terms.** Absence of a license file must be read as "all rights reserved by default", never as permission.

## 2. Per-record pointers are not grants

- Every real `vuln-intel/` record carries `provenance.license` (currently pointer text such as `Verify terms: github.com/github/advisory-database`).
- A pointer, a public URL, an API response, or an SPDX identifier alone does **not** establish permission to redistribute. Each upstream source (GHSA/NVD/OSV/…) carries its own terms; the authorized production stage must verify them source by source (HONESTY.md review checklist already requires this of human reviewers).
- Original Drobon content (packs, lessons, templates, CWE own-words summaries, remediation guidance) likewise has no grant until the owner chooses one.

## 3. Affected assets: marked BLOCKED_LICENSE_REVIEW

In `docs/REQUIREMENTS_MATRIX.json`, `licenseStatus` is `VERIFIED` for **zero** assets. In particular:

- `vuln-intel/` real records → `BLOCKED_LICENSE_REVIEW` (third-party content, terms unverified).
- Original content (packs, audiences, CWE summaries, vectors, docs) → unlicensed own work; consumable by the project only, redistribution terms pending the owner decision.

## 4. Decision required (owner)

1. Choose explicit license(s) for original dataset content and add the grant file(s). **[DECIDED 2026-10-17: PROPRIETARY — see section 7; grant text review and install still outstanding, so this record still shows no grant.]**
2. Confirm the upstream-terms handling for third-party records (per-source verification at the production stage; which sources are redistributable and under what attribution). **[STILL REQUIRED — D-ORIG grants third-party nothing; see section 7.]**
3. Only then: update this record, flip the matrix `licenseStatus` values with evidence, and re-run the suite.

## 5. Work allowed meanwhile

Everything that does not imply a license grant: schemas, validators, traceability, original content creation, synthetic fixtures, documentation, read-only assessment of existing records, and ingestion planning. Prohibited meanwhile: any statement or file that could read as a redistribution grant, and any production-data expansion (see `docs/INGESTION_PLAN.md`).

## 6. Rights-readiness record (prepared 2026-10-17 — no decision recorded)

Preparation only. **No grant, verdict, or approval exists.** This section
records what is ready for the owner so §4 can be answered with full evidence.

### 6.1 Prepared artifacts

| Artifact | Location | Role |
|---|---|---|
| Draft proprietary grant (**DRAFT — NOT APPROVED**) | `docs/PROPRIETARY_LICENSE_DRAFT.md` | D-ORIG option (b) text; alternatives in OWNER_DECISION_CHECKLIST D-ORIG |
| Per-source rights & redistribution checklist | `docs/SOURCE_RELEASE_GATE.md` S1–S6 | what each source's authorization must contain |
| Source-terms lay review (evidence, not legal advice) | `docs/LICENSE_REVIEW.md` | GHSA VERIFIED_ALLOWED (conditions), OSV/NVD RESTRICTED, CWE VERIFIED_ALLOWED, original BLOCKED |
| Attribution & notice requirements | `docs/NOTICE` + per-source rows below | must ship with any authorized publication |
| Decision briefs with options + consequences | `docs/OWNER_DECISION_CHECKLIST.md` (D-GHSA/D-OSV/D-NVD/D-CWE/D-ORIG) + packet sections B–D | the owner's answer sheet |
| Staleness/revocation design | `docs/INGESTION_PROTOCOL.md` §13 | what happens when terms change (design, not implemented) |

### 6.2 Attribution and notice requirements by source (if ever authorized)

- **GHSA:** per-record `provenance.sourceUrl` + CC-BY-4.0 credit (license link
  + change notes per batch) — `INGESTION_PROTOCOL.md` §4.
- **OSV:** per-record origin + upstream home id; each record carries its home
  terms — never one blanket license.
- **NVD (if ever used):** prominent product notice "This product uses data
  from the NVD API but is not endorsed or certified by the NVD."
- **CWE:** canonical definition link per entry; copies of MITRE text would
  additionally require reproducing the CWE Terms of Use notice (none copied).
- **Original content:** per the owner's chosen grant (none chosen).

### 6.3 Unresolved rights, restrictions, uncertainties (all still open)

1. Original-content treatment chosen 2026-10-17 (proprietary, section 7); still missing: grant file text reviewed and installed, owner legal name/jurisdiction, employer/contractor assignment evidence (BLK-001 stays open until these land).
2. GHSA redistribution `UNVERIFIED` in `vuln-intel/sources.json` — lay review
   ≠ counsel; counsel question quoted in packet D-2 field 12.
3. OSV per-home terms unresolved; blanket inference is prohibited.
4. NVD: no verified consumer need; API ToU acceptance is an owner act.
5. CWE acknowledgment-level decision open (own-words-plus-links scope).
6. Retention/staleness questions (what happens if terms change or a grant is
   replaced) recorded in packet addendum P1 — owner must answer with D-1/D-2.
7. `verifiedProductionCount` remains 0 in all categories; the machine tripwire
   (`validate-corpus`/matrix license checks) stays armed.

## 7. D-ORIG decision record — received and recorded 2026-10-17 (evidence pending)

**Owner statement (verbatim, scope preserved):**
> DROBON AEGIS Dataset D-ORIG owner decision: Proprietary — DROBON original
> content remains under DROBON control; no redistribution except explicitly
> authorized use. Third-party source rights remain separate and must be
> verified.

Source of the statement: the repository owner, in the working conversation
(channel evidence; no signed instrument supplied). Recorded in
`docs/OWNER_DECISIONS.json` (`ORIGINAL_CONTENT` → `APPROVED`, `decidedAt:
2026-10-17`) — the schema-allowed values only. The `decider` field records the
statement source ("repository owner"), **not** a verified personal/legal name.

The five states, kept separate:

| State | Status |
|---|---|
| 1. Owner decision received | **YES** — proprietary, 2026-10-17, verbatim above |
| 2. Decision recorded in repository | **YES** — `OWNER_DECISIONS.json` + this record + checklist/packet annotated |
| 3. Required supporting evidence | **PARTIAL** — present: owner statement. **Missing:** owner legal name/entity, jurisdiction, ownership/assignment (employer/contractor) evidence, reviewed grant text (PROPRIETARY_LICENSE_DRAFT stays `DRAFT — NOT APPROVED`), per-asset-class scope confirmation |
| 4. Legal review | **OUTSTANDING** — no counsel review of the proprietary text; lay drafting only; not legal advice |
| 5. Release gate status | **UNCHANGED / BLOCKED** — GATE-2 stays BLOCKED (no grant file, third-party rights open); G6/G16/G17 unchanged; no `LICENSE` file added; verifiedProduction stays 0 |

Scope limits of this decision (absolute):

- It grants **nothing to third parties**. GHSA/OSV/NVD/CWE rights remain
  `UNVERIFIED` / `OWNER_DECISION_REQUIRED` (4/5) exactly as before.
- Selecting proprietary treatment is **not** a license grant: absent a
  reviewed grant file, the legal default remains all-rights-reserved.
- Ownership is **not** legally proven by this record; assignment evidence is
  marked unresolved (section 6.3).
- No signature, legal name, or approval document is invented anywhere.
