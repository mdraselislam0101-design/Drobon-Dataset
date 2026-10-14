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

1. Choose explicit license(s) for original dataset content and add the grant file(s).
2. Confirm the upstream-terms handling for third-party records (per-source verification at the production stage; which sources are redistributable and under what attribution).
3. Only then: update this record, flip the matrix `licenseStatus` values with evidence, and re-run the suite.

## 5. Work allowed meanwhile

Everything that does not imply a license grant: schemas, validators, traceability, original content creation, synthetic fixtures, documentation, read-only assessment of existing records, and ingestion planning. Prohibited meanwhile: any statement or file that could read as a redistribution grant, and any production-data expansion (see `docs/INGESTION_PLAN.md`).
