# SOURCE_RELEASE_GATE.md — per-source production-ingestion gate ledger

Status: 2026-10-16. This ledger consolidates, **per proposed production
source**, exactly what an ingestion authorization must contain. Policy bodies
live in `docs/PROVENANCE_POLICY.md` (firewall), `docs/LICENSE_REVIEW.md`
(lay review), `docs/OWNER_DECISIONS.json` (decisions), and
`docs/INGESTION_GATES.json` (importer-enforced gates GATE-1..4). Nothing here
grants permission. **Unknown or missing permission = BLOCKED, never approved.**
Verified production records today: **0** (`docs/CORPUS_TARGETS.json`).

Counting vocabulary reminder (docs/COUNTING_POLICY.md): *files* (storage) ≠
*advisories* (unique GHSA ids) ≠ *items* (identity keys). The 100 seed files =
 78 unique advisories = 84 identity items are **structurally validated corpus
artifacts**, not production-verified intelligence.

---

## S1 — GitHub Security Advisories (GHSA) via `gh api /advisories`

| Gate field | State | Evidence |
|---|---|---|
| Exact source | `https://api.github.com/advisories` (GitHub Global Advisory Database; curated from NVD/CVE + submissions) | `scripts/import-ghsa.mjs`; `vuln-intel/sources.json` `sourceUrl` |
| Intended fields | id (GHSA), severity, summary, url, ecosystem, package, version ranges, published/updated timestamps, license pointer | `docs/FORMAT.md` mirrors `ScaAdvisory` (Drobon `c32c797` `packages/shared/src/sca.ts`) |
| Why needed | SCA dependency-vulnerability matching at the app's single runtime seam (`assess(coordinates)`) | `docs/PROVIDER_MAPPING.md` §1–2 |
| License / terms | GitHub advisory entries are published under CC-BY-4.0 (lay-reviewed) | `docs/LICENSE_REVIEW.md` §3 (evidence, NOT authorization) |
| Redistribution / publication rights | **UNVERIFIED** — a lay review is not counsel; per-source owner decision required | `vuln-intel/sources.json` `redistribution: UNVERIFIED`; `OWNER_DECISIONS.json` `GHSA` = `OWNER_DECISION_REQUIRED` |
| Attribution obligations | CC-BY-4.0 BY (attribution + link to license) — must accompany any authorized publication | `docs/LICENSE_REVIEW.md` |
| Version / collection method (if authorized) | snapshot per import run; staged fail-closed importer with dry-run, pagination guards, per-page checkpoint, quarantine | `scripts/import-ghsa.mjs`; `INGESTION_PROTOCOL.md` |
| Validation / provenance | importer re-validates against `validate.mjs` real-record checks (provenance.source/sourceUrl/retrievedAt/license required); 100 seed files pass | `test-importers.mjs` (49 mocked tests); `validate.mjs` |
| **Owner decision + approval evidence** | **NONE — BLOCKED** (BLK-002/GATE-1) | `OWNER_DECISIONS.json` decider/decidedAt null |

## S2 — OSV (osv.dev)

| Gate field | State |
|---|---|
| Exact source | `https://api.osv.dev/v1/query` (importer staged; no production run) |
| Intended fields | OSV id/aliases (CVE/GHSA), affected ranges (ecosystem-specific semver/PEP 440 subsets), summary, references |
| License / terms | **Per home database** (e.g. GitHub-derived entries carry CC-BY-4.0; NVD-derived differ) — never one blanket license |
| Redistribution | **BLOCKED** — per-entry origin must be resolved before any bulk publication |
| Attribution | per origin record |
| Owner decision | `OSV` = `OWNER_DECISION_REQUIRED` — **BLOCKED** |

## S3 — NVD (nvd.nist.gov)

| Gate field | State |
|---|---|
| Exact source | NVD CVE API 2.0 (roadmap only; no importer run) |
| License / terms | NVD terms of use (government work; attribution; no endorsement claim) |
| Redistribution | **BLOCKED** pending documented terms acceptance + owner decision |
| Owner decision | `NVD` = `OWNER_DECISION_REQUIRED` — **BLOCKED** |

## S4 — MITRE CWE (knowledge layer)

| Gate field | State |
|---|---|
| Exact source | `https://cwe.mitre.org/data/definitions/<id>.html` — **links only**; content is own-words summaries |
| License / terms | MITRE CWE terms of use; license pointer per entry (`knowledge/cwe/*` `license` field) |
| Redistribution | summaries are original content; MITRE name/number used nominatively with pinned links — `CWE` decision open for formal acknowledgment |
| Owner decision | `CWE` = `OWNER_DECISION_REQUIRED` — **BLOCKED** (acknowledgment-level) |

## S5 — Original Drobon content (rules, patterns, remediation, lessons, vectors)

| Gate field | State |
|---|---|
| Exact source | authored in-repo (cells → generator → packs/knowledge) |
| License | **no repository LICENSE file exists** — all-rights-reserved default |
| Redistribution | **BLOCKED** until owner grants an explicit license (BLK-001) |
| Owner decision | `ORIGINAL_CONTENT` = `OWNER_DECISION_REQUIRED` — **BLOCKED** |

## S6 — KEV / EPSS / commercial feeds

Not proposed. No importer, no schema fields, no records. Any future proposal
needs a new entry here plus a consumer seam (SCOPE.md rule: no seam, no
directory).

---

### Release-gate summary

| Source | Structurally validated | License-verified | Production-verified | Gate state |
|---|---|---|---|---|
| GHSA seed (100 files) | YES | NO (lay review only) | 0 | BLOCKED (BLK-002, GATE-1/2/3) |
| OSV | n/a (no records) | NO | 0 | BLOCKED |
| NVD | n/a | NO | 0 | BLOCKED |
| CWE knowledge (61) | YES | link-pinned | n/a | acknowledgment open |
| Original (953 rules etc.) | YES | NO (no LICENSE) | n/a | BLOCKED (BLK-001) |

No production corpus may be downloaded, normalized, published, or promoted
until every applicable row above carries an explicit owner decision with
date + decider. The importer enforces `docs/INGESTION_GATES.json` fail-closed.
