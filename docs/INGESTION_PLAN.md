# INGESTION_PLAN.md — production ingestion plan (blocked until authorized)

Status: **PLAN ONLY — BLOCKED_BY_DATA_LOCK.** Nothing in this document authorizes ingestion. Catalog expansion (importers or hand-written real records) is prohibited until every gate in §4 is explicitly approved.

## 1. What exists today (frozen, assessed read-only)

- **100-record GHSA seed** (50 npm + 50 pypi) + 3 labeled fixtures: preserved as-is; provenance complete on all 100 (source/sourceUrl/retrievedAt/license-pointer).
- **Tooling, ready**: `scripts/import-ghsa.mjs` (reviewed-only, validates before writing), `scripts/import-osv.mjs` (fixture-tested mapping), `scripts/range.mjs` (semver/PEP 440 subset), `interop/provider-vectors.json` (16 pinned expectations).
- **Format v1 frozen**: `docs/FORMAT.md` + executable `scripts/validate.mjs`; breaking changes require a new `schemaVersion`.

## 2. Prioritized missing assets (for the authorized stage)

| Priority | Asset | Why | Blocked by |
|---|---|---|---|
| P0 | License decision + grant files | Nothing is consumable/redistributable without terms | Owner decision (`LICENSE_DECISION_RECORD.md` §4) |
| P1 | Provider integration design (app repo) | Zero-match semantics: `ScaDatasetStatus` cannot express "checked, clean" today; range-evaluation policy; config-lock amendment | App maintainers (not this repo) |
| P2 | Catalog breadth batches | 100 records seed the mechanism; production matching needs reviewed breadth per ecosystem | Data lock + P0 + P1 |
| P3 | Pack/audience breadth (optional) | More starter rules/lessons/templates are original content and may grow any time, but are NOT required for any verified capability | Nothing (opportunistic) |
| P4 | Loader implementations (app repo) | Pack + audience loaders per `PACKS.md`/`AUDIENCES.md` checklists | App maintainers |

### Source review status (review findings; authorization still pending)

Machine-readable companion: `docs/SOURCE_ROADMAP.json` (validated by `scripts/validate-corpus.mjs`; volumes stay null until measured at staging).

| Source | Terms pointer | Registry | Records | Redistribution | Priority rationale |
|---|---|---|---|---|---|
| GHSA (reviewed advisories) | github.com/github/advisory-database | `vuln-intel/sources.json` | 100 (frozen seed) | REVIEWED CC-BY-4.0 (LICENSE_REVIEW.md §1) — owner batch authorization still required | Primary: reviewed-only, withdrawn excluded, importer ready |
| OSV (aggregated) | osv.dev | `vuln-intel/sources.json` | 0 (importer ready, runs blocked) | REVIEWED per-home terms (LICENSE_REVIEW.md §2) — resolve per record per batch | Secondary: cross-ecosystem breadth after GHSA batches |
| NVD/CVE feeds | — | not registered | 0 | REVIEWED public-domain+notice (LICENSE_REVIEW.md §3) — no verified need; register before any use | Tertiary: only if a verified need emerges (none today) |

Package priority within P2 batches follows `data/osv-seed-packages.json` (24 curated packages, machine-checked); extend the queue only with reviewed additions.

Explicitly NOT planned (no verified app consumer): CVSS/EPSS/KEV score feeds, exploit/threat-intel feeds, license-intelligence feeds, course/grade systems. See the `NOT_REQUIRED` rows in `docs/REQUIREMENTS_MATRIX.json` for evidence.

## 3. Ingestion procedure (to follow when authorized)

1. Authorize in writing: stage, source(s), maintainer, license basis per source.
2. Grow in small reviewed batches (`import:ghsa`/`import:osv` or hand-written with full provenance); every batch keeps `npm test` green.
3. Human review per `HONESTY.md` checklist: open every `sourceUrl`; verify id/package/severity/ranges; confirm license terms allow the intended use.
4. Same-commit vector updates when outcomes legitimately change (`vuln-intel/README.md` rule); never weaken an expectation without a data reason.
5. Update counts docs + `REQUIREMENTS_MATRIX.json` inventory in the same commit (machine-checked).
6. Record the batch (source, date, count, reviewer) in the matrix provenance notes.

## 4. Authorization gates (all required before any P2 ingestion)

1. Production-data stage explicitly approved (this lock lifted in writing).
2. License decision recorded (`LICENSE_DECISION_RECORD.md` §4 complete).
3. Advisory-record review capacity confirmed (a human opens every source URL — no bulk unreviewed ingest, ever).
4. App-side provider design accepted (P1), so ingested data has a verified consumer contract.

## 5. Non-goals (never)

- Bulk unreviewed ingestion; synthetic records presented as real intelligence.
- Importing data the app cannot consume (scores, feeds, payloads) — the app has no such fields.
- Weakening the app's dataset lock from this repo — integration stays an app-repo decision.
