# PROVIDER_HANDOFF.md — app-side provider dependency (GATE-4)

Date: 2026-10-14. This document specifies the exact handoff the Dataset
workstream needs from the separate Main App workstream before any
production ingestion. It decides nothing on the app side and approves no
ingestion; GATE-4 stays BLOCKED until the evidence below exists.

> **Update 2026-10-21 (App `9360dd1`):** the app now ships the artifacts this
> document asked for. `apps/api/src/scans/sca/filesystemProvider.ts` implements
> `assess(coordinates)` over `DATASET_PATH`, `VULN_INTEL_PROVIDER` accepts
> `none|filesystem` with a documented fail-closed config, and
> `docs/DATASET_APP_CONNECTION.md` describes the zero-match surface. Matching was
> verified against this tree (`fast-jwt@6.2.4` → 6 advisories; 16/16 vectors).
> GATE-2 (licence), GATE-1 (stage approval) and GATE-3 (review capacity) are still
> open, so ingestion is still blocked; see
> `docs/APP_CONNECTION_VERIFICATION_2026-10-21.md` for the evidence and defects.

## 1. The dependency

Ingested advisories need a verified app consumer: an SCA provider that
reads Dataset records, matches them against inventories, and reports
findings. At the time of writing the app had a locked Null provider and no
loader. **As of App `9360dd1` (2026-10-20) the loader exists** (filesystem
provider + `apps/api/src/external/`); the remaining conditions are the licence
and the post-connection conformance items (GAP-040…GAP-048), not the consumer's
existence. Shipping data without a
consumer contract risks schema drift, silent zero-matches, and unverified
range semantics.

## 2. Required app-side artifacts (all four)

1. **Provider design doc** (in the app repo): which record fields are
   consumed, range-evaluation policy, unknown-ecosystem handling.
2. **Zero-match semantics**: what "no finding" means and how the
   `ScaDatasetStatus` surface represents it (today it has no "clean"
   value — see CAPABILITY_COVERAGE.md).
3. **Config-lock amendment**: the documented change that permits a real
   provider where the Null provider is locked today.
4. **Consumer contract**: pinned record projection + interop vectors the
   Dataset side must satisfy (extends the existing 16 vectors).

## 3. Handoff format (what counts as evidence)

- A link to the accepted app-repo design (file path + commit SHA).
- Named app maintainer(s) + acceptance date.
- A compatibility statement: current Dataset record bounds/enums satisfy
  the contract, or the exact fields that must change first.

## 4. What the Dataset side provides in return

- `vuln-intel/` records in FORMAT v1 + `scripts/validate.mjs` schema.
- `check-vectors.mjs` interop vectors (16/16 green) + any new vectors
  the contract adds.
- SHA-256 manifests per corpus version (`scripts/manifest.mjs`).
- Batch records with provenance, license basis, and bucket counts.

## 5. Acceptance path

App workstream publishes 1–2, Dataset workstream extends vectors if the
contract adds cases, both suites green, then the owner records D-PROVIDER
(choice A) with the design link + maintainer + date, and GATE-4 can be
satisfied for that design only. A new design version restarts this path.
