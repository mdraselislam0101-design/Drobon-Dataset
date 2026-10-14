# PROVIDER_HANDOFF.md — app-side provider dependency (GATE-4)

Date: 2026-10-14. This document specifies the exact handoff the Dataset
workstream needs from the separate Main App workstream before any
production ingestion. It decides nothing on the app side and approves no
ingestion; GATE-4 stays BLOCKED until the evidence below exists.

## 1. The dependency

Ingested advisories need a verified app consumer: an SCA provider that
reads Dataset records, matches them against inventories, and reports
findings. Today the app side has a locked Null provider and no loader, so
ingested data would have no contract to satisfy. Shipping data without a
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
