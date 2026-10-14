# GATE_PLAN.md — ingestion and validation gate plan (100K scale)

Design for the automated gates that every production batch must pass. Status key:
`EXISTS` (implemented, green at seed scale), `DESIGN` (specified here, build at
staging), `BLOCKED` (needs a gate from §9 first). Tests passing proves only the
tested properties - never coverage, permission, or readiness by itself.

Assumptions verified 2026-10-14 (no app/schema compatibility changes required):
record bounds mirror `ScaAdvisory` exactly (id<=100, text/url<=400, name<=214,
version<=200); severity/CWE/ecosystem enums mirror the app; range grammar is
validator-enforced; the verbatim record-to-advisory projection is pinned in
`docs/PROVIDER_MAPPING.md`.

| # | Gate | Stage | Automated check | Pass criteria | State |
|---|---|---|---|---|---|
| G1 | Schema validity | always | `validate.mjs` + per-kind validators | 0 errors on every file | EXISTS |
| G2 | Canonical identifiers | always | GHSA-shape, CWE-pattern, id-pattern checks | every id matches its grammar | EXISTS |
| G3 | Duplicate detection | batch | scripts/dedup-report.mjs (identity grouping) + alias review | 0 duplicate identities; aliases attached, not split | EXISTS (seed scale; alias review manual at staging) |
| G4 | Provenance + timestamps | always | required source/sourceUrl/retrievedAt; ISO-8601 | 100% complete, well-formed | EXISTS |
| G5 | License/redistribution | batch | terms-review record per batch + LICENSE tripwire | batch license resolved or batch rejected | DESIGN |
| G6 | Malformed/malicious input | always | negative fixtures + control-char/ bounds guards | every malformed class rejected | EXISTS |
| G7 | Cross-reference integrity | always | consistency suite (dangling refs, pin resolution) | 0 dangling references | EXISTS |
| G8 | Rule conflict + false positives | batch | pack executable tests + FP corpus per rule | all tests pass; FP review recorded | EXISTS (packs) |
| G9 | Deterministic ingestion | batch | byte-identical re-import rehearsal | two runs, identical bytes | DESIGN |
| G10 | Regression | always | suite + vectors + matrix recompute | 740/740-style green, vectors pinned | EXISTS |
| G11 | Integrity + tamper detection | batch | scripts/manifest.mjs (SHA-256 per file, verified pre-release) | manifest matches, no drift | EXISTS (tool; per-release manifests at staging) |
| G12 | Versioning + rollback | batch | corpus version tag + restore rehearsal | rollback restores prior tag byte-identical | DESIGN |
| G13 | Performance + memory | staging | timed full-suite + validator runs at staged scale | budgets met (see OPERABILITY_PLAN) | DESIGN |

## Staging sequence (no production data until §9 gates pass)

1. **Harness staging.** Build G3/G5/G9/G11/G12/G13 against synthetic fixtures at
   1K/10K scale. Synthetic data never counts toward 100K.
2. **Measurement.** Quote the first real volume estimates (GHSA reviewed-only
   npm+PyPI; OSV seed-package yields) with basis + date; validator relaxes
   `volumeEstimate: null` only via an explicit, reviewed staging commit.
3. **Pilot batch.** One small real batch through G1-G13 after owner stage
   approval + terms review; full provenance; rollback rehearsed.
4. **Production batches.** Batched ingestion with per-batch license resolution,
   alias review, and manifest updates until verified production reaches 100K.

## What stays manual (automation assists, humans decide)

Severity/provenance truth per HONESTY.md, alias-canonical choice (§2),
FP-review sign-off, terms-review sign-off, and the release go/no-go.
