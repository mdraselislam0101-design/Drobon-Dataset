# ASSET_METHODOLOGY.md — how the generated intelligence set is authored (906 pack rules, 906 patterns, 866 generated records)

Date: 2026-10-15. This document states the authoring method so an auditor
can tell systematic original work from padding. The generator
(`scripts/generate-assets.mjs`) is a deterministic compiler: every byte it
writes comes from hand-designed cell data (`data/asset-cells/*.json`) plus
fixed composition templates. Nothing is fetched, copied, or inferred from
third-party rule sets.

## 1. One cell = one detection purpose = three assets

A cell is a (vulnerability class, language/tool) pair, e.g.
`sast:weak-hash-md5:java`. Each passing cell produces exactly:

- one functional rule (`packs/<kind>/v1/rules/DPK-*.json`) with executable
  detection logic and positive/negative tests that really run;
- one unique pattern (`knowledge/patterns/DPK-PAT-*.json`) mirroring the
  rule signal, with its own executed examples;
- one data record (`knowledge/records/DPK-REC-*.json`) describing the
  mechanics, applicability, and risk in our own words;
- one remediation entry (`knowledge/remediation/<ruleId>.json`).

A cell that fails any gate is quarantined (listed, never written). Counts
report validated cells only; quarantined cells are an explicit shortfall,
never silently retried into existence.

## 2. Why language x class cells are distinct (not trivial variations)

Real detection packs (Semgrep, CodeQL) ship per-language rules for the
same weakness because the sink spelling, the test evidence, the safe
alternative, and the remediation differ per language. Our cells follow the
same doctrine, enforced by machine gates:

- every cell has a distinct detection signal (exact-signal uniqueness is
  asserted per target set; same spelling in a different language is a
  different consumer, different evidence, different fix);
- every cell ships executed positive + negative tests (a test that does
  not behave as declared quarantines the cell);
- composed text shares class-level mechanics (the weakness genuinely is
  the same) but every file carries cell-specific substance: concrete sink
  spelling, concrete safe API, concrete test lines, concrete remediation
  before/after;
- record descriptions are asserted unique across the set.

Forbidden by policy and reviewed per class: same-language respellings of
one signal, per-scheme/per-key splits of one generic shape (e.g. one
credentials-in-URL rule, not one per scheme), and any cell semantically
subsumed by an existing rule (documented skip-list in the generator
header).

## 3. Secrets handling

Secret-shaped fixtures exist only as joined-in-memory strings inside the
generator run; cell data stores split fragments, so no committed data file
carries a matchable secret shape. Written fixtures land only in
`packs/secrets/**` (the audited fixture zone) with placeholder runs and
pass the suite leak scan plus GitHub push protection; any shape that
trips push protection is reworked or dropped, never bypassed.

## 4. Determinism and audit

Sorted cell order, fixed ID allocation, no timestamps, stable key order:
re-running the generator on unchanged data produces byte-identical files.
`data/asset-cells/quarantine.json` records skipped cells as bare
(cell, reason) pairs with no secret content. The suite re-verifies every
generated file independently (schema, execution, linkage, leak scan,
inventory), so generator output is evidence, never self-certification.

Retired reservations (21): the manifest keeps the IDs of cells whose source
was removed from `data/asset-cells/` but whose rule files were never
generated. Those IDs stay reserved, because `docs/PACKS.md` says rule IDs are
never reused. The consistency suite pins this list: any other manifest cell
without a rule file fails the test. Retired: DPK-SAST-048, DPK-SAST-508,
DPK-SAST-518, DPK-SAST-535, DPK-SAST-538, DPK-SAST-539, DPK-SAST-551,
DPK-SAST-595, DPK-SAST-631, DPK-SAST-634, DPK-SEC-009, DPK-SEC-012,
DPK-SEC-013, DPK-SEC-027, DPK-SEC-035, DPK-SEC-038, DPK-SEC-041,
DPK-SEC-042, DPK-SEC-053, DPK-SEC-062, DPK-SEC-066.
