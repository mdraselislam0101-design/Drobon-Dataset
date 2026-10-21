# ASSET_METHODOLOGY.md — how the generated intelligence set is authored (1414 pack rules, 1414 patterns, 1414 generated records)

Date: 2026-10-15; counts refreshed 2026-10-21 from `docs/CURRENT_INVENTORY.json` (1,414 packs / 1,414 patterns / 1,414 records / 1,414 remediation / 69 CWE). The earlier 1,353 counts were the 2026-10-21 batch-26 state. The earlier 954/954/914 header was the 2026-10-18 state and is kept here only as history.
This document states the authoring method so an auditor
can tell systematic original work from padding. The generator
(`scripts/generate-assets.mjs`) is a deterministic compiler: every byte it
writes comes from hand-designed cell data (`data/asset-cells/*.json`) plus
fixed composition templates. Nothing is fetched, copied, or inferred from
third-party rule sets.

## 1. One cell = one detection purpose = four assets

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

### 1.1 Per-sink text and weakness overrides (2026-10-20)

A multi-sink class (one `class` object with a `sinks` map, e.g. `csharp-flag`
or `sys-services`) shares one text template across its sinks. That is right for
the detection logic and wrong for the prose: `PrivateTmp=no`,
`ServerCertificateValidationCallback => true` and `ValidateRequest="false"`
weaken three different things, so a shared sentence either hedges ("relaxes a
security control such as …") or defers the judgement ("Varies by control").

A class may now carry `sinkOverrides`, keyed by the same sink ids as `sinks`:

```json
"sinkOverrides": { "csharp:certcb": { "cwe": "CWE-295", "recordDesc": "…", "risk": "…" } }
```

- Allowed fields: the same text fields as a custom cell's `overrides`
  (`title`, `description`, `remediation`, `limitation`, `why`, `fix`,
  `verifyT`, `recordDesc`, `risk`, `fp`, `scopeT`, `severity`) **plus `cwe`**,
  because one class can legitimately hold constructs from different weakness
  families (request validation, certificate validation, deserialisation, SQL
  building all appear in the .NET flag class).
- Fail-closed: an unknown sink id, an unknown field, a non-string value, or a
  `cwe` with no `knowledge/cwe` entry throws before any file is composed, so a
  typo quarantines the run instead of silently keeping the generic text.
- IDs, `kind`, `class`, `sinks` and the signal are not overridable: allocation
  and detection semantics stay with the cell data.

`scripts/test-assets.mjs` pins the outcome: no record may carry a "Varies by
control" risk line or one of the multi-mechanism hedge templates.

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

Retired reservations (31): the manifest keeps the IDs of cells whose source
was removed from `data/asset-cells/` and whose rule files are not on disk.
Those IDs stay reserved, because `docs/PACKS.md` says rule IDs are never
reused. The consistency suite pins this list: any other manifest cell
without a rule file fails the test. Two entries were withdrawn in the
2026-10-21 defensive batch before publication: the first asked exactly the
question an existing rule already asks, and the second reported evidence that
already contains an existing rule's evidence (a strict subset pair the overlap
gate would have required a ledger entry for). Both were deleted from
`data/asset-cells/dast-22.json` before any rule file was committed. A third
candidate — an unknown Permissions-Policy feature token — was rejected before
ID allocation because its evidence pattern needed 784 characters against the
500-character schema limit.
Retired: DPK-DAST-015, DPK-DAST-018, DPK-DAST-019, DPK-DAST-020, DPK-DAST-048, DPK-DAST-151, DPK-DAST-154,
DPK-DAST-283, DPK-DAST-284,
DPK-SAST-048, DPK-SAST-508,
DPK-SAST-518, DPK-SAST-535, DPK-SAST-538, DPK-SAST-539, DPK-SAST-551,
DPK-SAST-595, DPK-SAST-631, DPK-SAST-634, DPK-SAST-960, DPK-SEC-009, DPK-SEC-012,
DPK-SEC-013, DPK-SEC-027, DPK-SEC-035, DPK-SEC-038, DPK-SEC-041,
DPK-SEC-042, DPK-SEC-053, DPK-SEC-062, DPK-SEC-066.

DPK-DAST-151 (`script-src-attr` unsafe-inline) and DPK-DAST-154 (`style-src-attr` unsafe-inline)
were composed and then withdrawn inside the 2026-10-20 pump: their evidence is a
strict subset of DPK-DAST-021, whose pattern already covers the -elem and -attr
directives with a nonce/hash escape. Withdrawing them keeps the pack free of a
second rule for the same evidence; the IDs stay reserved and are never reused.
