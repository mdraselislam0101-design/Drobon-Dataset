# D-13 proposal — concept records for the 40 pre-generator rules

**Status: PROPOSAL ONLY — NOT APPLIED.** This directory is not referenced by the
generator, validators or tests, and it changes **no** count, status or gate.
Activation is blocked by owner decision **D-13 / BLK-013** (`docs/OWNER_DECISION_PACKET.md`
§D-13, status `BLOCKED_OWNER_DECISION`). Nothing here implies owner approval,
licence, or production eligibility.

## What this is

Forty original concept records — `DPK-REC-0941` … `DPK-REC-0980` — for the forty
detection rules that predate the cell compiler and therefore carry a rule, a
pattern and a remediation entry but **no concept record**:

| Family | Rules | Patterns |
|---|---|---|
| SAST | `DPK-SAST-001` … `-022` (22) | `DPK-PAT-0011` … `-0032` |
| Secrets | `DPK-SEC-001` … `-008` (8) | `DPK-PAT-0033` … `-0040` |
| DAST | `DPK-DAST-001` … `-010` (10) | `DPK-PAT-0001` … `-0010` |

Each record is written from the rule's own documented mechanism (title,
category, CWE, severity, limitation already in the pack file) and states the
concept, applicability and risk in DROBON's own words. It is not copied from any
third-party catalog, and it reuses no text from another record.

## Why it exists

`patterns 954 / records 914` is the only structural asymmetry left in the
knowledge layer: 914 rules have rule → pattern → record → remediation, and 40
have rule → pattern → remediation only. Closing it makes the knowledge layer
1:1 and gives the oldest and most fundamental concepts (command injection,
XSS, hard-coded credentials, missing security headers) the same concept layer as
the generated rules.

## Files

| File | Meaning |
|---|---|
| `legacy-records.proposed.json` | the 40 authored records, keyed by rule id, with fixed record ids |
| `generator.patch` | the exact `scripts/generate-assets.mjs` change that emits them deterministically and records `recId` in `data/asset-cells/.manifest.json` |

## What was verified before parking it

The patch was applied in the working tree, the generator was run, and:

- 40 record files were written (`knowledge/records/DPK-REC-0941..0980.json`), all
  schema-valid under `validateRecord`; `validate:packs`, `validate:assets`,
  `validate:cwe` and `validate:audiences` passed;
- a second generator run produced **no** tracked diff (allocation is stable once
  `manifest.legacy[].recId` is populated);
- rules, patterns and remediation files were byte-identical — only the manifest
  gained `recId` fields;
- the count cascade was exercised end-to-end (records 914 → 954, pattern↔record
  1:1) and then reverted.

The change was **not** kept because D-13 is explicitly an owner decision
(“create only if the coverage is wanted”), and this pump must not act on owner
decisions. A later audit re-run confirmed the tree is back at 914 records.

## Activation (owner-approved path)

1. Owner answers D-13 in `docs/OWNER_DECISION_PACKET.md` (option: create).
2. Apply `generator.patch` to `scripts/generate-assets.mjs`.
3. Move `legacy-records.proposed.json` to `data/legacy-records.json`.
4. `node scripts/generate-assets.mjs` → writes 40 records, updates the manifest.
5. Update the pinned counts that intentionally move with this change:
   `docs/AUDIENCES.md` (3 lines incl. the `matrix-counts` tripwire),
   `docs/REQUIREMENTS_MATRIX.json` (`inventory.records`),
   `docs/CORPUS_GAP_REPORT.md` status note,
   `scripts/test-doc-drift.mjs` records expectation,
   `scripts/test-current-state.mjs` (two AUDIENCES assertions),
   `docs/COMPLETION_MATRIX.json` `CAP-PATTERNS-RECORDS`,
   `docs/BLOCKER_REGISTER.json` BLK-013 → resolved,
   `docs/COVERAGE_MAP.json` BE-2 reason,
   `docs/CAPABILITY_COVERAGE_MATRIX.json` record counts and the residual-gap note,
   then `node scripts/inventory.mjs --write`.
6. `npm test` + all validators + `inventory:check` + `originality:check`.

## What it does not do

- It does not mark any record production-eligible (no licence exists).
- It does not create rules, patterns or remediation (those already exist).
- It does not change the 40 rules' detection behaviour.
- It does not imply that the App consumes records (it does not).
