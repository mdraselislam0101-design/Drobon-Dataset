# DATASET_APP_CONTRACT.md — versioned Dataset ↔ Main App compatibility contract

Contract version: **DATASET-APP/1.0** (2026-10-16). App reference: Drobon
`main` @ `c32c797a549453802bd6d82c5673d2a1728457a3` (read-only). Dataset
reference: `arena/9fe99288-drobon-dataset`. This document states what the
Dataset guarantees, what the App expects, and — explicitly — what is **not**
yet verifiable because the App ships no loader. It grants no runtime
compatibility: validating JSON against a schema is not integration.

## 1. Dataset schema / version inventory

| Asset type | Schema id | Location | Id convention |
|---|---|---|---|
| SAST rule pack | `drobon.pack.sast/v1` | `packs/sast/v1/rules/DPK-SAST-###.json` | stable, never reused (26 retired reservations pinned) |
| Secrets rule pack | `drobon.pack.secrets/v1` | `packs/secrets/v1/rules/DPK-SEC-###.json` | same |
| DAST rule pack | `drobon.pack.dast/v1` | `packs/dast/v1/rules/DPK-DAST-###.json` | same |
| Pattern | `drobon.knowledge.pattern/v1` | `knowledge/patterns/DPK-PAT-####.json` | 1:1 with rules (951) |
| Record | `drobon.knowledge.record/v1` | `knowledge/records/DPK-REC-####.json` | 911 (40 legacy patterns intentionally without a record — BLK-013) |
| Remediation | `drobon.knowledge.remediation/v1` | `knowledge/remediation/DPK-*.json` | 1:1 with rules (951), keyed by `ruleId` |
| Advisory record | `drobon.vuln-intel/v1` | `vuln-intel/{npm,pypi}/*.json` | identity `(provenance.source, id, ecosystem, package)`; files≠advisories≠items |
| CWE knowledge | `drobon.knowledge.cwe/v1` | `knowledge/cwe/*.json` | MITRE id, own-words summary + pinned URL |
| Lesson / template / engagement | `drobon.learning.lesson/v1` etc. | `learning/lessons/`, `assessments/templates/`, `engagements/` | `lsn_*` / template ids |
| Provider vectors | `drobon.vuln-intel/vectors/v1` | `interop/provider-vectors.json` | `VEC-###`, real records only |
| Manifest / integrity | SHA-256 manifest | `data/asset-cells/.manifest.json` + `manifest.mjs` | deterministic generation (tree digest pinned per release) |

## 2. Field and convention guarantees

- **Severity** enum: `CRITICAL|HIGH|MEDIUM|LOW|INFO` (advisory) / `HIGH|MEDIUM|LOW` (rules) — rule severity is rule-fixed, never client-influenced.
- **Category** enums per pack (secrets: `service-token`, `service-credential`, `cloud-credential`, `generic-credential`, `private-key`, `hardcoded-credential`).
- **Language tags** (`packs`/`knowledge`): `^[a-z][a-z0-9]{0,31}$` — **hyphenated app catalog ids are inexpressible** (`github-actions`, `shell-posix`, `android-manifest`). Mapping table and its owner-gated options: `docs/PACKS.md` (reachability section). `languages` omitted ⇒ universal (matches App `sast/rules.ts`: `languages: undefined` = universal).
- **CWE**: every rule/remediation CWE must resolve in `knowledge/cwe/` (consistency-tested). **CWE version pinned: MITRE CWE 4.20** (the version the entries' relationships were read against; recorded 2026-10-17 per the Phase 4 engineering decision — per-entry version metadata remains follow-up work). OWASP and CVSS fields are **absent by design** — no App contract consumes them and the production lock forbids importing scored feeds; `docs/CAPABILITY_COVERAGE.md` records this.
- **Linking**: rule.`patternRefs` ↔ pattern.`linkedRules`; record.`relatedPatterns`/`relatedRules`; remediation keyed `ruleId` — all integrity-checked (0 dangling, 2026-10-16 sweep).
- **Provenance** (advisories): `provenance.{source, sourceUrl, retrievedAt, license}` mandatory for real records (validator-enforced). Original content: `origin: 'original-authored'`.
- **Fixtures**: `fixture: true` + `DROBON-SAMPLE-###` ids; never counted in production metrics; validator rejects fixture-impostors.
- **Redaction**: every secrets rule carries `redact: true` and (unless `matchOnlyEvidence`) a placeholder `denylist` veto.

## 3. Matching / projection guarantee (the runtime seam)

The only App seam is `assess(coordinates) → { providerId, datasetStatus, advisories[] }`
(`apps/api/src/scans/sca/provider.ts`). Guarantees:

1. Every real advisory record survives the App's closed `isScaAdvisory` guards
   on dataset-sourced fields (id/severity/summary/url bounds mirrored in
   `validate.mjs`).
2. Matching key is `(ecosystem, name, version)` — coordinates only; manifest
   content never reaches the provider (`docs/PROVIDER_MAPPING.md` §1).
3. Range semantics: the 6 pinned classes (npm semver subset + PEP 440 subset)
   behave identically in the dataset matcher and the documented provider
   rules; 16 interop vectors pin the behavior executably.
4. Version-less coordinates never match; multi-file advisories collapse to one
   advisory id; identity conflicts are rejected fail-closed.

## 4. Validation behavior (Dataset-side, all executable)

| Gate | Command | Enforces |
|---|---|---|
| Advisory schema/identity | `npm run validate` | closed schema, provenance, fixture isolation |
| Sources ledger | `npm run validate:sources` | source rows valid |
| Corpus targets | `npm run validate:corpus` + `test-consistency` | counts = tree, totals reproduce |
| Pack rules + tests | `npm run validate:packs` | schemas, ReDoS lint, executed pos/neg tests, denylist contract |
| Assets | `npm run validate:assets` | pattern/record schema + link integrity |
| Audiences | `npm run validate:audiences` | lesson quiz/practice; practice files executed against target rules |
| CWE | `npm run validate:cwe` | 61 entries, URL pins |
| Vectors | `npm run test:vectors` | 16/16 matching pins |
| Doc/count drift | `scripts/test-doc-drift.mjs` | docs vs tree counts, ledger claims vs tree |
| Determinism | `scripts/test-determinism.mjs` | regeneration byte-identical; tree digest |
| Integrity | `scripts/manifest.mjs --check` | SHA manifest of 3,995+ files |

## 5. Compatibility status (three levels, honestly)

1. **Established from source/contracts (read-only verified at `c32c797`):**
   `ScaAdvisory`/`DependencyCoordinate` shapes, provider seam, dataset lock
   (`VULN_INTEL_PROVIDER` = `none`), SAST `languages` gating + universal
   convention, report contract sections (`SecurityReport`
   `packages/shared/src/reports.ts:70` — 9 sections, **no executive summary**),
   remediation/finding guidance shapes, lesson/assessment bounds.
2. **Verified by executable tests:** record→advisory projection (16 vectors),
   range semantics, identity/dedup, fixture isolation, determinism, every
   rule/pattern/remediation link. These are Dataset-side tests over the
   mirrored contract — not App runtime tests.
3. **Not verifiable (no App loader / no integration test exists):** actual
   runtime loading of `packs/`, `knowledge/`, `learning/`, `assessments/`,
   `engagements/`; performance at corpus scale; App-side report rendering over
   dataset advisories. Class E — the App workstream must build the loaders and
   their tests (backlog GAP-005..009).

## 6. Backward / forward compatibility & deprecation policy

- Schema ids are versioned (`/v1`); breaking changes require a new schema id
  and a migration note — never a silent field change.
- Rule/pattern/record/remediation ids are permanent; retirements reserve the
  id (never reuse) and are pinned in `data/asset-cells/.manifest.json`
  (`legacy`/retired lists).
- Additive optional fields are allowed within `/v1` only when no existing
  validator's closed-schema check is weakened without a test.
- Deprecations: mark in `docs/PACKS.md` batch log + this contract's changelog;
  keep the file until the App contract no longer references it.

## 7. Minimum supported App contract

`apps/api/src/scans/sca/provider.ts` + `packages/shared/src/sca.ts` +
`apps/api/src/scans/sast/rules.ts` (rule/languages semantics) at `c32c797`.
The App side is authoritative for shapes; this repo mirrors them and pins the
mirror with tests. Any App contract change requires re-running the seam
inventory (`docs/SCOPE.md` method line) and updating this document.

## 8. Explicitly unsupported (do not claim)

- Live secret validation / provider-side revocation checks (shape-only rules).
- Active DAST, crawling, auth, fuzzing (passive observations only).
- CVSS/EPSS/KEV fields, OWASP mappings, exploitability scoring (locked / absent).
- Executive-summary report section (absent from the closed App contract).
- Hyphenated language ids in packs (schema-blocked; BLK-009).
- Runtime loading of any Dataset asset (no App loader; class E).
- Production advisory breadth (0/100,000; GATE-1..4 BLOCKED).

## 9. Changelog

- **1.0 (2026-10-16):** first versioned contract; compiled from the
  finalization pump's source re-verification (`c32c797`), the 16-vector
  interop pins, and the full integrity/determinism gates.
