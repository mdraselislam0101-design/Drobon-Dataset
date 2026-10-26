# DATASET_APP_CONTRACT.md — versioned Dataset ↔ Main App compatibility contract

Contract version: **DATASET-APP/1.3** (2026-10-25). App reference: Drobon
`main` @ `9360dd1abdf940cc1bffd942aab0702703aaaaef` (read-only, re-verified
2026-10-21). Dataset reference: `main` @ `a3f2475` (PR #7 merge; packs SAST
1,000 · secrets 1,000 · DAST 1,007 · SCA 1,000). This document states what the
Dataset guarantees, what the App expects, and — explicitly — what is **not**
yet verifiable. The App does ship a loader for SAST/secrets/DAST (2 of the 6
checklist steps implemented); it has **no SCA loader**, so the SCA pack below is
declared but unreachable, and validating JSON against a schema is still not
integration.

## 1. Dataset schema / version inventory

| Asset type | Schema id | Location | Id convention |
|---|---|---|---|
| SAST rule pack | `drobon.pack.sast/v1` | `packs/sast/v1/rules/DPK-SAST-###.json` | stable, never reused (26 retired reservations pinned) |
| Secrets rule pack | `drobon.pack.secrets/v1` | `packs/secrets/v1/rules/DPK-SEC-###.json` | same |
| DAST rule pack | `drobon.pack.dast/v1` | `packs/dast/v1/rules/DPK-DAST-###.json` | same |
| SCA declaration pack | `drobon.pack.sca/v1` | `packs/sca/v1/rules/DPK-SCA-####.json` | same; **no App loader at `9360dd1`** (dataset-side only) |
| Pattern | `drobon.knowledge.pattern/v1` | `knowledge/patterns/DPK-PAT-####.json` | 1:1 with rules (4,007) |
| Record | `drobon.knowledge.record/v1` | `knowledge/records/DPK-REC-####.json` | 4,007 (1:1 with patterns; the 40 legacy record-less patterns were resolved by the generator 2026-10-19, D-13 never activated) |
| Remediation | `drobon.knowledge.remediation/v1` | `knowledge/remediation/DPK-*.json` | 1:1 with rules (4,007), keyed by `ruleId` |
| Advisory record | `drobon.vuln-intel/v1` | `vuln-intel/{npm,pypi}/*.json` | identity `(provenance.source, id, ecosystem, package)`; files≠advisories≠items |
| CWE knowledge | `drobon.knowledge.cwe/v1` | `knowledge/cwe/*.json` | MITRE id, own-words summary + pinned URL |
| Lesson / template / engagement | `drobon.learning.lesson/v1` etc. | `learning/lessons/`, `assessments/templates/`, `engagements/` | `lsn_*` / template ids |
| Provider vectors | `drobon.vuln-intel/vectors/v1` | `interop/provider-vectors.json` | `VEC-###`, real records only |
| Manifest / integrity | SHA-256 manifest | `data/asset-cells/.manifest.json` + `manifest.mjs` | deterministic generation (tree digest pinned per release) |

## 2. Field and convention guarantees

- **Severity** enum: `CRITICAL|HIGH|MEDIUM|LOW|INFO` (advisory) / `HIGH|MEDIUM|LOW` (rules) — rule severity is rule-fixed, never client-influenced.
- **Category** enums per pack (secrets: `service-token`, `service-credential`, `cloud-credential`, `generic-credential`, `private-key`, `hardcoded-credential`).
- **Language tags** (`packs`/`knowledge`): `^[a-z][a-z0-9]{0,31}$` — **hyphenated app catalog ids are inexpressible** (`github-actions`, `shell-posix`, `android-manifest`). Mapping table and its owner-gated options: `docs/PACKS.md` (reachability section). `languages` omitted ⇒ universal (matches App `sast/rules.ts`: `languages: undefined` = universal).
- **CWE**: every rule/remediation CWE must resolve in `knowledge/cwe/` (consistency-tested). **CWE version pinned: MITRE CWE 4.20** (the version the entries' relationships were read against; recorded 2026-10-17 per the Phase 4 engineering decision). Per-entry `cweVersion: "4.20"` metadata is present on all 61 `knowledge/cwe/` entries and enforced by `validate-cwe.mjs` (Phase 5, 2026-10-17) against the repo-pinned value only — this is a repo-local consistency check; no external catalog is fetched and nothing is externally verified. OWASP and CVSS fields are **absent by design** — no App contract consumes them and the production lock forbids importing scored feeds; `docs/CAPABILITY_COVERAGE.md` records this.
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
| CWE | `npm run validate:cwe` | 102 entries, URL pins, version pin |
| Vectors | `npm run test:vectors` | 16/16 matching pins |
| Independent eval coverage | `npm run eval:coverage` | every pack family measured: 4,007/4,007 rules exercised; an unmeasured pack directory fails the gate |
| Doc/count drift | `scripts/test-doc-drift.mjs` | docs vs tree counts, ledger claims vs tree |
| Determinism | `scripts/test-determinism.mjs` | regeneration byte-identical; tree digest |
| Integrity | `scripts/manifest.mjs --check` | SHA manifest of 3,995+ files |

## 5. Compatibility status (three levels, honestly) — re-verified at App `9360dd1` (2026-10-21)

1. **Established from source/contracts (read-only verified at `9360dd1`):**
   `ScaAdvisory`/`DependencyCoordinate` shapes, provider seam, dataset lock
   (`VULN_INTEL_PROVIDER` = `none`), SAST `languages` gating + universal
   convention, report contract sections (`SecurityReport`
   `packages/shared/src/reports.ts:70` — 9 sections, **no executive summary**),
   remediation/finding guidance shapes, lesson/assessment bounds.
2. **Verified by executable tests:** record→advisory projection (16 vectors),
   range semantics, identity/dedup, fixture isolation, determinism, every
   rule/pattern/remediation link. These are Dataset-side tests over the
   mirrored contract.
3. **Verified by executable probes against the App (2026-10-21, App `9360dd1`):**
   runtime loading of all nine categories from `DATASET_PATH`; SCA matching
   (`fast-jwt@6.2.4` → 6 advisories, `msgpack5@6.0.0` → 7, 13-file shard package
   deduplicated, `lodash@4.17.21` → 0); SAST/Secrets/DAST converter parity over
   every declared pack test (3,843 / 441 / 1,292 executed — 0 / 0 / 15
   mismatches). Commands and results: `docs/APP_CONNECTION_VERIFICATION_2026-10-21.md`.
4. **Still not verified:** App performance at corpus scale, browser/E2E runs, and
   App report rendering over dataset advisories. The App's own suites do not mount
   `DATASET_PATH`, and at `9360dd1` they do not pass (api 785/801, shared
   182/183) — `GAP-047`.

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
`apps/api/src/scans/sast/rules.ts` (rule/languages semantics) +
`apps/api/src/external/*` (loader) + `apps/api/src/scans/sca/filesystemProvider.ts`
at `9360dd1abdf940cc1bffd942aab0702703aaaaef` (2026-10-20).
The pinned App language catalog for reachability is `data/app-language-catalog.json`
(re-verify with `node scripts/validate-app-language-ids.mjs`).
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

## 9. Provider design acceptance requirements (GATE-4 preparation — 2026-10-17)

Status: `PREPARED — NOT ACCEPTED`. These are the requirements a future
App-side provider design must satisfy for GATE-4 evidence. Only the App owner/
design authority can accept a design; this section invents none and unlocks
nothing. The Null provider (`VULN_INTEL_PROVIDER=none`) stays locked until a
design is accepted **in the App repository** and cited in
`docs/INGESTION_GATES.json` GATE-4 `statusEvidence`.

| # | Requirement | Acceptance criteria (evidence the App design must show) |
|---|---|---|
| P1 | Dataset version + schema compatibility | Design pins the supported `DATASET-APP/x.y` contract version and schema ids from §1; rejects unknown/unsupported versions fail-closed |
| P2 | External storage + independent delivery | Dataset ships outside the App source/build (release artifact or server-side store); delivery path documented; **no Dataset asset is embedded, vendored, or bundled into Main App code or builds** |
| P3 | Integrity verification + provenance | Loader verifies the SHA-256 manifest (`scripts/manifest.mjs`) before use; per-record provenance passes through to the consumer; unverifiable artifacts are refused |
| P4 | Explicit enablement + fail-closed startup | Loading is opt-in behind explicit configuration; startup without a valid Dataset **degrades to the documented empty/no-op provider behavior** — never half-loaded, never crash-open |
| P5 | Missing / invalid / stale / unauthorized Dataset | Each state has a defined, tested behavior (refuse load + logged reason); stale rights/reviews (INGESTION_PROTOCOL §13) are treated as unauthorized; zero-match semantics documented per §3 |
| P6 | Update / revocation / rollback | Version update procedure, revocation handling (quarantine/refuse), and rollback to a prior verified version are documented and rehearsed; rollback restores byte-identical prior behavior |
| P7 | Contract tests | Executable tests pin: record→advisory projection (the 16 interop vectors), range semantics, identity/dedup, fixture isolation, P1–P6 states; CI runs them on every App change touching the seam |
| P8 | No automatic production loading | Even with a valid Dataset, production-data loading requires separate authorization (`requireGates()` semantics mirrored App-side); a production count of 0 must remain visibly 0 |
| P9 | Config-lock amendment | The design states the exact App config-lock change it needs (current lock: `VULN_INTEL_PROVIDER=none`); the change is made only in the App repo by App maintainers |

GATE-4 acceptance evidence = the App-repo design document + maintainer
acceptance record + the P1–P9 test transcripts. Until all three exist, GATE-4
remains `BLOCKED` ("No provider design exists; Null provider still locked").

## 10. Changelog

- **1.2 (2026-10-20):** section 1 inventory refreshed to the audited tree
  4,007 rules / 4,007 patterns / 4,007 records / 4,007 remediation; the 40
  legacy record-less patterns were resolved by the generator, not by filler).
  No schema id, field guarantee or compatibility statement changed, so 1.1
  documents remain valid: this is a count refresh, not a breaking revision.
- **1.1 (2026-10-17):** section 9 added (GATE-4 provider design acceptance
  requirements, prepared only); pattern/record/remediation counts refreshed to
  the Phase 9+ tree (954/914/954).
- **1.0 (2026-10-16):** first versioned contract; compiled from the
  finalization pump's source re-verification (`c32c797`), the 16-vector
  interop pins, and the full integrity/determinism gates.

## 9. Runtime mapping the App and this repo must agree on (2026-10-21)

Two fields look alike and are not: the provider's `datasetStatus`
(`NO_DATA_LOADED | DATASET_UNAVAILABLE | DATASET_AVAILABLE`) and the scan-level
`state` (`ASSESSED | NOT_ASSESSED`). They are produced by different layers, so an
integration test must not assume they move together.

| Case | Provider `datasetStatus` | Advisories | App scan state | Honest sentence |
|---|---|---|---|---|
| provider `none` | `NO_DATA_LOADED` | 0 | `NOT_ASSESSED` | no data was consulted |
| path wrong / unreadable | `DATASET_UNAVAILABLE` | 0 | `NOT_ASSESSED` | data was not reachable at scan time |
| data loaded, coordinate absent from corpus | `DATASET_AVAILABLE` | 0 | `NOT_ASSESSED` | not in this corpus — **not** "clean" |
| data loaded, package present, version outside every range | `DATASET_AVAILABLE` | 0 | `NOT_ASSESSED` | no known advisory applies **to this dataset version** |
| data loaded, range matches | `DATASET_AVAILABLE` | ≥1 | `ASSESSED` | verified match, with per-record provenance |

The dataset-side simulator (`scripts/sca-engine.mjs`) reports `ASSESSED` for the
third and fourth rows (it answered against loaded data); the App deliberately
collapses both to `NOT_ASSESSED` because an 84-item seed cannot support a "clean"
statement. **This is a documented mapping choice, not a divergence in matching:**
the advisory sets are identical (16/16 vectors). Keeping the mapping table here is
what prevents the two contracts from drifting (`GAP-043`).

Counting on the status surface is a separate, open item: the App reports the raw
advisory **file** count (100) where this repo counts **84 identity items / 78 ids**
(`docs/COUNTING_POLICY.md`). Counts shown to customers must use the canonical
numbers.
