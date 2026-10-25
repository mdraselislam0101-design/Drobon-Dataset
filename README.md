# Drobon-Dataset

Standalone **vulnerability-intelligence dataset + rule packs + user-type datasets** for [Drobon Aegis](https://github.com/mdraselislam0101-design/Drobon) (the `Drobon` app) — the project's datacenter: every external data need of the main app, versioned, validated, and cross-checked here.

This repository exists because the app enforces an **absolute dataset lock** (data lives here, never in the app repo): no CVE / NVD / GHSA / OSV / KEV / EPSS data may ever enter the app repository — not vendored, not embedded, not synthesized. The app's SCA engine stays fully usable without any dataset (inventory + SBOM) and honestly reports `NOT_ASSESSED` until a real provider matches records from **loaded data**. This repo is where that loaded data lives, versioned and reviewable on its own — alongside versioned, tested **rule packs** (SAST, secrets, DAST patterns-as-data) and **audience datasets** (remediation knowledge, CWE reference, student lessons, assessment and engagement templates) for future app-side loaders.

## Sibling repositories

| Repository | Holds | This repo's relation to it |
|---|---|---|
| [`Drobon`](https://github.com/mdraselislam0101-design/Drobon) | The main app (API, Web, Worker, scanners, rule *logic*) | **Consumer — connection verified 2026-10-21 at App `9360dd1`:** reads `vuln-intel/` through the SCA provider seam (`assess(coordinates)`, filesystem provider) and loads `packs/`, `knowledge/`, `learning/`, `assessments/`, `engagements/` from `DATASET_PATH` at runtime. Nothing is vendored: the App's default is still `VULN_INTEL_PROVIDER=none`, and `scripts/check-boundaries.mjs` keeps dataset bytes out of the App repo. Loader-conformance gaps: `GAP-040`…`GAP-048`, evidence in `docs/APP_CONNECTION_VERIFICATION_2026-10-21.md`. |
| [`Drobon-Database`](https://github.com/mdraselislam0101-design/Drobon-Database) | Future database schemas/migrations | No coupling today. If the dataset is ever served from a database, the schema lives there; the record *format* stays defined here. |

What lives where (by design — proven in `docs/SCOPE.md` by inventorying every app seam):

- **App logic** (engines, hardcoded matchers, SCA parsers, provider seam, lessons, remediation, assistant reasoning, report renderers) → `Drobon` repo only.
- **Vulnerability data + rule packs + audience datasets** → this repo only.
- **Database schemas** → `Drobon-Database` repo only.
- **Exploit payloads / active-attack tooling** → nowhere, ever.

## Data

- **Production-data lock in force**: catalog expansion (GHSA/OSV/CVE/KEV/EPSS/…) is blocked until the authorized production stage — see `docs/INGESTION_PLAN.md`. The seed below is preserved as-is and assessed read-only.
- **100 reviewed GHSA seed records** (50 npm + 50 pypi), imported 2026-10-14 via `scripts/import-ghsa.mjs` — reviewed advisories only, withdrawn excluded, every record with source URL + retrieval time. Counting vocabulary (enforced by `docs/COUNTING_POLICY.md`): these 100 **files** collapse to **78 unique GHSA advisory ids** and **84 unique advisory-package items** (identity = `(source, id, ecosystem, package)`); split `--N` shards share one identity and are never counted as separate items.
- **3 synthetic fixtures** (`*/samples/`, `DROBON-SAMPLE-###`) proving format/validator behavior; they assert nothing about the real world.
- **2146 pack rules** (1000 SAST + 97 secrets + 1007 DAST + 42 SCA), all original Drobon content with executable example tests — no proprietary rule was copied from any commercial tool, ever.
- **2146 remediation entries** — one per pack rule, enforced by consistency tests (no finding without guidance).
- **100 CWE knowledge entries** in our own words (60 earlier entries, plus CWE-117 added as a pack CWE in the log-forging batch, plus CWE-338 and CWE-843 added with their pack rules on 2026-10-19, plus CWE-116 for the UTF-7 charset rule on 2026-10-20, plus nine entries added with the 1,000-rule SAST batch and CWE-650 with the WebDAV rule on 2026-10-23, plus CWE-538, CWE-549, CWE-640, CWE-472, CWE-20, CWE-345, CWE-353, CWE-770, CWE-840, CWE-93, CWE-704, CWE-1236, CWE-201, CWE-269, CWE-307, CWE-384 and CWE-530 added with their body rules on 2026-10-25; the App-referenced split is re-derived: 16 distinct `DG-*` ids, 16/16 resolve — `docs/CAPABILITY_COVERAGE_MATRIX.json`), each linking its canonical MITRE page; every CWE reference in packs/remediation resolves here (enforced; see REQ-CWE-01 in `docs/REQUIREMENTS_MATRIX.json`).
- **11 audience starters**: 6 executable lessons (Student contract; 2 are developer-focused `lsn_dev_*`), 3 assessment templates (Security Professional), 2 passive-only engagement templates (Pentester).
- **OSV importer** (`scripts/import-osv.mjs`) for open aggregated data (mapping covered by fixture tests; live import needs network to api.osv.dev).
- **Verified App connection (2026-10-21):** at App `9360dd1` all nine dataset categories load from `DATASET_PATH` (100 files / 950 / 97 / 398 / 2104 / 69 / 6 / 3 / 2 — every count reproduced from this tree) and SCA matching returns real advisories (`fast-jwt@6.2.4` → 6). The same audit found nine defects, including 160 of 950 SAST rules unreachable through the App language catalog, 15 of 1,846 DAST declared tests disagreeing with the App evaluator profile, 73 of 398 DAST rules unreachable because the App forwards only 11 response headers (`interop/app-dast-reachability.json`), and 2104 remediation entries loaded but never surfaced. See `docs/APP_CONNECTION_VERIFICATION_2026-10-21.md`.
- **Computed completion ledger (2026-10-21):** `docs/DATASET_COMPLETION_LEDGER.md` answers "is it done?" without a composite percentage — 21 dimensions, each either COMPLETE with a verification command that exists, or PARTIAL/BLOCKED with a named owner and an executable next action. 7 complete · 5 partial · 1 policy-bound · 3 owner-blocked · 5 App-blocked. Regenerate: `npm run completion`; `npm test` fails when it stops reproducing.
- Coverage is a **growing seed, never a completeness claim**: an empty result means "not in this dataset", never "not vulnerable" (HONESTY.md rule 5).

## Layout

```
Drobon-Dataset/
├── README.md                  # This file
├── docs/
│   ├── FORMAT.md              # Advisory record spec (v1): fields, bounds, version ranges
│   ├── HONESTY.md             # No-fabrication rules every record must satisfy
│   ├── PROVIDER_MAPPING.md    # How a future provider maps records → ScaAdvisory
│   ├── PACKS.md               # Rule-pack formats, engine contract, loader checklist
│   ├── AUDIENCES.md           # Audience datasets (remediation/lessons/templates/engagements)
│   ├── SCOPE.md               # Seam inventory: what lives here, and why
│   ├── APP_CONNECTION_VERIFICATION_2026-10-21.md # Verified App↔Dataset connection (probes + defects)
│   ├── APP_LANGUAGE_ID_MAPPING.md # Generated: pack language ids vs the App catalog
│   ├── DATASET_COMPLETION_LEDGER.md # Generated: 20-dimension completion ledger (no composite %)
│   ├── REQUIREMENTS_MATRIX.json # Machine-readable capability → asset traceability (validated)
│   ├── LICENSE_DECISION_RECORD.md # License status: no grant; owner decision pending
│   └── INGESTION_PLAN.md      # Blocked-until-authorized production ingestion plan
├── schema/
│   └── advisory.schema.json   # JSON Schema for advisory records (editors/tooling)
├── vuln-intel/
│   ├── README.md              # Data directory policy
│   ├── sources.json           # Source registry (terms pointers, review status)
│   ├── npm/ + pypi/           # Real records, one file per advisory-package
│   └── npm/samples/ + pypi/samples/  # Labeled synthetic fixtures
├── packs/
│   ├── sast/v1/ + secrets/v1/ + dast/v1/  # pack.json + rules/*.json (one rule per file)
├── knowledge/
│   ├── remediation/           # Remediation entries, one file per rule id
│   ├── patterns/              # Generated detection patterns (DPK-PAT-*); examples are executed
│   ├── records/               # Generated concept records (DPK-REC-*)
│   └── cwe/                   # CWE reference entries, one file per CWE id
├── learning/lessons/          # Student lessons, one file per lsn_* id
├── assessments/templates/     # Assessment templates, one file per tmpl_* id
├── engagements/               # Engagement templates, one file per eng_* id (passive-only)
├── interop/
│   ├── provider-vectors.json  # Pinned coordinate → advisory-id expectations
│   ├── APP_CONFORMANCE.md     # Generated: declared-test parity vs the App, divergence register
│   └── app-conformance.json   # Generated: the same, machine-readable (the App's defect list)
├── data/
│   ├── app-language-catalog.json # Pinned App SAST language catalog (reachability gate)
│   ├── asset-cells/           # Hand-designed generator cell data + .manifest.json (stable ID ledger)
│   └── osv-seed-packages.json # Curated package list for the OSV importer
├── scripts/
│   ├── validate.mjs           # Zero-dependency advisory validator (executable spec)
│   ├── validate-packs.mjs     # Zero-dependency pack validator (executes rule tests)
│   ├── validate-audiences.mjs # Zero-dependency audience validator (executes lessons)
│   ├── validate-cwe.mjs       # Zero-dependency CWE validator (checks MITRE links)
│   ├── validate-matrix.mjs    # Zero-dependency requirements-matrix validator (recomputes counts)
│   ├── validate-app-language-ids.mjs # Pack language ids vs the App catalog (reachability gate)
│   ├── gen-app-conformance.mjs # Declared-test parity vs the App evaluator (conformance gate)
│   ├── completion-ledger.mjs  # Computes docs/DATASET_COMPLETION_LEDGER.* from the tree
│   ├── range.mjs              # semver / PEP 440 range syntax + evaluation
│   ├── import-ghsa.mjs        # Reviewed-GHSA importer (paginated, retrying, validates before writing)
│   ├── import-osv.mjs         # OSV importer (fixture-tested mapping)
│   ├── generate-assets.mjs    # Deterministic cell compiler (cells → rules/patterns/records/remediation)
│   ├── check-vectors.mjs      # Provider interop checker
│   ├── test.mjs               # Test runner part 1 (advisories + ranges + layout + vectors)
│   ├── test-packs.mjs         # Test runner part 2 (packs + negatives + OSV mapping)
│   ├── test-audiences.mjs     # Test runner part 3 (audiences + negatives)
│   ├── test-consistency.mjs   # Test runner part 4 (cross-dataset integrity + coverage)
│   ├── test-assets.mjs        # Test runner part 5 (pattern/record executability + linkage)
│   ├── test-rehearsal.mjs     # Test runner part 6 (1K/10K synthetic ingestion rehearsal, tmp only)
│   └── test-doc-drift.mjs     # Documentation-count drift gate (docs vs recomputed files)
├── test/
│   ├── invalid/               # Advisory fixtures the validator MUST reject
│   ├── invalid-packs/         # Pack fixtures the pack validator MUST reject
│   ├── invalid-audiences/     # Audience fixtures the audience validator MUST reject
│   ├── invalid-cwe/           # CWE fixtures the CWE validator MUST reject
│   ├── invalid-matrix/        # Matrix fixtures the matrix validator MUST reject
│   ├── invalid-sources/       # Source fixtures the source validator MUST reject
│   └── fixtures/              # OSV mapping fixtures (synthetic API-shaped input)
└── .github/workflows/ci.yml   # CI: npm test + all validators + vectors
```

Counts stated in this README and in `docs/CORPUS_GAP_REPORT.md`, `docs/CAPABILITY_COVERAGE.md`, `docs/REQUIREMENTS_MATRIX.json`, and `docs/CORPUS_TARGETS.json` are recomputed from files and enforced by `npm run test:drift` (`scripts/test-doc-drift.mjs`) — a stale count fails CI.

## Honesty rules (short version)

Full rules: `docs/HONESTY.md` (advisories), `docs/PACKS.md` (packs), `docs/AUDIENCES.md` (audiences). Non-negotiable summary:

1. **Verified records only** — every non-fixture record traces to a real published source (GHSA/OSV/…) with URL + retrieval time. No invented CVE/GHSA IDs, no guessed severities (OSV severity comes from CVSS via the standard mapping), no risk scores.
2. **Fixtures are labeled** — synthetic advisory samples carry `"fixture": true` and `DROBON-SAMPLE-###` ids. Packs/audiences have no samples at all: every entry is genuine and tested.
3. **Closed, bounded, executed shapes** — advisories mirror the app's `ScaAdvisory` contract; pack patterns must compile, pass ReDoS lint, and reproduce every declared example test; lessons targeting pack rules must demonstrably work.
4. **Cross-dataset integrity (enforced)** — every pack rule has a remediation entry, every CWE reference resolves to `knowledge/cwe/`, every lesson target resolves to a pack rule. Dangling references fail the suite.
5. **`NOT_ASSESSED` stays honest** — missing data is reported as missing, never as "clean".
6. **Original content only** — every pattern, lesson, template, and guidance entry is written from public knowledge. Proprietary rules, courses, and methodologies are never copied, adapted, or paraphrased.
7. **Audience boundaries** — templates never pre-declare authorization; engagement content is authorized + passive only (banned-phrase lint + human review); learner code is never executed.

## Commands

Prerequisites: Node.js 22 (see `.nvmrc`), no `npm install` needed — zero dependencies.

```bash
npm test                    # full suite: advisories + packs + audiences + consistency + rehearsal
npm run validate            # validate every record under vuln-intel/
npm run validate:packs      # validate every pack manifest + rule under packs/
npm run validate:audiences  # validate knowledge/ + learning/ + assessments/ + engagements/
npm run validate:cwe        # validate every entry under knowledge/cwe/
npm run validate:matrix     # validate the requirements traceability matrix (recomputes counts)
npm run validate:sources    # validate the source registry
npm run validate:corpus     # validate the corpus targets + source roadmap + owner decisions
npm run manifest -- --scope records   # SHA-256 integrity manifest over a corpus scope
npm run dedup-report        # group advisory files into corpus items by identity key
npm run test:rehearsal      # synthetic 1K + 10K ingestion rehearsal (tmp only, never production)
npm run test:vectors        # provider interop vectors only
npm run import:ghsa -- --limit 15   # BLOCKED by the production-data lock (see docs/INGESTION_PLAN.md)
npm run import:osv -- --limit 20    # BLOCKED by the production-data lock (see docs/INGESTION_PLAN.md)
```

## Contributing records, rules & content

1. Read the spec first: `docs/FORMAT.md` + `docs/HONESTY.md` (advisories), `docs/PACKS.md` (packs), `docs/AUDIENCES.md` (audiences).
2. Catalog growth is BLOCKED by the production-data lock until the authorized stage (importers and hand-written real records alike — see `docs/INGESTION_PLAN.md`). Original pack/audience/CWE content and labeled fixtures remain welcome; any record needs full `provenance` and one file per advisory-package (see `vuln-intel/README.md`).
3. Pack rules must be **original**, tested (≥1 positive + ≥1 negative example), severity-conservative, with a mandatory `limitation` section — **and** ship with a remediation entry plus resolvable CWE (consistency tests enforce both).
4. Audience content must be **original**; lessons must execute against their target rules; templates use exact hostnames and never declare authorization; engagements stay passive-only.
5. If a new record changes any vector outcome, update `interop/provider-vectors.json` in the same commit with a note.
6. Run `npm test` before committing — CI enforces it on every push. Pushes, PRs, releases, and deployments need explicit authorization.

## License

TODO: maintainers must choose data licensing explicitly (upstream sources such as NVD/GHSA/OSV each carry their own terms; per-record terms go in `provenance.license`). No license is granted by this file's presence.
