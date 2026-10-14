# Drobon-Dataset

Standalone **vulnerability-intelligence dataset + rule packs** for [Drobon Aegis](https://github.com/mdraselislam0101-design/Drobon) (the `Drobon` app).

This repository exists because the app enforces an **absolute dataset lock**: no CVE / NVD / GHSA / OSV / KEV / EPSS data may ever enter the app repository — not vendored, not embedded, not synthesized. The app's SCA engine stays fully usable without any dataset (inventory + SBOM) and honestly reports `NOT_ASSESSED` until a real provider matches records from **loaded data**. This repo is where that loaded data lives, versioned and reviewable on its own — alongside versioned, tested **rule packs** (SAST, secrets, DAST patterns-as-data) for a future app-side pack loader.

## Sibling repositories

| Repository | Holds | This repo's relation to it |
|---|---|---|
| [`Drobon`](https://github.com/mdraselislam0101-design/Drobon) | The main app (API, Web, Worker, scanners, rule *logic*) | Consumer: reads vuln-intel only through the SCA provider seam (`assess(coordinates)`), server-side. See `docs/PROVIDER_MAPPING.md`. Pack loader is future app work — see `docs/PACKS.md`. |
| [`Drobon-Database`](https://github.com/mdraselislam0101-design/Drobon-Database) | Future database schemas/migrations | No coupling today. If the dataset is ever served from a database, the schema lives there; the record *format* stays defined here. |

What lives where (by design — proven in `docs/SCOPE.md` by inventorying every app seam):

- **App logic** (engines, hardcoded matchers, SCA parsers, provider seam, lessons, remediation) → `Drobon` repo only.
- **Vulnerability data + rule packs** (advisories; SAST/secrets/DAST patterns-as-data) → this repo only.
- **Database schemas** → `Drobon-Database` repo only.

## Data

- **30 reviewed GHSA seed records** (15 npm + 15 pypi), imported 2026-10-14 via `scripts/import-ghsa.mjs` — reviewed advisories only, withdrawn excluded, every record with source URL + retrieval time.
- **3 synthetic fixtures** (`*/samples/`, `DROBON-SAMPLE-###`) proving format/validator behavior; they assert nothing about the real world.
- **12 starter pack rules** (4 SAST + 4 secrets + 4 DAST), all original Drobon content with executable example tests — no proprietary rule was copied from any commercial tool, ever.
- **OSV importer** (`scripts/import-osv.mjs`) for open aggregated data (mapping covered by fixture tests; live import needs network to api.osv.dev).
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
│   └── SCOPE.md               # Seam inventory: why ONLY vuln-intel + packs live here
├── schema/
│   └── advisory.schema.json   # JSON Schema for advisory records (editors/tooling)
├── vuln-intel/
│   ├── README.md              # Data directory policy
│   ├── npm/ + pypi/           # Real records, one file per advisory-package
│   └── npm/samples/ + pypi/samples/  # Labeled synthetic fixtures
├── packs/
│   ├── sast/v1/ + secrets/v1/ + dast/v1/  # pack.json + rules/*.json (one rule per file)
├── interop/
│   └── provider-vectors.json  # Pinned coordinate → advisory-id expectations
├── data/
│   └── osv-seed-packages.json # Curated package list for the OSV importer
├── scripts/
│   ├── validate.mjs           # Zero-dependency advisory validator (executable spec)
│   ├── validate-packs.mjs     # Zero-dependency pack validator (executes rule tests)
│   ├── range.mjs              # semver / PEP 440 range syntax + evaluation
│   ├── import-ghsa.mjs        # Reviewed-GHSA importer (validates before writing)
│   ├── import-osv.mjs         # OSV importer (fixture-tested mapping)
│   ├── check-vectors.mjs      # Provider interop checker
│   ├── test.mjs               # Test runner part 1 (advisories + ranges + layout + vectors)
│   └── test-packs.mjs         # Test runner part 2 (packs + negatives + OSV mapping)
├── test/
│   ├── invalid/               # Advisory fixtures the validator MUST reject
│   ├── invalid-packs/         # Pack fixtures the pack validator MUST reject
│   └── fixtures/              # OSV mapping fixtures (synthetic API-shaped input)
└── .github/workflows/ci.yml   # CI: npm test + validate + vectors
```

## Honesty rules (short version)

Full rules: `docs/HONESTY.md` (advisories), `docs/PACKS.md` (packs). Non-negotiable summary:

1. **Verified records only** — every non-fixture record traces to a real published source (GHSA/OSV/…) with URL + retrieval time. No invented CVE/GHSA IDs, no guessed severities (OSV severity comes from CVSS via the standard mapping), no risk scores.
2. **Fixtures are labeled** — synthetic advisory samples carry `"fixture": true` and `DROBON-SAMPLE-###` ids. Packs have no samples at all: every pack rule is genuine and tested.
3. **Closed, bounded, executed shapes** — advisories mirror the app's `ScaAdvisory` contract; pack patterns must compile, pass ReDoS lint, and reproduce every declared example test.
4. **`NOT_ASSESSED` stays honest** — missing data is reported as missing, never as "clean".
5. **Original pack content only** — every pattern, title, and test is written from public knowledge. Proprietary rules are never copied, adapted, or paraphrased.

## Commands

Prerequisites: Node.js 22 (see `.nvmrc`), no `npm install` needed — zero dependencies.

```bash
npm test              # full suite: advisories + packs + negatives + OSV mapping + vectors
npm run validate      # validate every record under vuln-intel/
npm run validate:packs  # validate every pack manifest + rule under packs/
npm run test:vectors  # provider interop vectors only
npm run import:ghsa -- --limit 15   # import reviewed advisories (GITHUB_TOKEN recommended)
npm run import:osv -- --limit 20    # import OSV records (needs network to api.osv.dev)
```

## Contributing records & rules

1. Read `docs/FORMAT.md` + `docs/HONESTY.md` (advisories) or `docs/PACKS.md` (packs) first.
2. Prefer the importers for advisory growth; hand-written records need full `provenance` and one file per advisory-package (see `vuln-intel/README.md`).
3. Pack rules must be **original**, tested (≥1 positive + ≥1 negative example), severity-conservative, with a mandatory `limitation` section.
4. If a new record changes any vector outcome, update `interop/provider-vectors.json` in the same commit with a note.
5. Run `npm test` before pushing — CI enforces it.

## License

TODO: maintainers must choose data licensing explicitly (upstream sources such as NVD/GHSA/OSV each carry their own terms; per-record terms go in `provenance.license`). No license is granted by this file's presence.
