# Drobon-Dataset

Standalone **vulnerability-intelligence dataset** for [Drobon Aegis](https://github.com/mdraselislam0101-design/Drobon) (the `Drobon` app).

This repository exists because the app enforces an **absolute dataset lock**: no CVE / NVD / GHSA / OSV / KEV / EPSS data may ever enter the app repository — not vendored, not embedded, not synthesized. The app's SCA engine stays fully usable without any dataset (inventory + SBOM) and honestly reports `NOT_ASSESSED` until a real provider matches records from **loaded data**. This repo is where that loaded data lives, versioned and reviewable on its own.

## Sibling repositories

| Repository | Holds | This repo's relation to it |
|---|---|---|
| [`Drobon`](https://github.com/mdraselislam0101-design/Drobon) | The main app (API, Web, Worker, scanners, rule *logic*) | Consumer: reads this data only through the SCA provider seam (`assess(coordinates)`), server-side. See `docs/PROVIDER_MAPPING.md`. |
| [`Drobon-Database`](https://github.com/mdraselislam0101-design/Drobon-Database) | Future database schemas/migrations | No coupling today. If the dataset is ever served from a database, the schema lives there; the record *format* stays defined here. |

What lives where (by design):

- **App logic** (SAST/Secrets/DAST matchers, SCA parsers, provider seam) → `Drobon` repo only.
- **Vulnerability data** (advisories mapped to ecosystem + package + versions) → this repo only.
- **Database schemas** → `Drobon-Database` repo only.

## Layout

```
Drobon-Dataset/
├── README.md            # This file
├── docs/
│   ├── FORMAT.md        # Record format spec (v1): fields, bounds, version ranges
│   ├── HONESTY.md       # No-fabrication rules every record must satisfy
│   └── PROVIDER_MAPPING.md  # How a future provider maps records → ScaAdvisory
├── schema/
│   └── advisory.schema.json  # JSON Schema for advisory records (editors/tooling)
├── vuln-intel/
│   ├── README.md        # Data directory policy
│   ├── npm/samples/     # Clearly-labeled synthetic fixtures (NOT real vulns)
│   └── pypi/samples/    # Clearly-labeled synthetic fixtures (NOT real vulns)
├── scripts/
│   ├── validate.mjs     # Zero-dependency validator (the executable spec)
│   └── test.mjs         # Positive + negative test runner
└── test/
    └── invalid/         # Fixtures the validator MUST reject
```

## Honesty rules (short version)

Full rules: `docs/HONESTY.md`. Non-negotiable summary:

1. **Verified records only** — every non-fixture record traces to a real published source (GHSA/OSV/NVD/…) with URL + retrieval time. No invented CVE/GHSA IDs, no guessed severities, no risk scores.
2. **Fixtures are labeled** — synthetic samples carry `"fixture": true` and `DROBON-SAMPLE-###` ids, and must never look like real advisories.
3. **Closed, bounded shapes** — every bound mirrors the app's `ScaAdvisory` contract exactly (id ≤ 100, summary ≤ 400, url ≤ 400, name ≤ 214, no control characters, no unknown fields).
4. **`NOT_ASSESSED` stays honest** — missing data is reported as missing, never as "clean".

## Commands

Prerequisites: Node.js 22 (see `.nvmrc`), no `npm install` needed — zero dependencies.

```bash
npm test        # validate samples + assert invalid fixtures are rejected
npm run validate  # validate every record under vuln-intel/
```

## Contributing records

1. Read `docs/FORMAT.md` and `docs/HONESTY.md` first.
2. Add one JSON file per advisory (see `vuln-intel/README.md` for placement).
3. Every real record needs `provenance.source`, `provenance.sourceUrl` (https) and `provenance.retrievedAt` — the validator rejects records without them.
4. Run `npm test` before pushing.

## License

TODO: maintainers must choose data licensing explicitly (upstream sources such as NVD/GHSA/OSV each carry their own terms; per-record terms go in `provenance.license`). No license is granted by this file's presence.
