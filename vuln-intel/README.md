# vuln-intel/ — data directory policy

One advisory record per JSON file. Every file must validate (`npm run validate`).

## Placement

```
vuln-intel/
├── npm/
│   ├── samples/                 # fixtures only ("fixture": true, DROBON-SAMPLE-###)
│   └── <ADVISORY-ID>.json       # real npm records
└── pypi/
    ├── samples/                 # fixtures only
    └── <ADVISORY-ID>.json       # real pypi records
```

- Real records: `vuln-intel/<ecosystem>/<ID>.json` where `<ID>` is the record's `id`. One advisory affecting several packages expands to one record per package: `<ID>.json`, `<ID>--2.json`, … (enforced by the layout tests).
- Ids must be filename-safe: bounded text without control characters; reviewers must reject ids containing path separators (`/`, `\0`).
- Fixtures: `vuln-intel/<ecosystem>/samples/<ID>.json` only. A fixture anywhere else fails review; a non-fixture under `samples/` fails the layout tests.
- New ecosystems require an app-side parser first (`SCA_ECOSYSTEMS` in the Drobon repo) — never add an ecosystem directory the app cannot produce coordinates for.

## Current state

- **50 real records** (25 npm + 25 pypi): GitHub-reviewed advisories, withdrawn excluded, imported 2026-10-14 via `scripts/import-ghsa.mjs` with full provenance. Regrow/extend with `npm run import:ghsa -- --limit N` (existing files are skipped unless `--force`).
- **3 fixtures** (`DROBON-SAMPLE-001…003`) proving format/validator behavior end to end.

## Vector maintenance

`interop/provider-vectors.json` pins coordinate → advisory-id expectations, including "matches nothing" vectors. Adding records can change outcomes (a new record may match a previously-absent package). Rule: **run `npm test` after any data change** — if a vector fails because the data legitimately grew, update the vector (ids + note) in the same commit. Never "fix" a vector failure by weakening the expectation without a data reason.

## Known TODOs (tracked, not silently assumed)

1. ~~**Range-parse validation**~~ — DONE: enforced by `scripts/range.mjs` via the validator (semver / PEP 440 subset, see `docs/FORMAT.md`).
2. ~~**Directory lint**~~ — DONE: enforced by the layout tests inside `npm test`.
3. **Coverage growth.** The 30-record seed is a starting point. Grow with the importer in reviewed batches; each import commit must keep `npm test` green (fix or skip-and-log, never force-fit).
4. **Sharding.** If real data grows past a few hundred files per ecosystem, shard by package-name prefix (e.g. `npm/lo/lodash/GHSA-….json`) and document it here. Do not shard prematurely.
