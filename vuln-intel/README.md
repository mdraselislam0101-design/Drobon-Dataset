# vuln-intel/ — data directory policy

One advisory record per JSON file. Every file must validate (`npm run validate`).

## Placement

```
vuln-intel/
├── npm/
│   ├── samples/                 # fixtures only ("fixture": true, DROBON-SAMPLE-###)
│   └── <ADVISORY-ID>.json       # real npm records (none yet)
└── pypi/
    ├── samples/                 # fixtures only
    └── <ADVISORY-ID>.json       # real pypi records (none yet)
```

- Real records: `vuln-intel/<ecosystem>/<ID>.json` where `<ID>` is the record's `id` with `/` replaced by `-` (ids must already be filename-safe: bounded text without control characters; reviewers must reject ids containing path separators).
- Fixtures: `vuln-intel/<ecosystem>/samples/<ID>.json` only. A fixture anywhere else fails review; a non-fixture under `samples/` fails the validator's cross-checks in spirit and review in letter.
- New ecosystems require an app-side parser first (`SCA_ECOSYSTEMS` in the Drobon repo) — never add an ecosystem directory the app cannot produce coordinates for.

## Current state

- **Real records: none yet.** The three `DROBON-SAMPLE-###` fixtures exist to prove the format, schema, and validator work end to end. They assert nothing about the real world.
- Adding the first real record requires: a published upstream advisory, full `provenance`, and the `HONESTY.md` review checklist.

## Known TODOs (tracked, not silently assumed)

1. **Range-parse validation.** The v1 validator checks range bounds/shape, not that ranges parse as semver/PEP 440. A zero-dependency range-syntax checker (or a pinned dev-dependency) should be added before the first real record lands.
2. **Directory lint.** No automated check yet that `samples/` contains only fixtures and real dirs contain no fixtures — currently enforced by review only.
3. **Sharding.** If real data grows past a few hundred files per ecosystem, shard by package-name prefix (e.g. `npm/lo/lodash/GHSA-….json`) and document it here. Do not shard prematurely.
