# PROVIDER_MAPPING.md — how the app consumes this dataset

The `Drobon` app never reads this repository directly. A future, separately-deployed **provider** loads this data server-side and plugs into the app's single seam (`apps/api/src/scans/sca/provider.ts`):

```
assess(coordinates) → { providerId, datasetStatus, advisories[] }
```

This document pins the mapping so dataset authors know exactly which fields matter and app-side implementers know exactly what this data guarantees. The app contracts below are quoted from `packages/shared/src/sca.ts` and `apps/api/src/scans/sca/provider.ts` (Drobon repo, `main`).

## 1. Input: what the provider receives (coordinates only)

```ts
interface DependencyCoordinate {
  ecosystem: ScaEcosystem;   // 'npm' | 'pypi'
  name: string;              // normalized package name
  version?: string;          // exact version when a lockfile provided one; absent for ranges
  dependencyId: string;      // dep_<24 hex> — response wiring only
}
```

Consequences for this dataset:

- Matching keys are `(ecosystem, package, version)`. The dataset's `package` values must equal the app's normalized coordinate `name`s, or records will never match.
- Manifest content, paths, and dependency graphs never reach the provider — the dataset cannot (and must not try to) key on them.

## 2. Output: the advisory shape (closed)

Every advisory the provider returns must satisfy the app's `isScaAdvisory` guard:

| `ScaAdvisory` field | Required | Bound | Dataset source |
|---|---|---|---|
| `id` | ✅ | 1–100 chars | record `id` (verbatim) |
| `severity` | ✅ | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO` | record `severity` (verbatim) |
| `summary` | ✅ | 1–400 chars | record `summary` (verbatim) |
| `dependencyId` | ✅ | `dep_[0-9a-f]{24}` | from the matched coordinate (never from data) |
| `ecosystem` | ✅ | `npm`/`pypi` | from the matched coordinate (must equal record `ecosystem`) |
| `name` | ✅ | 1–214 chars | from the matched coordinate (must equal record `package`) |
| `url` | optional | 1–400 chars | record `url` (verbatim, when present) |
| `version` | optional | 1–200 chars | from the matched coordinate `version` (when known) |

Rules for the future provider (app-side, recorded here so both sides agree):

1. **Match, then re-validate.** The engine re-validates every provider advisory against `isScaAdvisory` before persisting — a provider cannot smuggle shapes. Records that pass this repo's validator are guaranteed to survive that guard on the dataset-sourced fields.
2. **Only verified matches.** `assess` returns records it actually matched against loaded data. No match → no advisory; the scan completes `NOT_ASSESSED` for those dependencies.
3. **Dataset status is honest.** A configured provider whose data is missing/unreachable reports `DATASET_UNAVAILABLE` — the scan still succeeds with inventory + SBOM. The shipped Null provider reports `NO_DATA_LOADED`.
4. **Server-side composition only.** Nothing client-facing selects, registers, or influences a provider (`VULN_INTEL_PROVIDER` is server config; today it must be `none` and any other value fails app startup — changing that is an app-repo decision, not this repo's).

## 3. Range evaluation (provider-owned, dataset-constrained)

- The dataset guarantees `affected[].range` values are non-empty, ≤200 chars, and written in the ecosystem's native syntax (npm semver / PEP 440 — see `FORMAT.md`).
- The provider guarantees canonical evaluation (npm: semver comparator; PyPI: PEP 440 comparator) against the coordinate `version`, with a conservative policy for version-less coordinates (never silently "affected").
- `affected[].fixed` is informational in v1: there is no `ScaAdvisory.fixed` field to surface it through, so providers must not concatenate it into `summary` (that would break the verbatim-summary guarantee).

## 4. What changes where (when integration happens)

| Change | Repo | Notes |
|---|---|---|
| Advisory records, format versions | `Drobon-Dataset` (here) | review per `HONESTY.md` |
| Provider implementation, range evaluation, `VULN_INTEL_PROVIDER` values | `Drobon` (app) | app maintainers own the dataset-lock change |
| Database schemas, if data is ever DB-served | `Drobon-Database` | record *format* stays defined here |

Nothing in this repository can weaken the app's dataset lock — integration requires an explicit, reviewed change in the app repo. That is intentional.
