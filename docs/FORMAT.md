# FORMAT.md — advisory record format (v1)

`schemaVersion: "drobon.vuln-intel/v1"`. This is the **only** record format this repository accepts. The executable spec is `scripts/validate.mjs`; `schema/advisory.schema.json` mirrors it for editors and tooling. If they ever disagree, the validator wins and the schema must be fixed.

## Design constraints (inherited from the app)

The Drobon app's SCA provider seam would consume this data — once a real provider exists — through one narrow contract:

```
assess(coordinates) → { providerId, datasetStatus, advisories[] }
```

- Input coordinates carry only `{ ecosystem, name, version?, dependencyId }` — never manifest content.
- Output advisories must satisfy the app's **closed** `ScaAdvisory` guard: required `id`, `severity`, `summary`, `dependencyId`, `ecosystem`, `name`; optional `url`, `version`. Unknown fields are rejected; every text field is bounded and control-character-free.

Therefore every bound below **mirrors the app constant exactly**, so a record that validates here can never produce an advisory the app would reject:

| Dataset field | Bound | Mirrors app constant |
|---|---|---|
| `id` | 1–100 chars, no control chars | `SCA_ADVISORY_ID_MAX_LENGTH` |
| `summary` | 1–400 chars, no control chars | `SCA_ADVISORY_TEXT_MAX_LENGTH` |
| `url` | 1–400 chars, `https://` only | `SCA_ADVISORY_URL_MAX_LENGTH` |
| `package` | 1–214 chars, no control chars | `SCA_NAME_MAX_LENGTH` |
| `affected[].range`, `affected[].fixed` | 1–200 chars | `SCA_VERSION_MAX_LENGTH` |
| `ecosystem` | `npm` \| `pypi` | `SCA_ECOSYSTEMS` |
| `severity` | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` \| `INFO` | `FINDING_SEVERITIES` |

Deliberate omissions (v1 has no…): CVSS/risk scores, CWE ids, published/modified dates, CWE-to-finding mappings. The app's `ScaAdvisory` has no such fields, and the provider contract forbids fabricating scores — so the dataset does not carry them either. The only timestamp is `provenance.retrievedAt` (when *we* fetched the record, not a vuln claim).

## Record shape (closed — unknown fields rejected)

```jsonc
{
  "schemaVersion": "drobon.vuln-intel/v1",   // required, exact const
  "fixture": false,                          // required boolean (true = synthetic sample)
  "id": "GHSA-xxxx-yyyy-zzzz",                // required, 1–100 chars
  "ecosystem": "npm",                        // required: "npm" | "pypi"
  "package": "left-pad",                     // required, 1–214 chars, normalized name
  "summary": "One-line summary from the source.", // required, 1–400 chars
  "severity": "HIGH",                        // required, source-published severity
  "url": "https://…",                        // optional, https only, 1–400 chars
  "affected": [                              // required, 1–50 entries
    { "range": "<1.2.0", "fixed": "1.2.0" }   // range required; fixed optional
  ],
  "provenance": {                            // required (see HONESTY.md)
    "source": "GHSA",                        // required, 1–64 chars
    "sourceUrl": "https://…",                // required for real records, https only
    "retrievedAt": "2026-10-14T00:00:00.000Z", // required for real records, RFC 3339
    "license": "…"                           // optional, 1–100 chars
  }
}
```

### Field notes

- `package`: the normalized package name the provider matches against the coordinate `name` — npm names as-declared (lowercase scope rules), PyPI names PEP 503-normalized. Normalization rules are owned by the app's SCA parsers; dataset authors copy the canonical upstream name.
- `summary`: one line, copied or closely paraphrased from the source advisory. Must not claim exploitability beyond what the source states.
- `severity`: **must be the source-published severity**, never guessed or "upgraded". Records whose source publishes no severity must not be added until a severity can be verified. (The validator checks the enum; humans check the truth — see HONESTY.md.)
- `url`: primary reference link (usually the source advisory page). `https://` only.
- `affected[].range`: ecosystem version-range syntax (below). At least one entry; at most 50.
- `affected[].fixed`: first version containing the fix, when the source states one. Informational in v1 (the app has no `fixed` field to surface it through); kept so data is not lost.
- `provenance`: see HONESTY.md. Fixtures (`"fixture": true`) must use `"source": "fixture"`, must omit the "real record" requirements, and must use ids matching `DROBON-SAMPLE-###`. Real records must never use that id prefix.

## Version-range semantics

Matching is performed by the future provider against the coordinate `version` (exact resolved version when a lockfile provided one, else the declared pin). Ranges use the ecosystem's native syntax:

| Ecosystem | Range syntax | Examples |
|---|---|---|
| `npm` | semver range (node-semver compatible subset: `<`, `<=`, `>`, `>=`, `=`, hyphen, `x`-ranges, `||`) | `<1.2.0`, `>=1.0.0 <1.4.2`, `1.x` |
| `pypi` | PEP 440 version specifier set (comma = AND) | `<1.2.0`, `>=1.0.0,<1.4.2`, `==1.2.*` |

Rules:

1. A range matches a coordinate version if and only if the ecosystem's canonical comparator says so (npm: semver; PyPI: PEP 440). No fuzzy matching, no prefix guessing.
2. Coordinates **without** a version (declared range, no lockfile resolution) match only when the provider can prove the intersection semantics it implements — conservative default: match on name + ecosystem and let the record's `range` be evaluated only against exact versions; never silently treat "unknown version" as "affected". (Exact policy is owned by the provider implementation in the app repo; this dataset only guarantees ranges are parseable.)
3. Ranges must parse under this repo's zero-dependency checker (`scripts/range.mjs`), enforced by the validator on every record. Anything outside the supported subset is rejected at import/review time with an explicit error — never silently treated as match or miss. Evaluation (`satisfiesRange`) is exact-or-throw and backs the provider interop vectors.

### Supported range subset (enforced)

**npm** — `range := group ("||" group)*`; `group := hyphen | and`; `hyphen := version "-" version` (spaces around `-` required); `and := token ((" " | ",") token)*`; `token := [op] version`; `op := ">=" | "<=" | ">" | "<" | "="`; `version := ["v"] num ["." num ["." num]] ["-" pre] ["+" build]` where each `num` is digits or `x`/`X`/`*`. Operator-glued spacing (`"<= 2.7.0"`, `">= 1.0.0, < 2.0.0"`) is accepted. A lone `*` is rejected — use explicit bounds.

**pypi** — `range := spec ("," spec)*`; `spec := op version`; `op := "===" | "==" | "~=" | "!=" | "<=" | ">=" | "<" | ">"`; `version` is PEP 440 (optional epoch, dot-separated release, `a`/`b`/`rc` pre, `post`, `dev`, `local`). `".*"` is allowed only with `==` / `!=`; `"~="` needs at least two release segments; `"==="` takes a non-space literal (string equality). Environment markers (`; …`) are rejected — ranges match versions only.

## Determinism & ordering

- One advisory-package-range record per file: multi-package and multi-range-branch advisories expand to `<ID>.json`, `<ID>--2.json`, … (see `vuln-intel/README.md` for paths).
- Files and `affected` entries SHOULD be sorted (by `ecosystem`, `package`, `id`; ranges ascending) so diffs stay reviewable. The validator does not enforce order in v1.

## Versioning policy

- `drobon.vuln-intel/v1` is immutable: any breaking change (renamed/removed field, tightened bound, new required field) requires a new `schemaVersion` and a migration note in this doc.
- Additive, backward-compatible changes (new *optional* field) require a minor version bump and a validator + schema update in the same commit.
