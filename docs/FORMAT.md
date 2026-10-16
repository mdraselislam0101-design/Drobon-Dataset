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
- `provenance`: see HONESTY.md. Fixtures (`"fixture": true`) must use `"source": "fixture"`, must omit the "real record" requirements, and must use ids matching `DROBON-SAMPLE-###`. Real records must never use that id prefix. `provenance.source` must resolve to `vuln-intel/sources.json`, and GHSA-sourced records must carry `GHSA-xxxx-yyyy-zzzz` ids.

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

**pypi** — `range := spec ("," spec)*`; `spec := op version`; `op := "===" | "==" | "~=" | "!=" | "<=" | ">=" | "<" | ">"`; `version` is PEP 440 (optional epoch, dot-separated release, `a`/`b`/`rc` pre, `post`, `dev`, `local`). Local identifiers are rejected in `<`, `<=`, `>`, `>=` and `~=` (D3); `==`/`!=` prefix matches containing a dev or local release are rejected (D4); `==`/`!=` with a local identifier match only an equal normalized local label (D5, fixed in Pump 7). `".*"` is allowed only with `==` / `!=`; `"~="` needs at least two release segments; `"==="` takes a non-space literal (string equality). Environment markers (`; …`) are rejected — ranges match versions only.

### npm prerelease behaviour — OPEN OWNER DECISION (no policy chosen, Pump 4; source-checked Pump 5)

Current behaviour, pinned by `scripts/test.mjs` and labelled POLICY-PENDING there: `satisfiesRange('npm', '1.5.0-beta.1', '>=1.0.0 <2.0.0')` returns **true**.

Source (Pump 5): the node-semver README, section "Prerelease Tags" (https://raw.githubusercontent.com/npm/node-semver/main/README.md): a prerelease version satisfies a comparator set only if some comparator in that set has the same `[major, minor, patch]` tuple and also carries a prerelease tag. Under that rule `1.5.0-beta.1` does not satisfy `>=1.0.0 <2.0.0`. The engine's behaviour therefore differs from the npm default. This is npm library policy, not a semver.org MUST, so it stays POLICY-PENDING: the owner decides whether the Dataset adopts it. Over-inclusion is conservative for SCA but over-reports affected versions. Owner options match the PyPI section below and need the Main App provider to agree.

### PEP 440 deviations — D1–D4 FIXED (Pump 6); D5 FIXED (Pump 7)

Pump 5 recorded these as known defects that needed owner approval. Pump 6 fixed D1–D4 in `scripts/range.mjs` after adding failing regression rows first (RED: 14 evaluator rows and 8 validator rows failed before the fix; GREEN after). They are MUST requirements in PEP 440 (https://peps.python.org/pep-0440/, sections "Version matching" and "Exclusive ordered comparison"; text re-checked 2026-10-15), not policy choices. The pre-release SHOULD default is separate and remains POLICY-PENDING (below).

- **D1 — `>V` no longer allows a post-release of V** unless V is itself a post-release (candidate with the same epoch and zero-padded release as V, and a post segment, is rejected). Spec: "`>V` MUST NOT allow a post-release of the given version unless `V` itself is a post release"; `>1.7` allows `1.7.1` but not `1.7.0.post1`. Now `satisfiesRange('pypi', '1.7.0.post1', '>1.7')` returns **false**; `satisfiesRange('pypi', '1.7.1', '>1.7')` still returns true. Pinned rows `2.0.post1 >2.0` and `1.7.0.post1 >1.7` now carry the spec value (false).
- **D2 — `<V` no longer allows a pre-release or dev-release of a final V.** Applies only when V is a final release; candidates with the same epoch and zero-padded release that carry a pre or dev segment are rejected. Spec: "`<V` MUST NOT allow a pre-release of the specified version unless the specified version is itself a pre-release." Now `satisfiesRange('pypi', '2.0.0a1', '<2.0')` returns **false**. Pre-, dev- and post-release V values are unchanged (out of scope, no defect shown). Pinned row `2.0.0a1 <2.0` now carries the spec value (false).
- **D3 — local identifiers are rejected in bounds.** `validateRange` rejects a local identifier in `<`, `<=`, `>`, `>=` and `~=`. Spec: "Local version identifiers are NOT permitted in this version specifier" (inclusive and exclusive ordered comparisons; compatible release). `==`, `!=` and `===` keep local identifiers. `1.6` with `<1.7+local` is now rejected at import/review time instead of being accepted.
- **D4 — invalid prefix matches are rejected.** `validateRange` rejects `==`/`!=` prefix matches containing a dev or local release (for example `1.0.dev1.*`, `1.0+foo.*`). Spec: "It is invalid to have a prefix match containing a development or local release."

Verification (Pump 6): `node scripts/test.mjs` 572/572; `npm run test:vectors` 16/16 (no pypi vector has a strict bound that changes); a spec probe of the PEP 440 examples reported 0 mismatches; nine mutants of the new guards were each detected by `node scripts/test.mjs` (post-guard off, pre-guard off, local-bound check off, dev-prefix check off, local-prefix check off, `~=` not forbidden, post-guard ignoring pre, pre-guard dropping the dev exemption, pre-guard ignoring release). Real-record impact over 30 real pypi ranges × 308 candidate versions (9,240 pairs): 48 decisions change, all `true → false` on `a1`, `rc1` or `.dev1` candidates against an exclusive `<` final bound; 0 change `false → true`; the set of ranges that throw is unchanged. The audited Main App snapshot (`c32c797`) has no SCA range evaluator, so there is no live consumer of these results on that side.

### D5 — `==` / `!=` with a local identifier — FIXED (Pump 7)

Spec (re-fetched 2026-10-15, "Version matching", https://peps.python.org/pep-0440/): "If the specified version identifier is a public version identifier (no local version label), then the local version label of any candidate versions MUST be ignored when matching versions. If the specified version identifier is a local version identifier, then the local version labels of candidate versions MUST be considered when matching versions, with the public version identifier being matched as described above, and the local version label being checked for equivalence using a strict string equality comparison."

Before Pump 7 the evaluator dropped the local label, so `satisfiesRange('pypi', '1.0', '==1.0+abc')` and `satisfiesRange('pypi', '1.0+xyz', '==1.0+abc')` both returned true (MUST violations). `!=` inherited the same error. Pump 7 fixed it in `scripts/range.mjs`:

- A candidate matches `==V+L` only if its public part matches V (as before) and its normalized local label equals L. A candidate with no label, or a different label, does not match.
- `!=V+L` is the inverse of that match. Public-only specifiers (`==V`, `!=V`) still ignore the candidate label.
- Label normalization follows PEP 440 "Normalization": case-insensitive; purely numeric segments are integers (`01` equals `1`, leading zeros removed); integers inside an alphanumeric segment are not normalized (`foo0100` is not `foo100`). Comparison is then strict string equality. Numeric normalization is string-based, so long labels cannot lose precision.
- `===` is unchanged (plain string equality).
- Limitation (fail closed, not a wrong answer): the parser accepts local labels only as `[a-zA-Z0-9]` segments joined by `.`. A spec-valid label with `-` or `_` (for example `1.0+ubuntu-1`) is rejected with an error and never evaluated. Accepting it would widen the grammar in `validateRange` too, so it is recorded as an open item rather than changed here.

RED first: 8 rows failed before the fix (candidates without the label, different label, numeric and alphanumeric normalization, pre-release candidate, and `!=` inversion). The controls (exact label, case, padding, public-only specifiers, `===`) passed before and after.

Real-data impact (recomputed 2026-10-15, `vuln-intel/` 50 real pypi records, 30 distinct pypi ranges, 308 candidate versions each): 0 of 9,240 decisions change. No real pypi range uses a local label in `==`, `!=` or `===`. `interop/provider-vectors.json` has no local versions. The 870 throws in this sweep come from synthetic candidates the sweep itself generates (for example `0.5.0b3.dev1a1`, which is not a valid PEP 440 version); they are identical before and after the fix.

Owner options, now resolved by the spec and the Pump 6 contract: none outstanding for D5. Fail-closed rejection was the alternative; exact matching was chosen because it is the spec-direct behavior and changes no current result.

### PyPI prerelease policy — OPEN OWNER DECISION (no policy chosen)

Current behaviour, pinned by `scripts/test.mjs` and labelled POLICY-PENDING there: `satisfiesRange('pypi', '1.5rc1', '>=1.0,<2.0')` returns **true**. Prerelease versions are evaluated as ordinary PEP 440 versions and are included in ranges.

Source (Pump 5): PEP 440 "Handling of pre-releases" (https://peps.python.org/pep-0440/): pre-releases are implicitly excluded from all version specifiers unless already installed, explicitly requested, or the only version that satisfies the specifier; resolution tools "SHOULD" follow that default. The wording is SHOULD, so the default is a tool policy. It is separate from the D1/D2 MUST items above, which hold regardless of this policy.

PEP 440 defines a default where pre-releases are excluded from a specifier set unless the set itself names a pre-release or the caller opts in. This dataset does NOT adopt that default. Options for the owner to decide (each is a behaviour change that would also need the Main App provider to agree):

1. Keep the current inclusive behaviour (document it as the provider contract).
2. Adopt the PEP 440 default (exclude pre-releases unless a specifier names one, e.g. `>=1.0a1`).
3. Make it a per-coordinate or per-record flag, defaulting to one of the above.

Until an owner decision is recorded, do not infer one; the current behaviour stays, and the pinned test must be updated together with any decision.

## Determinism & ordering

- One advisory-package-range record per file: multi-package and multi-range-branch advisories expand to `<ID>.json`, `<ID>--2.json`, … (see `vuln-intel/README.md` for paths).
- Files and `affected` entries SHOULD be sorted (by `ecosystem`, `package`, `id`; ranges ascending) so diffs stay reviewable. The validator does not enforce order in v1.

## Versioning policy

- `drobon.vuln-intel/v1` is immutable: any breaking change (renamed/removed field, tightened bound, new required field) requires a new `schemaVersion` and a migration note in this doc.
- Additive, backward-compatible changes (new *optional* field) require a minor version bump and a validator + schema update in the same commit.
