# SCA rule schema — proposal (not implemented)

Status: **PROPOSAL ONLY.** No schema, validator, generator, test, or rule file has changed. SCA rule-pack count stays **0** until an owner approves the schema below and rules pass validation.

Date: 2026-10-16. Main App reference: `main` = `c32c797` (read-only).

## 1. Current state (three tiers, counted separately)

| Tier | SCA count | Evidence |
|---|---|---|
| SCA rule packs (`packs/sca/`) | **0** | No `packs/sca/` directory. The SCA target counts rule packs. |
| Advisory records (`vuln-intel/`), validated | **84 items** (100 files) | `docs/CORPUS_TARGETS.json` `advisory-record`: `validatedCount` 84, `licenseStatus` `BLOCKED_LICENSE_REVIEW`, notes say breadth is frozen under the data lock. |
| Advisory records, verified production | **0** | `verifiedProductionCount` 0. |
| Publish-ready | **0** | Release is NO-GO (licence and provenance gates BLOCKED). |

The 84 advisory items are not included in the rule-pack total (SAST 950 + DAST 398 + SCA 0 = **1871** rule packs, recount 2026-10-21). Earlier drafts of this line cited "820", a mid-batch snapshot whose derivation is not reproducible from any committed count; it must never be read as a current verified total. `docs/CORPUS_TARGETS.json` is the only authoritative count source. Rule-pack totals count rule packs only.

## 2. Why advisory records cannot reach the target now

- `vuln-intel/README.md`: extension is **BLOCKED_BY_DATA_LOCK** until an authorized production stage. Coverage growth waits for that authorization.
- Advisory data carries licence and provenance obligations. Those gates are BLOCKED (S10 in `docs/OWNER_ACTION_REQUIRED.md`).
- Adding advisories now would mean fabricating or importing data without authorization. Neither is allowed.

So advisory records are a data-authorization decision, not a rule-authoring task. This proposal covers the rule-pack kind only.

## 3. What an SCA rule is (proposed)

An SCA rule classifies a **declared dependency specifier or lockfile entry** as a supply-chain hygiene risk. It does not decide whether a concrete version is affected, and it does not look up advisories.

Input domain (what the rule sees):
- `declaredVersion` from `package.json` or a PEP 508 requirement line. The app already parses this (`RawDependency.declaredVersion`).
- Lockfile entry fields that the app already parses: `integrity` (npm lockfile, requirements hashes).

It is **not** a membership test. The concrete-version question stays with `scripts/range.mjs` and advisory records.

### 3.1 Required fields (new kind `drobon.pack.sca/v1`)

```json
{
  "schemaVersion": "drobon.pack.sca/v1",
  "id": "DPK-SCA-001",
  "title": "Unbounded npm dependency specifier",
  "description": "...",
  "severity": "MEDIUM",
  "category": "dependency-hygiene",
  "ecosystems": ["npm"],
  "check": { "type": "declared-specifier-unbounded", "input": "declaredVersion" },
  "remediation": "...",
  "limitation": "...",
  "tests": [
    { "input": { "declared": "*" }, "match": true },
    { "input": { "declared": "1.2.3" }, "match": false }
  ]
}
```

- `id`: `DPK-SCA-NNN`. A new prefix, so no existing ID is reused. Retired IDs stay reserved as today.
- `ecosystems`: exactly one of `npm` or `pypi` per rule. Same-concept rules for each ecosystem are separate cells, like the per-language SAST cells.
- `check.type`: a **closed vocabulary**. Only the values in section 3.2 are accepted. Unknown types fail validation.
- `tests`: at least 2 positive and 2 negative fixtures. At least one negative is a near miss that a naive variant would flag.
- Remediation text is required (`knowledge/remediation/DPK-SCA-NNN.json`), matching the consistency rule that no finding lacks guidance.
- No `patterns/` or `records/` files. Those are regex-signal artefacts. The consistency suite needs an explicit SCA exemption for them.

### 3.2 Closed check vocabulary (proposed)

| `check.type` | Input | Fires when |
|---|---|---|
| `declared-specifier-unbounded` | npm `declaredVersion` | `""`, `*`, `x`, `X`, or `latest` |
| `declared-specifier-non-registry` | npm `declaredVersion` | git/github/gitlab/bitbucket/http(s)/`file:` URL, or GitHub `user/repo` shorthand |
| `declared-specifier-prerelease-pin` | npm `declaredVersion` | exact version carrying a prerelease tag (`2.0.0-rc.1`) |
| `declared-specifier-open-lower-bound` | npm `declaredVersion` | `>=` or `>` with no `<`/`<=` bound and no `\|\|` |
| `declared-version-absent` | pypi `declaredVersion` | requirement has no version specifier |
| `declared-specifier-open-lower-bound` | pypi `declaredVersion` | `>=` or `>` with no upper bound (`<`, `<=`, `==`, `~=`, `===`) |
| `declared-specifier-prerelease-pin` | pypi `declaredVersion` | `==` pinned to a PEP 440 pre-release (`2.0.0rc1`, `1.0b2`) |
| `lockfile-integrity-absent` | npm lockfile entry | registry `resolved` URL with no `integrity` |
| `requirement-hash-absent` | pypi requirement line | `==` pin with no `--hash` |

The `declared-specifier-*` types are one check per ecosystem and concept. Each pair differs in syntax, not in version logic.

Two further types need an app field that is not parsed today, so they are **blocked**:

- `declared-source-non-index` (PEP 508 `name @ url` and `git+` requirements). The app `RawDependency` has no source-kind field.
- `lockfile-resolved-untrusted` (npm `resolved` host or scheme). `RawDependency` has no resolved-URL field.

## 4. Distinct from `scripts/range.mjs` (measured)

Probe (read-only, run from `/tmp`, not committed) of the Dataset's own evaluator on declared specifiers:

| Input | `validateRange` result | Consequence for an SCA rule |
|---|---|---|
| npm `*` | rejected: "bare `*` is not allowed" | The rule must *report* `*`, which the evaluator refuses. |
| npm `""` | rejected: "non-empty string" | Same as above. |
| npm `latest` | rejected: bad comparator | dist-tag, outside the evaluator grammar. |
| npm `^1.2.3` | rejected: bad comparator | The most common npm specifier is outside the advisory grammar. |
| npm `git+https://…` | rejected: bad comparator | Non-registry source, outside the grammar. |
| npm `2.0.0-rc.1` | accepted | Prerelease pin: the rule reports it, evaluator accepts it. |
| pypi `>=2.0` | accepted | Open lower bound: the rule reports it. |

`satisfiesRange('npm', '1.2.3', '*')` throws ("invalid range"). The evaluator fails closed by design. An SCA hygiene rule needs the opposite behaviour, namely to report the declared specifier text. The two do not overlap in input domain or output.

## 5. Fixture evidence (probe)

Candidate classifiers were run over positive and negative fixtures (probe in `/tmp/p17/sca-probe.mjs`, not committed):

| Cell | Ecosystem | Positives | Negatives | Result |
|---|---|---|---|---|
| declared-specifier-unbounded | npm | 4 | 4 | PASS |
| declared-specifier-non-registry | npm | 5 | 4 | PASS |
| declared-specifier-prerelease-pin | npm | 3 | 3 | PASS |
| declared-specifier-open-lower-bound | npm | 2 | 3 | PASS |
| declared-version-absent | pypi | 2 | 2 | PASS |
| declared-specifier-open-lower-bound | pypi | 2 | 3 | PASS |
| declared-specifier-prerelease-pin | pypi | 2 | 2 | PASS |
| lockfile-integrity-absent | npm | 2 | 2 | PASS |
| requirement-hash-absent | pypi | 2 | 2 | PASS |

These fixtures are the proposal's test data, not yet in the repo. Fixtures must reach the stated minimums before any rule file is written.

Sources for the semantics: npm `package.json` dependency specifiers, in particular `*` and `""` matching any version, `latest` as a tag, and the git, `file:` and URL forms: https://docs.npmjs.com/cli/v7/configuring-npm/package-json/ . pip hash-checking mode, where `--hash` implies `--require-hashes` for the whole install and every requirement must be pinned: https://pip.pypa.io/en/stable/cli/pip_install/ .

## 6. Deduplication

- Signature = `(ecosystem, check.type, normalized parameters)`. An exact signature match quarantines the later cell, like SAST signal dedup.
- Two rules may share a concept only if their ecosystems differ. Two rules in one ecosystem must differ in check type.
- A rule that fires on the same fixture set as another rule in the same ecosystem is a duplicate and must be merged or removed.

## 7. Honest ceiling

The concepts above give **at most 11 distinct cells**: 9 buildable from current app fields and 2 blocked on app fields. A 1000-rule SCA target **cannot** be met with distinct rules of this kind. Reaching 1000 would need 989 near-duplicate variants of the same specifier checks, which is the superficial padding the directive forbids.

So the SCA target is a decision for the owner:

1. **Keep SCA rule packs at 0** until the schema is approved and the cells pass.
2. **Approve the schema and the 9 buildable cells**, and record the SCA target as capped at about 11 distinct rules.
3. **Authorize the advisory-record stage** (data lock lifted, licence review closed) for the advisory tier. That is a separate decision from rule packs, and it is the only route to large counts.
4. **Add the 2 app fields** (source kind and resolved URL) so the blocked cells can be built. That is an app-side change. The Main App stays read-only for this project.

## 8. Decisions needed before any change

- Approve the `drobon.pack.sca/v1` kind, with the vocabulary in section 3.2 (owner approval, as for any schema change).
- Choose option 2, 3, or 4 from section 7, or a combination.
- Confirm that prerelease pin classification is policy-independent. This proposal classifies declared text. It does not evaluate versions, so the OWNER DIRECTION on prerelease inclusion (`docs/FORMAT.md`, not implemented) does not change it.

## 9. Not done in this change

- No schema change, validator change, generator change, test change, or rule file.
- SCA rule-pack count stays 0.
- Main App unchanged (read-only).
