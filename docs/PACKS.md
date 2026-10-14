# PACKS.md — rule packs as data

Rule packs are Drobon's answer to paid-tool rule content: detection rules shipped as **versioned, tested data** instead of hardcoded logic — the same concept as Nuclei templates or Semgrep rules, but in Drobon's own format and with 100% original Drobon content. No proprietary rule was copied, adapted, or "clean-roomed" from any commercial tool; see the originality rule below.

**Honest state: packs have no consumer in the app today.** The Drobon app's current rules are hardcoded matchers. Packs become live only when the app repo ships a pack loader (checklist below). Until then this directory is ready-and-waiting data with machine-checked semantics — never silently half-integrated.

## Layout

```
packs/
├── sast/v1/
│   ├── pack.json            # { schemaVersion, packId, version, description }
│   └── rules/DPK-SAST-###.json
├── secrets/v1/
│   ├── pack.json
│   └── rules/DPK-SEC-###.json
└── dast/v1/
    ├── pack.json
    └── rules/DPK-DAST-###.json
```

- One rule per file; filename MUST equal the rule `id`.
- `pack.json` carries the pack identity (`packId` `^[a-z0-9-]+$`, `version` `^N.N.N$`).
- Packs have **no sample concept**: every shipped rule must be a genuine, tested rule. Ids containing `-SAMPLE-` are rejected.

## Common rule fields (all three kinds)

| Field | Bound | Notes |
|---|---|---|
| `schemaVersion` | const per kind | `drobon.pack.sast/v1` / `drobon.pack.secrets/v1` / `drobon.pack.dast/v1` |
| `id` | `^DPK-(SAST\|SEC\|DAST)-[0-9]{3,}$` | stable, never reused; distinct from the app's `DG-*` ids |
| `title` | 1–120 chars | surfaces in findings |
| `description` | 1–1000 chars | what matched and why it matters |
| `severity` | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO` | conservative; lexical-only rules cap at MEDIUM unless the construct itself is the weakness |
| `category` | `^[a-z0-9-]{1,64}$` | grouping (`command-injection`, `private-key`, …) |
| `remediation` | 1–1000 chars | fix guidance (surfaces in findings) |
| `limitation` | 1–1000 chars | documented detection limits (required — every rule states what it cannot see) |
| `cwe` | optional `^CWE-[0-9]{1,4}$` | only when certain; omitted rather than guessed |
| `tests` | 2–50 entries | executable examples, ≥1 positive AND ≥1 negative (required) |

All shapes are closed (unknown fields rejected) and control-character-free, mirroring the advisories discipline. The executable spec is `scripts/validate-packs.mjs`.

## SAST pack (`drobon.pack.sast/v1`)

Lexical, line-based rules — the data twin of the app's `SastRule` matcher contract (one physical line in, at most one match out).

- `languages` (optional, 1–10): app language-family ids (`javascript`, `python`, …). Must be syntactically valid here; the loader MUST reject ids missing from the app's `SAST_LANGUAGE_CATALOG` (fail-closed). Omitted = universal (runs on every analyzed file).
- `patterns` (1–8): `{ source (1–500 chars), flags? }`. A line matches when ANY pattern matches. Only flag `"i"` is allowed — never `g`/`y` (stateful `lastIndex`) — and the loader must construct one `RegExp` per pattern exactly as written.
- `tests`: `{ line (1–1000 chars), match }`. The validator compiles every pattern and asserts every example.

### ReDoS policy

Every pattern passes a conservative static lint (validator-enforced): **no nested quantifiers** (`(a*)*`), **no repeated unbounded wildcards** (`.*.*`); character classes are stripped before linting so `[.*]` literals are fine. This lint is necessary, not sufficient: the app-side loader MUST also run bounded-time regression tests (pathological-line analysis budget, like the app's current ReDoS suite) before any pack rule goes live.

Flow/dataflow rules (`flow: command|sql|html` in the app) are NOT expressible as packs — packs are lexical only, by design.

## Secrets pack (`drobon.pack.secrets/v1`)

Credential-shape rules — the data twin of the app's `SecretsRule` contract. Shape-only: a match proves the STRING has a credential's shape, never that it is live/valid/compromised.

- `confidence` (required): `LOW`/`MEDIUM`/`HIGH` — detection confidence only.
- `patterns`: same contract as SAST (1–8, `"i"` only, ReDoS lint, example-executed).
- `denylist` (optional, ≤20 entries of 1–64 chars): case-insensitive substrings that VETO a match (placeholders, documentation values). The validator applies the veto when executing tests.
- `redact` (required): MUST be `true` — a pack rule ships only if it promises evidence redaction of matched material.
- `matchOnlyEvidence` (optional bool): evidence is the match alone (for headers/carriers without material, e.g. PEM headers).
- No `languages`: secrets rules are universal.
- `tests`: same shape as SAST; negatives SHOULD demonstrate denylist vetoes and short-fragment misses.

## DAST pack (`drobon.pack.dast/v1`)

Passive checks over one observed response — the data twin of the app's `evaluateDastObservation` input (`{ url, status, headers, body, contentType }`). Active probing is not expressible and never will be.

Closed check vocabulary (v1 — the loader implements exactly these):

| `check.type` | Params | Fires when |
|---|---|---|
| `http-url` | — | observed URL scheme is `http:` |
| `missing-response-header` | `header` (HTTP token) | header absent (case-insensitive) |
| `response-header-missing-directive` | `header`, `directive` (HTTP tokens) | header absent, OR present without the `;`-separated directive (directive name matched before any `=`, case-insensitive) |
| `cookie-missing-flag` | `flag`: `Secure`/`HttpOnly`/`SameSite` | any `Set-Cookie` entry lacks the flag (`Secure`/`HttpOnly`: `;`-delimited token; `SameSite`: requires `=`). Responses with no cookies never match. |

Notes:

- Header names/values in tests may use any case; matching is case-insensitive throughout.
- One header value counts as one cookie (a folded multi-cookie single value may under-flag — documented v1 limitation; loaders SHOULD pass arrays).
- `status`/`body`/`contentType` are validated structurally in tests and reserved for future check types; v1 checks do not read them.
- `tests`: `{ observation: { url (http/https, ≤400), status (100–599), headers (≤30, values string or string[] ≤1000), body? (≤4000), contentType? (≤200) }, match }`. The validator IMPLEMENTS the four checks (`evalDastCheck`) and asserts every example — DAST semantics are executable here, not prose.

## Finding mapping (loader contract)

When the app loader runs a pack rule, fields map 1:1 onto the app finding model: `ruleId` ← pack `id`, plus `title`, `description`, `severity`, `remediation`, `cwe?`. The loader derives file/line/column evidence (SAST/secrets) or observed-response evidence (DAST, fixed templates per check type), applies secrets redaction, and runs the app's standard finding-identity/dedup. Pack ids (`DPK-*`) never collide with app ids (`DG-*`); overlapping coverage may double-flag with distinct rule ids — acceptable and honest.

## Loader checklist (app-repo work, not this repo's)

1. Parse + validate packs at startup with this repo's validator semantics; fail closed on unknown `schemaVersion`, unknown field, or unknown DAST check type.
2. Gate SAST rules by the app language catalog; reject unknown families (never run ungated).
3. Re-run bounded-time ReDoS regression over all pack patterns; refuse slow packs.
4. Execute every rule's examples at load (same assertions as the validator); refuse packs whose tests fail.
5. Redact secrets evidence per `redact`/`matchOnlyEvidence` before findings persist.
6. Surface pack id + version in scan metadata so findings trace to data versions.

## Contributing rules

1. **Original content only.** Write every pattern, title, description, and test yourself from public knowledge (language semantics, vendor-documented credential formats, HTTP standards, CWE definitions). Never copy, adapt, or paraphrase proprietary rules (Semgrep Pro, Checkmarx, GitGuardian, Snyk, …). Coverage overlap with commercial tools is expected and fine; expression must be yours.
2. **Every rule tested.** ≥1 positive + ≥1 negative example, executed by the validator. A rule whose tests fail does not ship.
3. **Conservative severity, certain CWE.** Lexical rules cannot prove taint — cap at MEDIUM unless the construct itself is the weakness; omit `cwe` when unsure.
4. **`limitation` is mandatory.** State what the rule cannot see (comments, aliases, encodings, folded headers…).
5. **Run the suite.** `npm test` covers packs, negatives, ReDoS units, and OSV mapping fixtures.

## Versioning

- Pack content versions live in each `pack.json` (`N.N.N`, semver per pack: new rules = minor, rule removal/semantics change = major).
- Format versions are the `schemaVersion` consts: any breaking field change requires a new const + validator + this doc updated together.
