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
| `cwe` | optional `^CWE-[1-9][0-9]{0,5}$` (app `FINDING_CWE_PATTERN`, no leading zeros) | only when certain; omitted rather than guessed |
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
| `response-header-missing-directive` | `header`, `directive` (HTTP tokens) | header absent, OR present without the directive. Directives are split on `;` and `,` (CSP directives and policies; RFC list headers such as `Cache-Control`); the directive name is matched before any `=`, case-insensitive |
| `cookie-missing-flag` | `flag`: `Secure`/`HttpOnly`/`SameSite` | any `Set-Cookie` entry lacks the flag (`Secure`/`HttpOnly`: `;`-delimited token; `SameSite`: requires `=`). Responses with no cookies never match. |
| `response-header-matches` | `header`, `valuePattern` (bounded regex, ReDoS-linted) | header present and any value matches the pattern (case-insensitive). Absent header never matches. |
| `response-body-matches` | `valuePattern` (bounded regex, ReDoS-linted); optional `requireScheme`: `http`/`https` | observation has a body and it matches the pattern (case-insensitive). With `requireScheme`, the observed URL must use that scheme first. No body captured never matches. Passive: reads the observed response only. |
| `response-header-host-differs` | `header` (HTTP token, e.g. `Location`) | status is 3xx, the header is present, and its first value resolves (relative to the observed URL) to an `http:`/`https:` host different from the observed host. Unparseable or non-web targets never match. No redirect is followed. **Host-only policy:** the comparison is on the URL hostname (case-insensitive via URL parsing). Port and scheme changes on the same host do NOT match (e.g. `https://app/` to `https://app:8443/` or to `http://app/`); userinfo tricks such as `https://app@evil/` do match (real host is `evil`). |

Notes:

- Header names/values in tests may use any case; matching is case-insensitive throughout.
- One header value counts as one cookie (a folded multi-cookie single value may under-flag — documented v1 limitation; loaders SHOULD pass arrays).
- `status`/`body`/`contentType` are validated structurally in tests and reserved for future check types; v1 checks do not read them.
- `tests`: `{ observation: { url (http/https, ≤400), status (100–599), headers (≤30, values string or string[] ≤1000), body? (≤4000), contentType? (≤200) }, match }`. The validator IMPLEMENTS all seven checks in the table above (`evalDastCheck`) and asserts every example — DAST semantics are executable here, not prose.

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

## Pump 3 review snapshots (2026-10-15)

Recorded evidence and open gaps from Pump 3. Counts are snapshots; the tests named here re-check them.

### Secrets — DPK-SEC-063 (credentials in a URL)

- Pattern: `[A-Za-z][A-Za-z0-9+.\-]*://[^\s:@/]*:[A-Za-z0-9]{12,}@`. Tests: 10 (indices 0–3 original; 4–9 appended through the generator's `extraTests`, index-preserving).
- Mutation evidence: `{12,}`→`{11,}` and removing the trailing `@` both make `validate-packs` fail.
- Probe-verified NOT covered (documented gaps, no false negatives asserted as expected): JDBC URLs with a `password=` query parameter; ADO-style `Password=` key/value connection strings; URL passwords containing symbols (non-alphanumeric). Coverage of quoted `password = "…"` forms by other secrets rules was NOT ASSESSED in Pump 3.

### DAST — evaluator contract

- Seven check types (the table above). Evaluator rows in `scripts/test-packs.mjs`: 9 (Pump 2) + 36 (Pump 3: boundary 299/300/399/400, userinfo and subdomain host confusion, port/scheme policy, malformed and empty Location, header-name case, cookie flag edge cases, body edge cases).
- Redirect host-only policy is pinned by tests: same host different port or scheme does NOT match.
- Mutation evidence (on a disposable copy): redirect host comparison disabled → 6 failures; status boundary `>399`→`>=399` → 1 failure; comma-split reverted → 2 failures.
- Latent defect fixed in Pump 3: `response-header-missing-directive` split only on `;`, so `Cache-Control: no-cache, no-store` reported `no-store` as missing. Now split on `;` and `,`. No current rule uses a comma-separated header, so no shipped rule result changed.

### SAST — duplicate review (shared-pattern groups)

Groups = SAST rules sharing an identical pattern source and flags. Reproduced: **31 groups / 86 rules**. Tripwires in `scripts/test-consistency.mjs` enforce TRUE_DUPLICATE = 0 and pin the snapshot counts.

| Class | Groups | Rules | Rule used | Disposition |
|---|---|---|---|---|
| TRUE_DUPLICATE | 0 | 0 | same pattern AND same language | none found |
| CROSS_CWE | 13 | 28 | same pattern, different `cwe` values | OPEN owner/CWE review: mapping inconsistency for one sink |
| POSSIBLE_OVERLAP | 4 | 30 | ≥6 rules on one bare function name (G2 `system`, G4 `eval`, G21 `redirect`, G24 `rand`) | OPEN owner review; kept |
| LANGUAGE_IDIOM | 12 | 24 | one sink name, distinct language-specific idioms | keep (language-gated) |
| CONFIG_KEY_SHAPE | 2 | 4 | same YAML/HCL key shape | keep (config-family rules) |

Classification is deterministic from the rule files; the five labels above are this pump's working taxonomy and should be confirmed by the owner.

### SAST — language reachability (Dataset vs Main App catalog) — Pump 3 snapshot, SUPERSEDED by Pump 4 below

Snapshot against Main App `apps/api/src/scans/sast/languages.ts` at commit `c32c797` (read-only). The Main App engine gates rules per file by catalog language id.

- (Pump 3 figures, SUPERSEDED by Pump 5 below: "109 language ids" was the distinct pattern-target count, which includes the DAST target `http`; it was not a language count. Current: 108 language ids, 67 absent from the catalog.)
- SAST rules (743): 567 have at least one catalog id; 175 have none (includes 10 rules tagged `universal`, which is not a catalog id); 1 has no `languages` field (DPK-SAST-004, the universal convention that the app treats as universal).
- `shell-posix` (catalog id, POSIX shell): not expressible. The schema rule `^[a-z][a-z0-9]{0,31}$` rejects hyphens; no POSIX-shell rules exist. Owner schema decision open.
- `shell` (Dataset-only id, 25 rules) is emitted alongside `bash`. The `bash` tag is the catalog id.
- The validator's message says "exist in the app language catalog", but it checks only the pattern. A catalog check is NOT ASSESSABLE in this repo without a snapshot of the app catalog (owner decision).

### SAST — language reachability, Pump 4 (machine-checked)

The Main App engine analyzes a file only when its family maturity is `PARTIAL`, `CONFIG_ANALYSIS` or `FULL`; `SYNTAX_ONLY` and `UNSUPPORTED` families are skipped. A SAST rule runs on a file only when `rule.languages` includes the file's family id (no alias map; rules with no `languages` field are universal by convention). Dataset rules therefore reach the engine only through catalog ids.

Catalog snapshot (Main App `apps/api/src/scans/sast/languages.ts`, commit `c32c797`, read-only; id → maturity). `test-consistency` re-checks the counts below against this block; it cannot re-read the Main App repo.

```app-language-catalog
{"javascript":"PARTIAL","typescript":"PARTIAL","jsx":"PARTIAL","tsx":"PARTIAL","python":"PARTIAL","java":"PARTIAL","kotlin":"PARTIAL","c":"PARTIAL","cpp":"PARTIAL","csharp":"PARTIAL","go":"PARTIAL","php":"PARTIAL","rust":"PARTIAL","ruby":"PARTIAL","swift":"PARTIAL","dart":"PARTIAL","scala":"PARTIAL","objc":"PARTIAL","objcpp":"PARTIAL","lua":"PARTIAL","solidity":"PARTIAL","r":"PARTIAL","elixir":"PARTIAL","erlang":"PARTIAL","clojure":"UNSUPPORTED","groovy":"PARTIAL","perl":"PARTIAL","haskell":"UNSUPPORTED","ocaml":"UNSUPPORTED","julia":"PARTIAL","vbnet":"PARTIAL","apex":"PARTIAL","bash":"PARTIAL","shell-posix":"PARTIAL","powershell":"PARTIAL","sql":"CONFIG_ANALYSIS","html":"SYNTAX_ONLY","css":"SYNTAX_ONLY","xml":"CONFIG_ANALYSIS","yaml":"CONFIG_ANALYSIS","json":"CONFIG_ANALYSIS","dockerfile":"CONFIG_ANALYSIS","terraform":"CONFIG_ANALYSIS","github-actions":"CONFIG_ANALYSIS","android-manifest":"CONFIG_ANALYSIS","assembly":"UNSUPPORTED","matlab":"UNSUPPORTED","fortran":"UNSUPPORTED","cobol":"UNSUPPORTED","crystal":"UNSUPPORTED","zig":"UNSUPPORTED","nim":"UNSUPPORTED","v":"UNSUPPORTED"}
```

- Catalog: 53 ids. Dataset language ids: 108 (Pump 4, after `hcl` alias applied). Intersect: 41. Dataset ids not in catalog: 67.
- SAST rules (743), counted per rule against analyzed catalog ids: fully reachable (every tag analyzed) 500; partially reachable 25; no analyzed tag 217; no `languages` field 1 (DPK-SAST-004, universal convention).

reachability-counts: fully=528 partial=25 unreachable=217 noLanguages=1 ids=112 intersect=45

- SAST Batch 3 (2026-10-16): 2 Solidity rules, SAST 769 -> 771, fully reachable 526 -> 528. Added `unchecked-arithmetic` (an `unchecked` block that disables Solidity 0.8 overflow checks; CWE-190) and `unchecked-send` (a bare `send()` whose boolean result is ignored; CWE-252). The `send` pattern excludes call sites whose result is consumed. Both CWE records were verified against the MITRE 4.20 names and added as pack-only entries. `send` is deprecated in the Solidity docs and is still matched in existing code.
- SAST Batch 2 (2026-10-16): 8 new language-specific rules, SAST 761 -> 769. Added: Elixir Ecto/Repo SQL concatenation, VB.NET `SqlCommand` concatenation with `&`, PL/SQL `EXECUTE IMMEDIATE ... ||`, MySQL `PREPARE ... FROM CONCAT(`, Erlang `erl_eval:expr` code evaluation, Erlang and Apex MD5 selection, Erlang `verify_none` and Dart `badCertificateCallback` TLS verification off. Excluded as duplicates of an existing rule: Erlang `rand:uniform` (random-3), Erlang `verify_none` (tls-langs). Not added: Apex `Math.random` and VB.NET `New Random` (same detection as Java and C#). Solidity `unchecked` and `send` need new CWE records (CWE-190, CWE-252), which are not in `knowledge/cwe/`.

- Rule-tag view: the `universal` tag appears on 10 rules and is not a catalog id, so those rules fall into partial or unreachable.
- Mapped in Pump 4: `hcl` → `terraform` (Terraform / HCL family, extensions `.tf`/`.hcl`/`.tfvars`). Applied to DPK-SAST-018, 021, 325–333, 711–717 (18 rules) and their 18 patterns via the generator's `APP_LANGUAGE_ALIASES` and count-asserted legacy splices. Rule-level change: +18 fully reachable (16 generated + 2 legacy), −2 partial, −16 unreachable.
- NOT mapped, blocked by schema: `gha` → `github-actions` (5 rules, DPK-SAST-520..524). Language ids in `packs` and `knowledge` must match `^[a-z][a-z0-9]{0,31}$`, which rejects hyphens. Hyphenated catalog ids (`github-actions`, `shell-posix`, `android-manifest`) are unexpressible until the owner approves a schema change. Note: the Main App catalog itself uses hyphenated ids.
- NOT mapped, owner decision: `universal` (10 rules; Main App `universal` meaning would broaden findings), `k8s` (13) and `compose` (4) (YAML-family broadening), `shell` (25; `.sh` detects as `shell-posix`, which is unexpressible; `bash` is reached only via shebang detection).
- Unreachable by design of the app (catalog maturity UNSUPPORTED or SYNTAX_ONLY): crystal, fortran, matlab, nim, ocaml, clojure, haskell, cobol, html (58 rule-tags). Dataset rules on these stay unreachable until the app catalog changes.
- Dataset-only ids with no app family (no catalog entry): awk, vba, apache, nginx, properties, tcl, grafana, … (67 ids in total, including `gha`, `k8s`, `compose`, `shell`). Their rules have no engine reach. Do not describe them as covered.
- Catalog ids with no Dataset rule: objcpp, solidity, vbnet, apex, shell-posix, sql, css, github-actions, android-manifest, assembly, zig, v (12). New rule files for analyzed gaps (objcpp, solidity, vbnet, apex, shell-posix) need explicit approval.

### Generator — fail-loud guard

- If any cell is quarantined, `scripts/generate-assets.mjs` now exits 1, lists the reasons on stderr, and writes or removes no files. Before this, a quarantined cell silently removed its previously generated files and still exited 0 (reproduced on a disposable copy: `removed: 4`).
- Invariant: `data/asset-cells/quarantine.json` must list zero cells; a sandbox run with a schema-rejected cell must fail without touching assets (`test-consistency`).

### Four-UserType matrix

See `docs/AUDIENCES.md` §5 (machine-checked counts).

### pypi prerelease

Policy NOT chosen; see `docs/FORMAT.md` ("PyPI prerelease policy — OPEN OWNER DECISION").

## Pump 4 review snapshots (2026-10-15)

Recorded evidence from Pump 4. Counts are snapshots; the tests named here re-check them. Everything below is PARTIAL: no gate is closed by this pump (see the gates list in `docs/OWNER_ACTION_REQUIRED.md`).

### Language mapping

- `hcl` → `terraform` applied (18 SAST rules, 18 patterns). Mechanism: `APP_LANGUAGE_ALIASES` in `scripts/generate-assets.mjs`; legacy DPK-SAST-018 and 021 edited by count-asserted splices. Guard: `test-consistency` `reachability:` rows.
- `gha` → `github-actions` NOT applied: the language id schema rejects hyphens. Owner schema decision required (see the Pump 4 reachability section above).

### Secrets

- DPK-SEC-063 `url-credentials` extra tests 6 → 10 (14 total). Added: `mongodb+srv` positive, empty-username `redis://` positive, `<password>` negative, `${DB_PASSWORD}` negative.
- DPK-SEC-007 limitation corrected. It previously said placeholders are vetoed by the denylist. The denylist is `EXAMPLE` and `changeme` only, so `<password>` and `${DB_PASSWORD}` still match. This is a known false positive. Narrowing the denylist (for example adding `${` as DPK-SEC-003 already does) is an owner tuning decision and was NOT made. CORRECTION (Pump 5): the parenthetical is WRONG. DPK-SEC-003's `${` entry does not veto quoted `${...}` placeholders, because that rule's character class cannot match them at all. See the Pump 5 secrets section.
- Probe-verified gaps, still NOT covered by any secrets rule: unquoted `DB_PASSWORD=…` environment assignments; JDBC `password=` query parameters; ADO `Password=` connection strings; URL passwords containing symbols. Each needs an owner-approved new rule (new file).

### DAST

- Evaluator rows 13 added (`p4 …` in `scripts/test-packs.mjs`): uppercase scheme, array header values, `SecureX` vs `Secure`, bare `SameSite`, `Location` with uppercase scheme and ftp scheme, `no-store-x` vs `no-store`, uppercase `HTTPS` in `requireScheme`. Each expected value follows the contract in the DAST table above.
- Mutation evidence on disposable copies: cookie flag terminator removed → `test-packs` fails.

### SCA ranges

- Existing `POLICY-PENDING` rows extended: npm prerelease `1.5.0-beta.1` vs `>=1.0.0 <2.0.0` (current: included). Pinned, not endorsed. pypi `2.0.0a1` vs `<2.0` was labelled POLICY here; Pump 5 reclassified it as a KNOWN DEFECT (PEP 440 MUST). See `docs/FORMAT.md`.
- Caret `^` and tilde `~` are rejected (outside the documented subset) and pinned as invalid rows.

### Reflection (CWE-470)

- DPK-SAST-747..753 (7 rules, 4 tests each: 2 positive, 2 negative) on csharp, java, python, ruby. All four families are `PARTIAL` in the Main App catalog, so these rules are reachable.
- CWE-470 name corrected to the canonical form `Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')`. The ID is unchanged. Checked against three secondary mirrors (exploit-intel.com, penscan.org, radar.offseq.com) on 2026-10-15. UPDATE (Pump 5): the MITRE page WAS fetched (https://cwe.mitre.org/data/definitions/470.html, version 4.20) and the name matches verbatim. The three-mirror check above is superseded by this primary source.

### Generator quarantine re-proof (disposable copy)

- A cell with `confidence: BOGUS` makes `scripts/generate-assets.mjs` exit 1, print the reason, and leave all 3584 files under `packs/`, `knowledge/`, `learning/`, `data/` byte-identical (sha256 before/after).

### Duplicate and CWE review

- Shared-pattern groups unchanged after the `hcl` mapping: 31 groups / 86 rules; CROSS_CWE 13 groups stay OPEN (no CWE value changed without an owner decision).

### Not done in Pump 4 (owner decision or new file required)

- Lesson audience field (see `docs/AUDIENCES.md` §2: DEFERRED).
- Schema change for hyphenated language ids (`github-actions`, `shell-posix`, `android-manifest`).
- Denylist tuning for DPK-SEC-007.
- Records for the 40 legacy hand rules (would be new files).
- New rules for catalog gaps (objcpp, solidity, vbnet, apex, shell-posix).

## Pump 5 review snapshots (2026-10-15)

Status: **PARTIAL**. No gate is closed by this pump. Every open decision is listed in `docs/OWNER_ACTION_REQUIRED.md` §6. Nothing was committed or pushed in Pump 5. Counts were re-derived from the working tree; tests pin them.

### Reachability, reason-coded (Main App `c32c797`, read-only)

- The `app-language-catalog` block matches the live catalog: 53 of 53 ids and maturities, checked by a read-only import of `apps/api/src/scans/sast/languages.ts` in Pump 5. The engine runs a rule on a file only when `rule.languages` contains the detected family id exactly. There is no alias map.
- Detection paths: every analyzed family has an extension, filename, or shebang path, except `github-actions` (content-only: `runs-on` plus `jobs:` or `on:`) and `matlab` (content-only `.m` tie-break, UNSUPPORTED).
- SAST 743 rules, by reason:
  - FULL 500.
  - PARTIAL 25: all `shell` + `bash`. `bash` reaches only extensionless shebang scripts. `.sh` files go to `shell-posix`, which has zero Dataset rules.
  - NONE 217 = NO_APP_FAMILY 127 + CAT_UNSUPPORTED 55 + ALIAS_OR_BROADEN 22 (gha 5, k8s 13, compose 4) + UNIVERSAL_TAG 10 + CAT_SYNTAX_ONLY 3.
  - UNIVERSAL_CONVENTION 1: DPK-SAST-004 has no `languages`, so the app runs it on every analyzed file. Its tests are intentional: `hashlib.md5(...)` is a negative, excluded by `(?<!\.)`.
  - Sum: 500 + 25 + 217 + 1 = 743.
- Analyzed app families with zero Dataset SAST rules: objcpp, solidity, vbnet, apex, shell-posix, sql, github-actions, android-manifest. `yaml` and `xml` rules never see GHA workflows or `AndroidManifest.xml`, because those files route to other families.
- Blocked by schema: hyphenated ids (`github-actions`, `shell-posix`, `android-manifest`). The id regex `^[a-z][a-z0-9]{0,31}$` rejects them, and `scripts/test-consistency.mjs` (~L872–900) pins that rejection on purpose. Changing it needs owner approval.
- DPK-SAST-018 carries tags `terraform` and `python`. No test line is Python-shaped, so the `python` tag has no test evidence. Retained and flagged for owner review, not changed.

### Language-id count (corrects "109")

- Base commit `dd487175`: distinct rule `languages[]` = 108, including `hcl`. Distinct pattern `targets` = 109. The extra one is `http`, a DAST target, not a language.
- Working tree: 108 = 108 − `hcl` (mapped to `terraform`, which already existed) + `bash`.
- `bash` comes from a Pump 4 generator change, `languageTags('shell') → ['shell','bash']` in `scripts/generate-assets.mjs`. It is not in base commit `dd487175`. It is in the working tree and the generator reproduces it byte-for-byte. It tags 25 `shell` rules.
- Catalog intersect 41; ids absent from the catalog 67.

### Four-UserType audit

See `docs/AUDIENCES.md` §6. Counts equal the `matrix-counts` tripwire.

### SAST — CWE-470 group analysis

- MITRE 4.20 name confirmed verbatim from the primary page: "Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')". The MITRE relationships section was not read in Pump 5, so the mapping is not checked against CWE hierarchy.
- DPK-SAST-747..753 (7 rules) use 7 distinct patterns (DPK-PAT-0898..0904). They share no pattern source with any other rule.
- Sink names (`CreateInstance`, `GetType`, `forName`, `getDeclaredMethod`, `getattr`, `const_get`, `public_send`) appear in no other rule.
- The rules are in no CROSS_CWE and no POSSIBLE_OVERLAP group. Disposition: no change.

### SAST — CROSS_CWE reproduction

Reproduced with the Pump 3 definition (identical pattern source and flags): 31 groups / 86 rules; CROSS_CWE 13 groups / 28 rules; TRUE_DUPLICATE (same pattern and same language) 0. Unchanged. The 13 CROSS_CWE groups stay OPEN for owner/CWE review. CWE-470 is in none of them.

### Records, retired IDs, and generator invariants

- Patterns 888; records 848. The 40 patterns without a record are exactly the 40 `legacy` manifest entries.
- Retired reservations: 26, the list in `docs/ASSET_METHODOLOGY.md`. They equal the manifest cells that have no rule file (26). Batch 2 (2026-10-16) retired five exact-duplicate DAST cells, each with the same check signature as an earlier rule that is kept: DPK-DAST-015 (= 002), DPK-DAST-019 (= 005), DPK-DAST-020 (= 007), DPK-DAST-018 (= 009), DPK-DAST-048 (= 010). None exists as a rule, pattern, or remediation file.
- DAST overlap review (2026-10-16, no retirement): HSTS DPK-DAST-003 (no max-age), DPK-DAST-023 (no preload) and DPK-DAST-049 (no includeSubDomains), and CSP DPK-DAST-021 (unsafe-inline) and DPK-DAST-022 (`default-src *`), each have a distinct check signature (type, header, and directive or pattern). None is an exact duplicate, so none is retired under the policy. They share a trigger only when the header is absent. Main App built-in DG-DAST-002 (HSTS missing or ineffective max-age) overlaps DPK-DAST-003 at the app level; retiring a pack rule does not resolve that, and it is out of Dataset scope. Open item: DPK-DAST-022 is titled "wildcard source", but its pattern matches only `default-src *`; a rule-text correction needs approval.
- Generator byte-stability: a regenerate in a disposable copy changed 0 of 3584 files.
- Quarantine: setting `confidence: "BOGUS"` on the secrets class in `data/asset-cells/secrets.json` made `generate-assets` exit 1 with "43 cell(s) quarantined". 0 of 3584 files changed. One class-level field quarantines all its cells.

### DAST evaluator — mutation evidence (disposable copies)

| Mutant (`scripts/validate-packs.mjs`) | Result |
|---|---|
| redirect host comparison disabled | DETECTED (10 FAIL lines) |
| status boundary `>399` → `>=399` | DETECTED (2 FAIL lines) |
| comma split reverted to `;` only | DETECTED (4 FAIL lines) |
| host check skipped for uppercase `HTTP` observed URL | **MISSED** at first: no test row covered it. Two rows added (`p5 host-differs`, `scripts/test-packs.mjs`). Re-run: DETECTED (2 FAIL lines). |

Pack-tests: 3648 → 3650.

### Secrets — veto mechanism: test gap CLOSED at the rule layer (Pump 6)

**Original gap (Pump 5).** The denylist veto (`scripts/validate-packs.mjs`, `checkLineTests`) had no regression evidence. Across 88 secrets rules with a denylist, zero negative tests have their outcome changed by the veto. Mutants that disable the veto (`B1`), disable the lowercasing of the denylist (`B2`), or disable the lowercasing of the test line (`B3`) were all **MISSED** by `npm test` (exit 0 for each).

**Failed approach (Pump 5, reverted).** Two veto-only negatives were added to `packs/secrets/v1/rules/DPK-SEC-007.json`. The generator mirrors every rule test into the pattern's `examples`, and `test-assets` checks those examples against the pattern regex, which has no denylist. The mirrored examples failed with `got true, want false`. The rule and its pattern were restored byte-identical. The pattern test path expects regex-only results, so veto-only negatives must not be placed there.

**Pump 6 design (chosen, no new file, no rule or pattern change).** The veto is applied by the rule-level validator, so the regression lives in the existing pack harness, `scripts/test-packs.mjs`, section "Pump 6: secrets denylist veto at the rule layer". That section:

- loads the real `DPK-SEC-007` pattern and denylist (`EXAMPLE`, `changeme`);
- combines them with synthetic tests in memory through the exported `validatePackFile`; nothing is written to the repository;
- pairs each row with a partner of the opposite expectation, so every call has at least one positive and one negative;
- has two positive controls (no denylist term, so the pattern must still match);
- has four veto rows: exact `EXAMPLE`, case-insensitive `Example`, exact `changeme`, case-insensitive `CHANGEME`;
- has a harness self-check: a veto row labelled as a match must be rejected with `expected match=true`, so the rows cannot pass vacuously.

Test values contain spaces. The repository's own leak scanner (`scripts/test-consistency.mjs`, "no credential shapes outside packs/secrets fixtures") rejects credential-shaped literals outside `packs/secrets`. A first version with `ss3cr3t…` and `Xq9v…` literals was caught by that guard and was rewritten. The guard was not changed. The pattern class `[^"']{4,}` accepts spaced values, so the veto is exercised the same way.

**Mutant results.**

| Mutant | Change in `scripts/validate-packs.mjs` | Pump 6 before tests (`npm test`) | Pump 6 after tests (`npm test`) |
|---|---|---|---|
| B1 / F1 | veto disabled (`if (false && hit && …)`) | MISSED (exit 0) | DETECTED (exit 1, 5 FAIL lines) |
| B2 / F2 | denylist not lowercased (`lowered.includes(deny)`) | MISSED (exit 0) | DETECTED (exit 1, 3 FAIL lines) |
| B3 / F3 | test line not lowercased (`const lowered = entry['line'];`) | MISSED (exit 0) | DETECTED (exit 1, 4 FAIL lines) |
| F4 | exact-only, no case folding (`entry['line'].includes(deny)`) | not run | DETECTED (exit 1, 2 FAIL lines) |

`test-packs` after the change: 3657/3657 (was 3650). Pattern-mirror tests and `DPK-PAT-0039` are unchanged.

**Generator/validator divergence — RESOLVED (Pump 7).** `generate-assets.mjs` `runLineTests` applied the denylist with a case-sensitive `includes`, while `docs/PACKS.md` (the contract) and `validate-packs.mjs` use case-insensitive substrings. Pump 7 made the generator case-insensitive and exported `runLineTests` (a behaviour-neutral export) so `test-packs.mjs` can check it directly. Regression rows (Pump 7 section of `test-packs.mjs`): uppercase `EXAMPLE` veto, lowercase `example` veto, mixed-case `Example` veto, a control, and a mislabelled vetoed line that must be reported. RED before the fix: 3 failures (the lowercase, mixed-case and mislabelled rows). GREEN after. Mutants: G1 (generator case-sensitive again) DETECTED, 3 FAIL lines; G2 (generator veto off) DETECTED, 4 FAIL lines. Generator output is unchanged: two consecutive runs and the working tree agree byte-for-byte (0 differences), so no generated record changed.

**Still open (owner decisions).** Denylist tuning for DPK-SEC-007 (`${`, `<`) is not changed. Adding `${` or `<` would also veto real values that contain those characters. The case-insensitive veto also suppresses real-looking values that contain `example` in any case (for example, a quoted value containing the word example in any letter case); this is the intended contract, not a defect, but it is an over-veto risk to review.

### Secrets — probe results (synthetic values, read-only)

Synthetic secret body `Zq7Lm2Wx9Rt4Yc8Vb3Nk`. Each line was tested pattern-only, then with the veto applied as in `validate-packs`.

- **Gaps** (no rule matches): JDBC `password=` parameter; JDBC `;password=`; ADO `Password=`; unquoted `DB_PASSWORD=`; `export DB_PASSWORD=`; unquoted YAML `password:`; URI with a symbol in the password (`Qz!9#…`).
- **Covered:** URI alphanumeric password (DPK-SEC-063); redis URI with empty user (DPK-SEC-063); `mongodb+srv` (DPK-SEC-063); quoted `password = "…"` (DPK-SEC-007).
- **Correct negatives:** a 10-character URI password; `${DB_PASSWORD}` inside a URI.
- **Vetoed:** `changeme` and `EXAMPLE` (DPK-SEC-007 denylist `["EXAMPLE","changeme"]`).
- **Known false positives, not vetoed (structural):** `password = "<password>"`, `password = "${DB_PASSWORD}"`, and `your-password-here` all match DPK-SEC-007. Its class `[^"']` admits `<`, `$`, `{`. This is a pattern limit, not a denylist omission.

### Secrets — correction to Pump 4 (DPK-SEC-003 `${`)

Pump 4 said DPK-SEC-003 "already" vetoes `${`. That was wrong:

- DPK-SEC-003's class `[A-Za-z0-9_\-]{16,}` cannot match `$`, `{`, `<`, or `>`. It never matches `api_key = "${API_KEY_VALUE}"` or `api_key = "<api-key-value>"`, so its `${` entry is inert for quoted placeholders.
- The `${` entry acts only on lines that otherwise match and contain `${` anywhere. Example: a real-looking literal followed by a trailing `${...}` comment is suppressed. That is an over-veto.
- `your-api-key-here-xx` is vetoed by `your-api-key`, as expected.
- Owner decision: adding `${` or `<` to DPK-SEC-007's denylist would veto these false positives. It could also veto real values that contain `${`. NOT changed.

### SCA ranges

- PEP 440 exclusive-bound deviations D1 (`>V` post-release), D2 (`<V` pre-release), and D3 (local versions accepted in bounds) are MUST-level. They are KNOWN DEFECTS, not policy. Full text, citations, and reproduction are in `docs/FORMAT.md` under "PEP 440 exclusive-bound deviations".
- npm prerelease inclusion stays POLICY-PENDING. PyPI default pre-release exclusion stays an owner decision (PEP 440 "Handling of pre-releases" is SHOULD).
- Spec-agreeing rows: 27 added in `scripts/test.mjs`, 20 PEP 440 (including the spec's own examples) and 7 npm.
- Engine: unchanged in Pump 5.

### Test totals (npm test, working tree)

- `npm test` exit 0. All six suites PASS.
- tests 545 (baseline 516: +27 spec rows, +2 KNOWN DEFECT pins); pack-tests 3650 (3648); audience-tests 2705; asset-tests 6994 (unchanged); consistency-tests 182; rehearsal-tests 78.
- Pump 6 and Pump 7 (current, supersede the Pump 5 numbers above): `npm test` exit 0. tests 599 (PEP 440 rows added in Pump 6 and 7, D5 rows and the malformed-local rows included); pack-tests 3662 (Pump 6 secrets veto section, Pump 7 generator veto section); audience-tests 2705; asset-tests 6994; consistency-tests 182; rehearsal-tests 78. `test:vectors` 16/16. Validators: validate 103, validate-packs 891, validate-audiences 898, validate-cwe 48, validate-matrix PASS, validate-sources 1, validate-corpus 3, validate-assets 1736, all 0 errors.

### Pump 7 reconciliation (live recompute, 2026-10-15)

Reachability (`/tmp/p7-reach.mjs`, read-only, Dataset `packs/sast/v1/rules` × Main App `apps/api/src/scans/sast/languages.ts` at `c32c797`). Prospective compatibility analysis only: the Main App contains no reference to `DPK-*` rules or to Dataset paths, so no Dataset rule is loaded or executed by the app today.

- Catalog: 53 families (PARTIAL 32, CONFIG_ANALYSIS 8, SYNTAX_ONLY 2, UNSUPPORTED 11). No family is `FULL`.
- Dataset SAST rules: 743 files. Status per rule: FULL 500, PARTIAL 25, NONE 217, UNIVERSAL 1 (DPK-SAST-004, no `languages` field, the intended universal convention). These match the Pump 5 values.
- Language ids: 108 distinct ids across rule `languages` arrays (this is the language-id count, not the pattern-target count). 41 exist in the catalog; 67 are absent.
- Absent ids with the most rules: `universal` (10 rules: DPK-SAST-026, -063, -138, -190, -247, -277, -307, -361, -409, -448), `shell` (25), `k8s` (13), `gha` (5), `compose` (4), `matlab` (6, catalog family is UNSUPPORTED). The Main App convention for "any file" is to omit `languages`, so the 10 `universal` rules can never match a Main App family. Changing them is a rule change and needs owner approval; so do `gha`, `k8s` and `compose`, whose only possible mapping (`github-actions`, `yaml`) would be an alias or a broadening.
- `shell` / `bash`: the same 25 rules carry both tags (generator alias). In the Main App, `bash` is detected only by shebang (`#!…bash`), and an ordinary `.sh` file is detected as `shell-posix`. No Dataset rule uses `shell-posix`, and that id is hyphenated, so it needs the owner's schema decision. Those 25 rules therefore reach extensionless bash scripts only (PARTIAL).
- `hcl` is merged into `terraform` (18 rules). The Main App `terraform` family is CONFIG_ANALYSIS and covers `.tf`, `.hcl` and `.tfvars`.
- `github-actions` has no Dataset rule id. The Main App detects it by YAML content (`runs-on:` plus `jobs:`/`on:`).
- DPK-SAST-018 has languages `terraform` and `python`. Its four tests are HCL-shaped (`acl = "public-read"`), with no Python test evidence. Its pattern (lowercase `acl`, double quotes) does not match the common Python shape (`ACL='public-read'`). The `python` tag is therefore unsupported by the rule's evidence. Open owner decision: remove the tag or add Python test evidence. Not changed.

CWE-470 (MITRE relationships, read 2026-10-15 from `https://cwe.mitre.org/data/definitions/470.html`, version shown as 4.20): name "Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')" matches `knowledge/cwe/CWE-470.json` exactly. Relationships: ChildOf CWE-610 (Class), ChildOf CWE-913 (Class), ChildOf CWE-20 (Class, View-700), MemberOf CWE-399 (Category, View-699). The Dataset does not store hierarchy fields, so there is nothing to contradict. The seven rules (DPK-SAST-747–753, reflective invocation via `Activator.CreateInstance`, `Type.GetType`, `Class.forName`, `getDeclaredMethod`, `getattr`, `const_get`, `public_send`, all "review required") are sink detectors. They do not evaluate whether the input is externally controlled, so the CWE-470 mapping is consistent with the category but over-describes what the rules check. Uncertain: the Dataset does not pin a CWE version, so the relationships reflect 4.20 only.

Secrets and probe gaps (unchanged, open): see the Secrets sections above. The Pump 7 veto regression and the generator fix do not close the probe gaps (unquoted `DB_PASSWORD=`, JDBC `password=`, ADO `Password=`, symbol-containing URL passwords) and do not change the `${` / `<` denylist behaviour.

Four-UserType audit (Pump 7 recheck, `docs/AUDIENCES.md` §6): live counts match the tripwire `matrix-counts: devLessons=2 studentLessons=5 securityTemplates=3 pentesterTemplates=2 remediation=888 patterns=888 records=848 cwe=48`. The four UserType ids are the same in the Main App (`packages/shared/src/authz.ts`). The Main App contains 0 references to Dataset paths, so there is no consumer for any UserType. 0 of 5 lessons carry an audience field. 0 of 3 templates pre-declare authorization. Engagement checklist kinds are `authorization`, `scope`, `evidence`, `safety`. The only offensive-term hit is the benign phrase "exploitability notes" in `tmpl_api_review.json`.

### Not done in Pump 5 (owner decision or new file required)

- Fix D1–D3 in `satisfiesRange`. (Pump 6: D1–D4 fixed; D5 open. See `docs/FORMAT.md`.)
- npm and PyPI prerelease policy.
- Secrets veto test design (Pump 6: closed at the rule layer; see Secrets, veto mechanism).
- Denylist tuning for DPK-SEC-007 (`${`, `<`).
- New secrets rules for the probe gaps.
- Hyphenated language-id schema.
- Review of the `python` tag on DPK-SAST-018.
- Review of the `bash` tag on the 25 `shell` rules (Pump 4 generator change, not in base commit).
- Records for the 40 legacy patterns (new files).
