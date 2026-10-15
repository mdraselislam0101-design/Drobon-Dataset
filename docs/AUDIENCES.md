# AUDIENCES.md — user-type datasets

The Drobon app serves four user types (`DEVELOPER`, `STUDENT`, `SECURITY_PROFESSIONAL`, `PENTESTER` — classification only, never authorization). Each type's workspace runs on hardcoded app content today (remediation maps, lesson catalog, assessment inputs, engagement setup). These four directories hold that content **as versioned, validated data** for future app-side loaders — the same concept as rule packs, extended to audiences.

**Honest state: no consumer in the app today.** The app's hardcoded content stays authoritative until the app repo ships loaders (checklist per dataset below). Until then these directories are ready-and-waiting data with machine-checked semantics.

## 1. Remediation knowledge — `knowledge/remediation/` (Developer + Security Professional)

One file per rule (`<RULE-ID>.json`), mirroring the app's `FindingRemediationGuidance` (`ruleId`, `whyItMatters`, `actions[]`, `verification`, `standardId?`, `example?{before, after, caveat?}`).

- `schemaVersion`: `drobon.knowledge.remediation/v1`.
- `ruleId`: any `DG-SAST-*` / `DG-SEC-*` / `DG-DAST-*` / `DPK-*` id.
- Bounds: `whyItMatters`/`verification` ≤1000, `actions` 1–8 × ≤400, `example.before`/`after` ≤800, `caveat` ≤400, `standardId` `^CWE-[1-9][0-9]{0,5}$` (app `FINDING_CWE_PATTERN`; omit when uncertain).
- Loader contract: merge by `ruleId` into remediation responses; entries for unknown rule ids must be ignored with a warning, never surfaced (fail-closed against stale data).
- Coverage bar (consistency-tested): every `DPK-*` pack rule MUST have a remediation entry — a new rule without guidance fails `npm test`. The reverse is allowed (entries may cover `DG-*` app rules too).

## 2. Student lessons — `learning/lessons/` (Student)

One file per lesson (`lsn_*.json`), mirroring `StudentLessonInternal` and the shared bounds (`STUDENT_LESSON_ID_PATTERN`, ≤5 objectives, text ≤2000, quiz ≤6 questions × ≤5 options, practice ≤3 files × ≤800 chars, `answerIndex` server-side in the app).

- `schemaVersion`: `drobon.learning.lesson/v1`.
- Executable practice (validator-enforced): when `practice.targetRuleId` is a `DPK-SAST-*` rule, the validator loads that pack rule and asserts starter files trigger it (≥1 matching line) and fixed files do not (0 matching lines). A lesson whose exercise cannot work does not ship.
- `DG-*` targets are shape-checked only (app-owned rules are unverifiable here — the loader verifies); `DPK-SEC-*`/`DPK-DAST-*` targets are rejected (lesson practice is SAST-scan based in v1).
- Loader contract: extend the lesson catalog; strip `answerIndex`/`explanation` from public projections (same as the hardcoded catalog); never execute learner code (static analysis only, as today).

## 3. Assessment templates — `assessments/templates/` (Security Professional)

One file per template (`tmpl_*.json`): starting objectives + scope notes for common assessment types, mirroring the app bounds (title ≤120, objectives ≤10 × ≤240, hosts ≤20 total, notes ≤1000, exact DNS hostnames only).

- `schemaVersion`: `drobon.assessment.template/v1`.
- **Templates never pre-declare authorization.** There is no `authorizationDeclarations` field — the closed shape rejects it outright. Every engagement's authorization is declared at runtime by the user (`USER_DECLARED`) and stays unverified by the platform, exactly as today.
- Loader contract: offer templates as pre-filled starting points for new assessments; the user still reviews scope, hosts, and declarations before activation.

## 4. Engagement templates — `engagements/` (Pentester)

One file per template (`eng_*.json`): scope boundaries + workflow checklists for authorized, **passive-only** engagements. This dataset contains NO offensive content: no payloads, no exploit steps, no tooling for active probing — the app model is passive observation plus user declarations, and this data stays inside it.

- `schemaVersion`: `drobon.engagement.template/v1`.
- `scopeTemplate`: `notes` (≤1000) + `boundaries` (1–10 explicit out-of-scope reminders, ≤240 each).
- `checklist`: 1–20 `{ item (≤240), kind }`, `kind` closed to `authorization` / `scope` / `evidence` / `safety`.
- Banned-phrase lint (validator-enforced tripwire): reverse shells, msfvenom, sqlmap, mimikatz, meterpreter, shellcode, cobalt strike, zero-days, kerberoast, pass-the-hash, bloodhound, burp. High-precision by design; human review still required for anything the lint cannot see.
- Loader contract: surface as engagement setup aids; never auto-fill authorization; halt lines of inquiry that leave declared scope (checklist kind `scope`).

## Contributing audience content

1. **Original content only** (same rule as packs): write every lesson, template, and guidance entry yourself. Never copy assessment methodologies, course content, or checklist products verbatim.
2. **Bounds are app-compatible by construction**: every bound mirrors or tightens an app constant, so validated data can never break app guards.
3. **Executable where possible**: lessons targeting pack rules must demonstrably work (validator runs them); quiz answers must point at real options; templates must use exact hostnames.
4. **Review checklist**: `npm test` green; no pre-declared authorization anywhere; no offensive content in engagements (read every line — the lint is a backstop, not a reviewer); CWE/standard ids only when certain.
