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
- Developer-focused lessons (Pump 2): `lsn_dev_*` files use the same Student contract. The contract has no audience field, so DEVELOPER membership is by id prefix only; a dedicated audience field needs owner approval.
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

## 5. Four-UserType coverage matrix (Pump 3)

One shared intelligence base serves all four user types. Membership is by directory and id prefix only; the lesson contract has no audience field (owner decision, see gaps). Counts below are machine-checked by `scripts/test-consistency.mjs` (tripwire line) and must not be hand-edited.

| UserType | Dataset content it draws on | Count (tree) | Status |
|---|---|---|---|
| DEVELOPER | Remediation guidance (shared, every pack rule); developer lessons `lsn_dev_*` | remediation 1200; dev lessons 2 | Data present; no app consumer |
| STUDENT | Lessons `learning/lessons/*` (includes the 2 `lsn_dev_*` lessons; no audience field) | lessons 6 | Data present; overlap with DEVELOPER by design until audience field is approved |
| SECURITY_PROFESSIONAL | Assessment templates `tmpl_*`; shared packs (SAST 950 / secrets 97 / DAST 91) and CWE knowledge | templates 3; CWE 63 | Data present; templates never pre-declare authorization |
| PENTESTER | Passive engagement templates `eng_*` (no offensive content) | engagement templates 2 | Data present; passive-only by design |

Shared base (all four types): packs 1732 rules, patterns 1732 (all referenced by a rule), records 1732 (every rule and every pattern now has exactly one record, including the 40 legacy rules that previously had none), remediation 1732, CWE 83.

**Honest state:** no UserType has a live app consumer from this repo. Dataset presence does not imply Main App engine or loader capability (see the language-reachability snapshot in `docs/PACKS.md`).

Tripwire line (format is load-bearing; read by `test-consistency`):

matrix-counts: devLessons=2 studentLessons=6 securityTemplates=3 pentesterTemplates=2 remediation=1732 patterns=1732 records=1732 cwe=83

**Gaps (not closed in Pump 3):**
- DEVELOPER has 2 executable lessons; a broader developer curriculum needs new lesson files, which require explicit approval (new-file rule).
- No audience field on lessons; DEVELOPER/STUDENT membership is by id prefix only. Needs owner approval (schema change).
- Pump 4 decision: DEFERRED. No schema or data change was made. Options for the owner: (a) keep id-prefix membership as the contract; (b) add an optional closed `audiences` enum to `LESSON_ALLOWED` (default STUDENT when absent; the two `lsn_dev_*` files set DEVELOPER and STUDENT). Option (b) needs owner approval for the schema change and the Main App loader must ignore or accept the field.
- SECURITY_PROFESSIONAL and PENTESTER have template-level content only; no assessment-depth content beyond the 3 + 2 templates.

## Contributing audience content

1. **Original content only** (same rule as packs): write every lesson, template, and guidance entry yourself. Never copy assessment methodologies, course content, or checklist products verbatim.
2. **Bounds are app-compatible by construction**: every bound mirrors or tightens an app constant, so validated data can never break app guards.
3. **Executable where possible**: lessons targeting pack rules must demonstrably work (validator runs them); quiz answers must point at real options; templates must use exact hostnames.
4. **Review checklist**: `npm test` green; no pre-declared authorization anywhere; no offensive content in engagements (read every line — the lint is a backstop, not a reviewer); CWE/standard ids only when certain.

## 6. Four-UserType audit (Pump 5, 2026-10-15)

Read-only audit of the four UserTypes against the working tree and the Main App (`c32c797`). Status: **PARTIAL**. The Dataset holds content for every type, but none has a live consumer from this repo.

| UserType | Checked | Result |
|---|---|---|
| DEVELOPER | `knowledge/remediation/` (1,732 files); lessons `lsn_dev_*` (2 files) | Counts match the tripwire. Remediation is shared, not forked. No app consumer. |
| STUDENT | `learning/lessons/` (5 files) | Counts match. The 2 `lsn_dev_*` lessons also sit in this set. No lesson has an `audience` or `userType` field (0 of 5), so overlap with DEVELOPER stays by design until the owner decides the audience field (§2). |
| SECURITY_PROFESSIONAL | `assessments/templates/` (3); CWE (48) | Counts match. All three templates list only `scope`: `inScopeHosts`, `outOfScopeHosts`, and notes. None pre-declares authorization. Notes say "review-only" or "passive only". |
| PENTESTER | `engagements/` (2) | Counts match. Checklists require written authorization, check that the target matches the declared scope exactly, and say that anything beyond passive reads needs a new written scope. No offensive or exploit content was found. A grep for `exploit`, `payload`, and `attack` in `engagements/` and `assessments/templates/` matched one benign triage phrase in `tmpl_api_review.json` ("exploitability notes"), and nothing else. |

Cross-check against the Main App (read-only): `packages/shared/src/authz.ts` `USER_TYPES` = `DEVELOPER`, `STUDENT`, `SECURITY_PROFESSIONAL`, `PENTESTER`. The four Dataset types match these four ids. The Main App treats UserType as classification, not authorization, and the Dataset does the same.

Shared base for all four types (current counts, 2026-10-21 recount): the numbers in the shared-base paragraph above are the recomputed figures — packs 1732 rules; patterns 1732; records 1732, every pattern referenced by exactly one record; remediation 1732; CWE 83. The 40 legacy rules that had no record before the 2026-10-19 generator fix are included.

Gaps found and left open (owner decisions, see `docs/OWNER_ACTION_REQUIRED.md` §6):
- Lesson audience field (none exists; DEVELOPER and STUDENT overlap).
- ~~Records for the 40 legacy patterns (new files would be needed).~~ **Resolved 2026-10-19** by the generator fix; 0 patterns are without a record. Owner decision D-13 stays inactive and untouched.
- No Main App consumer for any UserType. Dataset presence does not imply app capability.

**Pump 7 recheck (2026-10-15, live).** All counts above were recomputed from the working tree and match the tripwire: remediation 888, lessons 5 (2 `lsn_dev_*`), templates 3, engagements 2, CWE 48, packs 743 + 89 + 56 = 888, patterns 888, records 848. The Main App `packages/shared/src/authz.ts` `USER_TYPES` lists the same four ids, and the Main App contains 0 references to Dataset paths, so no UserType has a live consumer. Still open: the lesson audience field (owner decision), and the 40 legacy patterns without records. Status: PARTIAL, unchanged. Scope note: the "exploit" hit is the benign phrase "exploitability notes" in `tmpl_api_review.json`.

