# SCOPE.md — why this repo holds ONLY vulnerability intelligence

This document proves the dataset surface is **complete**: every place in the Drobon app that could consume external data was inventoried, and exactly one seam needs a dataset. Anything proposed for this repo that is not vulnerability intelligence must cite a new app seam — otherwise it belongs in the app repo (logic) or the database repo (persistence schemas).

Method: cloned `Drobon` (`main`, 2026-10-14) and searched `apps/*/src` + `packages/shared/src` for data seams (`dataset`, `vuln-intel`, `provider`, `catalog`, `advisory`, `CVE/GHSA/OSV/NVD/KEV/EPSS`, JSON imports, file reads, `fetch(`). Runtime `readFileSync` hits were triaged one by one: all are operational stores (user/scans/projects state), not datasets.

## Seam inventory

| # | App seam | Verdict | Evidence (Drobon `main`) |
|---|---|---|---|
| 1 | SCA vulnerability-intelligence provider: `assess(coordinates) → { providerId, datasetStatus, advisories[] }` | **DATASET — this repo** (`vuln-intel/`) | `apps/api/src/scans/sca/provider.ts` (Null provider, `NO_DATA_LOADED`); `packages/shared/src/sca.ts` (`ScaAdvisory`); `apps/api/src/config.ts:335-341` (`VULN_INTEL_PROVIDER` locked to `'none'`) |
| 2 | AI assistant provider (`AssistantProvider.generate`) | NOT data — a model-API boundary; production default is `NONE` with no credentials, no fake output | `apps/api/src/assistant/provider.ts` (`createNoAssistantProvider`); `service.ts` only reads already-persisted scan state |
| 3 | Student lessons | NOT data — hardcoded `LESSONS` const, app content | `apps/api/src/student/lessons.ts:37` (413-line module, no loads) |
| 4 | Remediation guidance | NOT data — hardcoded messages, app logic | `apps/api/src/scans/remediationGuidance.ts` |
| 5 | SAST rules (`DG-SAST-###`) | NOT data — matcher *functions* with regression tests (determinism, linear-time, conservative firing) | `apps/api/src/scans/sast/rules.ts` |
| 6 | Secrets rules (`DG-SEC-###`) | NOT data — matcher functions + redaction contract + tests | `apps/api/src/scans/secrets/rules.ts` |
| 7 | DAST rules | NOT data — passive-HTTP rule logic + tests | `apps/api/src/scans/dast/rules.ts` |
| 8 | SCA parsers / inventory / SBOM | NOT data — manifest parsing + CycloneDX emission, app logic | `apps/api/src/scans/sca/parsers.ts`, `inventory.ts` |
| 9 | Runtime stores (users, scans, projects, payments, …) | NOT data — operational persistence; future schemas belong to `Drobon-Database`, never here | `apps/api/src/*/store.ts`, `apps/api/src/auth/jsonFileUserRepository.ts` |
| 10 | Assessments | NOT data — user-created records in the runtime store | `apps/api/src/assessments/store.ts` |
| 11 | Config selectors | No other dataset switch exists — `VULN_INTEL_PROVIDER` is the only one, and it is locked | `apps/api/src/config.ts` (no other `*_PROVIDER`/`*_DATASET` env) |
| 12 | Rule packs: SAST (`DPK-SAST-*`) | **DATA — this repo** (`packs/sast/`); consumer = future app pack-loader (not yet implemented) | `docs/PACKS.md`; mirrors the app `SastRule` matcher contract (`sast/rules.ts`), lexical only |
| 13 | Rule packs: secrets (`DPK-SEC-*`) | **DATA — this repo** (`packs/secrets/`); consumer = future loader | `docs/PACKS.md`; mirrors `SecretsRule` (`secrets/rules.ts`): shape-only + denylist + redaction |
| 14 | Rule packs: DAST (`DPK-DAST-*`) | **DATA — this repo** (`packs/dast/`); consumer = future loader | `docs/PACKS.md`; mirrors `DastRuleInput` (`dast/rules.ts`): passive checks only |
| 15 | Remediation knowledge (`knowledge/remediation/`) | **DATA — this repo**; consumer = future loader merging into remediation responses | `docs/AUDIENCES.md`; mirrors `FindingRemediationGuidance` (`findings.ts`) |
| 16 | Student lessons (`learning/lessons/`) | **DATA — this repo**; consumer = future loader extending the lesson catalog | `docs/AUDIENCES.md`; mirrors `StudentLessonInternal` + shared bounds (`student.ts`) |
| 17 | Assessment templates (`assessments/templates/`) | **DATA — this repo**; consumer = future loader offering starting points | `docs/AUDIENCES.md`; mirrors Assessment bounds (`assessments.ts`); never pre-declares authorization |
| 18 | Engagement templates (`engagements/`) | **DATA — this repo**; consumer = future loader (pentester setup aids) | `docs/AUDIENCES.md`; authorized + passive only, banned-phrase lint |

## Completeness statement

`vuln-intel/` is the complete dataset surface for the Drobon app as inventoried above. Consequences:

- A new top-level data directory requires: (a) a new consumer seam in the app repo, (b) a row in the table above, (c) format + validator + tests of the same standard. No seam, no directory.
- Moving rule *logic* (rows 5–7) out of the app would break its build and ~150 engine tests; rules stay in the app by design.
- Re-verify this inventory when the app cuts releases: re-run the seam search and update the method line (date + commit).

## What "100%" means here

For the app's needs, this repo is complete when: the format mirrors the provider contract exactly (FORMAT.md), real verified data flows with provenance (importer + seed), matching behavior is pinned (interop vectors), and every change is machine-checked (validator + CI). That is the bar this repo holds itself to — not record count, which honestly grows over time and never claims completeness.
