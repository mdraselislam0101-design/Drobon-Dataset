# SCA scope decision — original-authored only (2026-10-23)

**Decision source:** the owner answered the scope question in the interactive session on 2026-10-23.
This file records the statement; it is not legal review and it does not flip any licence state.

## What was decided

1. **"1,000 per engine" includes the four audiences.** DEVELOPER, STUDENT,
   SECURITY_PROFESSIONAL and PENTESTER each get a 1,000-rule surface. Because the Main
   App has no per-audience engine (`apps/api/src/engines.ts` closes `ScanType` to
   `sast`/`sca`/`secrets`/`dast` at `9360dd1`), that surface is a **lens** over the
   shared packs, rendered by `scripts/gen-user-lenses.mjs` into `views/*.json`
   and `docs/USER_TYPE_LENSES.md`. A lens copies no rule and claims no new detection.
2. **SCA proceeds on an original-authored schema.** SCA content will be written by us
   (advisory-shaped cases, versions, ranges and remediation), not ingested from GHSA,
   OSV or NVD. Nothing in GAP-001 or GAP-002 changes for those external sources: the
   production-data lock and the redistribution licence review stay open.

## What this does **not** authorise

- It does not authorise ingesting GHSA/OSV/NVD records, mirroring advisory text, or
  caching CVE descriptions. Those remain blocked by GAP-001 (production-data lock)
  and GAP-002 (an unowned licence).
- It does not claim real vulnerability coverage. Original-authored cases describe the
  class of dependency weakness and the version-range shape we can defend; a coverage
  number computed from them is **authored coverage**, never production advisory breadth.
- It does not change `NOT_ELIGIBLE_NO_LICENSE` (G6): the repository still has no
  `LICENSE` file.

## Consequences for the counts

| Item | Before | After |
|---|---|---|
| SCA rules | 0 (BLOCKED_OWNER) | authorable, own-authored schema only |
| `verifiedProduction` | 0 | stays 0 until a licensed source is ingested |
| Per-user-type lens | not defined | 4 × 1,000 selected rules, machine-checked |

`docs/ENGINE_CAPACITY_2026-10-21.md` keeps reporting SCA rules against the 1,000 target;
its status flips from `BLOCKED_OWNER` to `IN_PROGRESS` only when the first original-authored
batch lands, and `verifiedProduction` stays `0` in every report.
