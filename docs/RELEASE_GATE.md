# RELEASE_GATE.md — pre-publish release gate (all NO-GO until evidenced)

The application must NOT be publicly published until every gate below is GO
with evidence. Status key: `GO` (evidenced), `NO-GO` (not met), `N/A-DATASET`
(owned by another workstream; tracked here so nothing is forgotten).

| # | Gate | Owner | Status | Evidence required |
|---|---|---|---|---|
| R1 | App capabilities + engines complete and verified | App | N/A-DATASET | app workstream sign-off |
| R2 | Database integration + migrations verified | Database | N/A-DATASET | database workstream sign-off |
| R3 | Dataset-to-app integration verified (provider seam live) | App+Dataset | NO-GO | end-to-end `assess(coordinates)` against loaded data |
| R4 | >=100,000 unique, licensed, validated production items | Dataset | NO-GO | `CORPUS_TARGETS.json` verifiedProduction >= 100000 |
| R5 | Unit/integration/security/regression/e2e tests green | All | NO-GO | transcripts per workstream |
| R6 | Performance/load tests at realistic dataset scale | All | NO-GO | G13 budgets met at staged scale |
| R7 | Backup + restore rehearsed | Dataset | NO-GO | rehearsal transcript (OPERABILITY_PLAN §4) |
| R8 | Automated update + version-validation workflow live | Dataset | NO-GO | workflow run history + fail-closed refusal demo |
| R9 | Monitoring/alerting/rollback/recovery documented + live | All | NO-GO | dashboards + runbook + rehearsal |
| R10 | Repository-boundary checks pass (no bundling, no leaks) | Dataset | NO-GO | boundary audit transcript |
| R11 | Zero unresolved critical release blockers | All | NO-GO | empty critical-blocker list, reviewed |

Current release verdict: **NO-GO** (R4 at 0/100,000 verified production;
B-license, B-datalock, B-design open). This file flips to GO only row by row,
each with linked evidence - never by declaration.
