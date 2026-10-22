# Per-user-type lenses — 1,000 rules each (2026-10-21)

> **Measured, not promised.** `node scripts/gen-user-lenses.mjs --write` renders this page and the four
> lens files; `--check` runs inside `npm test`, so a selection cannot drift from the packs.

## What a "user-type engine" can honestly be

The Main App closes `ScanType` to `sast`, `sca`, `secrets` and `dast` (`apps/api/src/engines.ts` at
`9360dd1`), so there is no per-user-type engine to load a pack. What the dataset can give each user
type is a **lens**: a deterministic selection of the 1,000 rules from the shared packs that matter most
for that audience, with the score and the reasons recorded for every one of them.

A lens is **not new content**. Writing four 1,000-rule packs would quadruple the counts while adding
zero detections — the padding `docs/PACKS.md` forbids. The same rule can legitimately serve several
audiences, and this page says so instead of counting it four times as if it were new.

## The four lenses

| UserType | Selected | App-reachable | Cutoff score | SAST | SCA | Secrets | DAST | File |
|---|---|---|---|---|---|---|---|---|
| DEVELOPER | **1000** / 1000 | 788 | 3.90 | 972 | 0 | 28 | 0 | `views/developer-v1.json` |
| STUDENT | **1000** / 1000 | 891 | 3.90 | 812 | 0 | 52 | 136 | `views/student-v1.json` |
| SECURITY_PROFESSIONAL | **1000** / 1000 | 979 | 3.70 | 431 | 0 | 97 | 472 | `views/security-professional-v1.json` |
| PENTESTER | **1000** / 1000 | 962 | 3.90 | 398 | 0 | 97 | 505 | `views/pentester-v1.json` |

Candidates: **1640** rules across the four packs. Every lens selects the top 1000, so a rule
outside a lens is not rejected as wrong — it is simply past the cutoff for that audience.

## Scoring model (authored policy, printed so it can be argued with)

`score = kindWeight + 0.5 × severityWeight + categoryAffinity + reachableBonus`; ties break on rule id.

| UserType | SAST | SCA | Secrets | DAST | Reachable bonus |
|---|---|---|---|---|---|
| DEVELOPER | 3.0 | 2.0 | 1.6 | 0.9 | 0.8 |
| STUDENT | 2.4 | 1.2 | 1.8 | 1.6 | 0.6 |
| SECURITY_PROFESSIONAL | 1.8 | 2.2 | 2.0 | 2.2 | 0.8 |
| PENTESTER | 1.4 | 0.8 | 2.2 | 3.0 | 1.0 |

Category affinities are listed per user type in `docs/USER_TYPE_LENSES.json` and in each lens file’s
`method` block. “App-reachable” reuses the measured surfaces: the 53-id App language catalog for SAST,
the 11 forwarded response headers for DAST, and the ungated secrets engine.

## What this does not claim

- No user type has a live App consumer for these lenses; the file is a dataset artefact until the App
  gains an audience filter.
- A selected rule is not a verified finding: reachability measures whether the rule *can* fire, not
  whether it fires correctly. That is the eval corpus’s job (1,888 cases, TP 1,583, FN 0, FP 1).
- SCA contributes zero rules to every lens because the SCA pack is still empty and blocked on the
  owner decision recorded in `DROBON_REMAINING_WORK.csv` (GAP-001, GAP-002).

---

Regenerate: `node scripts/gen-user-lenses.mjs --write`. Verify: `--check`.
