# REVIEW_PACKAGE.md — GATE-3 independent-reviewer readiness (prepared 2026-10-17)

Status: `PREPARED — NO REVIEWER NAMED`. This document prepares what an
independent human reviewer needs; it names nobody and grants nothing. GATE-3
(`docs/INGESTION_GATES.json`) stays `BLOCKED` until a real, eligible reviewer
commits in writing (identity + capacity + HONESTY.md acknowledgment), and the
gate file is updated in the same change. **An AI/agent self-check is not
independent review** — everything below assumes a human who is not the
author of the material being reviewed.

## 1. Reviewer eligibility and capacity (from existing policy)

| Requirement | Source | What counts as evidence |
|---|---|---|
| Named human reviewer(s) | `INGESTION_GATES.json` GATE-3 passCriteria | Identity in the written commitment (name + contact/role) |
| Independent of the reviewed material | HONESTY.md review checklist; GATE-3 title | Statement that the reviewer did not author the records/rules under review |
| Capacity for the batch size | GATE-3 evidenceRequired ("no bulk unreviewed ingest ever") | "I will personally open every source URL for batches up to N records" |
| HONESTY.md checklist acknowledgment | GATE-3 passCriteria | Signed/quoted acknowledgment of `docs/HONESTY.md` review checklist |
| Continuity | `OWNER_ACTION_REQUIRED.md` §2 | Capacity statement covers the batch(es) it applies to; a new batch needs covered capacity |

## 2. Reviewer-readiness checklist (the reviewer confirms before committing)

- [ ] I have read `docs/HONESTY.md` and will execute its per-record checklist
      (open every `provenance.sourceUrl`; verify id/package/severity/ranges/
      summary against the source; verify `provenance.license`).
- [ ] I understand the machine checks in `docs/DATASET_APP_CONTRACT.md` §4 and
      that passing tests proves tested properties only — never accuracy,
      permission, or completeness.
- [ ] I have read the known-issues set: documented false positive
      (EVAL-SAST-008 / DPK-SAST-283), the 11 UNASSESSED eval cases, and the
      capability limitations in `docs/CAPABILITY_GAP_MATRIX.md` +
      `docs/DATASET_APP_CONTRACT.md` §8.
- [ ] I understand the production-data lock: verified production count is 0;
      the 100 seed files are structurally validated artifacts, not
      production-verified intelligence (`docs/COUNTING_POLICY.md`).
- [ ] I understand licensing state: no LICENSE grant exists; redistribution of
      GHSA/OSV/NVD material is UNVERIFIED; my review is evidence, never
      authorization.
- [ ] My capacity for this engagement: up to ______ records / ______ batches.
- [ ] Commitment: by ______ (name), on ______ (date).

## 3. Review package outline (what maintainers must hand the reviewer)

1. **Scope and exclusions.** Which batch(es)/asset classes are in review;
   explicitly out of scope: Main App code, production databases, deployment.
2. **Licensing and provenance.** `docs/LICENSE_REVIEW.md` (lay review),
   `docs/SOURCE_RELEASE_GATE.md` S1–S6, `vuln-intel/sources.json`,
   `docs/NOTICE`, and the provenance report (`npm run provenance`).
3. **Rule/pattern/record/remediation consistency.** Latest validator
   transcripts (`npm run validate:packs`, `validate:assets`, `validate:cwe`),
   linkage counts (rule↔pattern bidirectional), dedup report.
4. **Test results and known false positives.** Full `npm test` transcript
   (per-suite counts), `node scripts/run-eval.mjs` summary (TP/FN/FP per
   cohort), and the named FP rows with their documented cause.
5. **Unassessed synthetic evaluation cases.** The UNASSESSED id list (11
   cases) with ground-truth notes — reviewed for honesty, not scored.
6. **Production-data lock.** `docs/INGESTION_GATES.json` state,
   `requireGates()` behavior, `docs/CORPUS_TARGETS.json`
   (verifiedProductionCount = 0).
7. **Known capability limitations.** `docs/CAPABILITY_GAP_MATRIX.md`
   (NOT_IMPLEMENTED semantics, no live secret verification, passive DAST,
   0/100,000 production breadth); `DROBON_REMAINING_WORK.csv` classification.
8. **Release-gate enforcement.** `docs/RELEASE_READINESS_MATRIX.json` G-rows,
   `docs/OWNER_DECISION_PACKET.md` section E, fail-closed importer behavior.
9. **Questions for the reviewer (findings form below).**

## 4. Required reviewer findings and sign-off format

The reviewer returns exactly this shape (a filled copy is the review evidence):

```
REVIEW RECORD — DROBON DATASET
Reviewer identity: <name, role, contact>
Independence statement: <confirm: did not author the reviewed material>
Capacity covered: <N records / M batches>
Scope reviewed: <batch ids / asset classes>
Findings:
  F-<n>: <PASS | FAIL | OBSERVATION> — <subject> — <evidence ref> — <detail>
Overall: <APPROVED | REJECTED | APPROVED WITH CONDITIONS (list)>
Date: YYYY-MM-DD
Signature/acknowledgment: <how identity is verified in the owner's process>
```

Rules: findings may not contradict `docs/HONESTY.md`; a FAIL on any record
fails the batch (fail-closed); conditions never weaken a gate; the completed
record is stored verbatim and cited from GATE-3 `statusEvidence` when the gate
flips — the flip commit contains both. **No reviewer identity, signature, or
approval may be invented, simulated, or back-dated — fabrication is a defect.**
