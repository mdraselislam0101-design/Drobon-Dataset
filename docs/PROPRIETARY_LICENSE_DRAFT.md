# PROPRIETARY_LICENSE_DRAFT.md — **DRAFT — NOT APPROVED** (not a grant)

Date: 2026-10-14 (status re-affirmed 2026-10-17). **DRAFT — NOT APPROVED.**
This is a review draft for the owner (one option of D-ORIG; the alternatives —
a named data/content license such as CC-BY-4.0, explicit all-rights-reserved,
or per-class dual licensing — are compared in
`docs/OWNER_DECISION_CHECKLIST.md` D-ORIG and packet D-1). It grants nothing,
reserves nothing beyond what the law already reserves, and takes effect only
if the owner approves it AND it is installed as the repository `LICENSE` file
together with the matrix/license-record updates the validators require.
Bracketed fields are UNKNOWN — never fill them with guesses.

## 1. Proposed license text (draft)

```
DROBON AEGIS DATASET — PROPRIETARY — ALL RIGHTS RESERVED

Copyright (c) [YEAR] [OWNER LEGAL NAME]. All rights reserved.

This dataset and its original contents (detection rules, patterns, checks,
matching logic, remediation guidance, validation framework, and accompanying
documentation created by the owner) are the proprietary property of
[OWNER LEGAL NAME].

No part of the original contents may be used, copied, modified, merged,
published, distributed, sublicensed, sold, or included in any other product
or dataset, in whole or in part, without the prior written permission of
[OWNER LEGAL NAME], except where a separate written agreement grants such
rights. All rights not expressly granted are reserved.

THIRD-PARTY CONTENT IS EXCLUDED. Records, definitions, or text sourced from
third parties (including any GHSA/OSV/NVD/CWE-derived material present for
reference) remain governed solely by their own upstream terms, notices, and
attribution requirements; this license claims no rights over them and grants
none. See NOTICE for the per-source position.

This draft is not legal advice. [GOVERNING JURISDICTION: UNKNOWN]
```

## 2. Scope: what the grant would cover (owner-controlled original content)

Packs, remediation guidance, lessons, templates, engagement aids, interop
vectors, CWE own-words summaries, planning/process docs, and dataset-side
tooling authored in this repository. Evidence of authorship: git history
per file (`npm run provenance` — 1969/1969 recorded as of 2026-10-17).

## 3. Explicitly excluded from the proprietary grant

- `vuln-intel/` real advisory records (third-party-derived; per-record
  provenance pointers; redistribution pending per-source review).
- Any upstream definitions, feeds, or bulk data ingested later (each needs
  its own rights review; gates enforce this).
- Secrets-detection placeholders and synthetic fixtures (test-only, never
  licensed content).

## 4. Blockers to finalization (all must clear)

1. Owner legal name, copyright year(s), and jurisdiction — UNKNOWN.
2. Owner written approval of this text (D-ORIG choice A or C).
3. Decision: repository stays public (verified 2026-10-14: public) while
   content is proprietary — owner must accept that a license does not make
   public bytes secret (see DATASET_ACCESS_POLICY.md).
4. Companion updates in the same commit: root `LICENSE` install, matrix
   `licenseStatus` flips with evidence, LICENSE_DECISION_RECORD rewrite,
   and the matrix LICENSE-tripwire update the validator requires.

## 5. What stays true meanwhile

No LICENSE file exists; all rights reserved by default; everything this
draft would cover is project-internal only; release stays NO-GO.
