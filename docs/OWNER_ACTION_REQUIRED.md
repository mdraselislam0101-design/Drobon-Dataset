# OWNER_ACTION_REQUIRED.md — decisions only the owner can make

Date: 2026-10-14. Companion to `docs/OWNER_DECISIONS.json` (all 5 entries
`OWNER_DECISION_REQUIRED`) and `docs/INGESTION_GATES.json` (all 4 gates
BLOCKED). Agent research in `docs/LICENSE_REVIEW.md` is evidence, never
authorization. Nothing below is decided until the owner replies in writing;
the reply must name the decider and date so the registers can record it.

## 1. Per-source license decisions

### GHSA (reviewed advisories, npm + PyPI)
- Lay finding: CC-BY-4.0 (repository LICENSE.md); withdrawn advisories must
  be excluded; per-batch license-field resolution still required.
- Decide: (a) authorize GHSA batches for production ingestion with per-record
  CC-BY-4.0 attribution (license link + change notes)? (b) confirm scope:
  reviewed-only, withdrawn-excluded, `advisory-record` full schema fields?
  (c) counsel review needed before first batch?

### OSV (aggregated vulnerabilities, npm + PyPI)
- Lay finding: NO single OSV license — terms differ per home database.
- Decide: (a) authorize the per-record home-terms resolution policy with
  fail-closed exclusion? (b) which home terms are acceptable (e.g. only
  CC-BY-4.0 / public-domain homes)? (c) who resolves unmapped homes?

### NVD (CVE feeds)
- Lay finding: public-domain data but notice + API Terms of Use + rate limits
  (5/50 per 30s) still apply; NO verified consumer need today; no key used.
- Decide: (a) is there a verified consumer need for NVD data? If no, keep
  blocked. (b) if yes, authorize API-key acquisition under the NVD Terms of
  Use and approve the product-notice placement?

### CWE (definitions)
- Lay finding: royalty-free including commercial use, reproduce-notice on
  copies; current scope copies no MITRE text (own-words + links).
- Decide: confirm the own-words-plus-links scope needs no further clearance.

### Original Drobon content
- Fact: NO license grant exists (no LICENSE file; all rights reserved).
- Decide: choose license(s) + scope per asset class (packs, remediation,
  lessons, templates, engagements, vectors, CWE summaries, planning docs),
  then add the grant file(s) and update the decision register + matrix.

## 2. Ingestion-gate evidence

- GATE-1: written stage approval naming stage, source(s), maintainer, and
  license basis per source.
- GATE-3: named reviewer(s) + capacity statement (a human opens every
  source URL; no bulk unreviewed ingest ever).
- GATE-4 (app workstream): provider design accepted — range policy,
  zero-match semantics, config-lock amendment, consumer contract.
- Policy gap (no semantics exist yet): approval expiry / re-review cadence
  and corpus refresh cadence. Owner to set both; until then, any approval
  is single-batch and non-extending.

## 3. What stays blocked meanwhile

All production ingestion (importers exit 1), all per-category volume
promises (volumes stay null / NOT_MEASURED), and any release (NO-GO).
Synthetic rehearsals continue; they never count toward production.
