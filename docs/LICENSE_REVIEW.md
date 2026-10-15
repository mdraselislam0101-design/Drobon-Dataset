# LICENSE_REVIEW.md — source-license verification report (2026-10-14)

Lay reading of upstream terms for triage, not legal advice. The owner (or
counsel) makes the final call before any production batch. Findings below
change **review state only**: nothing here authorizes ingestion, flips the
corpus production count (still gated on a LICENSE grant), or weakens the
production-data lock. Status key: `VERIFIED_ALLOWED` (terms text permits our
exact use - redistribution + commercial - with stated conditions),
`RESTRICTED` (usable only with material conditions/approvals resolved per
batch), `BLOCKED_UNVERIFIED` (terms not verified - do not use).

## Firewall: what a finding authorizes

- A `VERIFIED_ALLOWED` finding means: the license text was read, permits the
  use, and the evidence is linked. It does **not** mean: ingest now.
- Production ingestion still needs all four INGESTION_PLAN gates (written stage
  approval, LICENSE decision, review capacity, app provider design).
- `verifiedProduction` in CORPUS_TARGETS.json stays 0 until a LICENSE grant
  exists (machine-enforced tripwire), regardless of upstream findings.

## Summary

| Source | Terms | Redistribution + commercial | Attribution | Status |
|---|---|---|---|---|
| GHSA reviewed advisories | CC-BY-4.0 (repo LICENSE.md) | Yes, with BY conditions | Per-record sourceUrl + license note | VERIFIED_ALLOWED |
| OSV (npm+PyPI records) | Per-home-database terms (GHSA/PYSEC CC-BY-4.0; CVE-from-NVD public domain) | Yes, under each record's home terms | Per-record source + home id | RESTRICTED |
| NVD CVE | U.S. public domain (17 USC) + required notice + API ToU for keys | Yes, with notice; key needs ToU agreement | NVD notice in product | RESTRICTED |
| MITRE CWE | CWE Terms of Use (royalty-free, commercial OK, reproduce notice on copies) | Yes, with notice | Canonical link (we copy no text) | VERIFIED_ALLOWED |
| Original Drobon content | No license chosen yet | No grant exists | N/A (own work) | BLOCKED (owner decision) |

## 1. GHSA reviewed advisories — VERIFIED_ALLOWED (conditions apply)

- **Official URL:** https://github.com/github/advisory-database
- **License:** Creative Commons Attribution 4.0 International (CC-BY-4.0).
  Evidence: `gh api repos/github/advisory-database` returns
  `license.spdx_id: CC-BY-4.0`; root `LICENSE.md` holds the full CC-BY-4.0
  text; README states the database is "free and open source" (verified
  2026-10-14).
- **Redistribution + commercial:** permitted. CC-BY-4.0 allows sharing and
  adaptation, including commercially, with attribution.
- **Attribution obligations:** credit the source, link the license
  (https://creativecommons.org/licenses/by/4.0/), indicate changes. Our
  mechanism: per-record `provenance.sourceUrl` + `retrievedAt` (already on
  100/100 seed records); per-batch license note naming CC-BY-4.0 before any
  batch counts.
- **Bulk retrieval/storage/republication:** the repo license does not cap bulk
  use. Retrieval via the GitHub REST advisory API is additionally subject to
  GitHub's API Terms + rate limits (60 req/hr unauthenticated, 5000 req/hr
  with a free token - confirm at staging); a token is owner-provided, free,
  never committed.
- **Aggregation nuance:** GHSA ingests upstream databases (NVD, PyPA, RubySec,
  RustSec, ...). The root CC-BY-4.0 is the repo's grant; preserving each
  record's upstream `sourceUrl` keeps attribution intact. Batches must still
  resolve the license field per HONESTY.md review - the pointer alone is not
  the review.
- **Required notices:** CC-BY-4.0 attribution as above; no additional
  source-specific notice text is imposed by the repo.

## 2. OSV aggregated vulnerabilities — RESTRICTED (per-home terms)

- **Official URL:** https://osv.dev (API https://api.osv.dev, docs
  https://google.github.io/osv.dev, sources
  https://github.com/google/osv.dev/blob/master/source.yaml)
- **License:** no single license. OSV "aggregates data from home databases
  licensed under a variety of different open source or public domain licences"
  and "enriched records are redistributed under the same terms they are
  ingested" (maintainer statement, osv-discuss, verified 2026-10-14).
- **Our ecosystems:** OSV `source.yaml` maps npm+PyPI to home databases
  including `ghsa` (github/advisory-database, CC-BY-4.0) and `pysec`
  (pypa/advisory-database, CC-BY-4.0 per API `license.spdx_id`), plus
  programmatically converted CVE-from-NVD records (public domain, §3).
  **Every OSV batch must therefore resolve each record's home terms**
  (GHSA/PYSEC/CVE provenance) - no blanket OSV status exists.
- **Redistribution + commercial:** permitted only under the applicable home
  terms per record. Records whose home terms cannot be resolved are excluded
  from the batch (fail-closed).
- **Attribution:** per-record source + upstream home id (`sourceUrl` to the
  osv.dev entry and/or home record).
- **Bulk retrieval/storage/republication:** permitted channels are the API
  (currently no rate limit per FAQ; 32 MiB HTTP/1.1 response cap, use HTTP/2
  for large queries) and the GCS bulk dumps (`gs://osv-vulnerabilities`) with
  `modified_id.csv` for incremental sync. No SLA beyond targeted SLOs; no key
  required. Do not confuse OSV.dev with the defunct osvdb.org, whose separate
  historical license was restrictive - they are unrelated entities.
- **Withdrawn/deleted:** POST query responses already exclude `withdrawn`
  records (our importer's query path); deleted upstream records may linger
  orphaned - batches re-check withdrawn state at import time.

## 3. NVD CVE — RESTRICTED (notice + key ToU; no verified need today)

- **Official URL:** https://nvd.nist.gov (API docs
  https://nvd.nist.gov/developers/start-here)
- **License:** "All NIST publications are available in the public domain
  according to Title 17 of the United States Code" (NVD start-here page,
  verified 2026-10-14).
- **Redistribution + commercial:** permitted as public-domain data, with the
  required notice below. No NVD importer exists; no verified app consumer
  needs CVE-keyed records beyond GHSA/OSV coverage, so NVD stays UNASSESSED
  in the roadmap regardless of terms.
- **Attribution / required notice:** services using the NVD "are asked to
  display the following notice prominently within the application: 'This
  product uses data from the NVD API but is not endorsed or certified by the
  NVD.'" The NVD name may identify the source but never imply endorsement.
- **Bulk retrieval/storage/republication:** REST API 2.0; rate limits 5
  requests/rolling-30s without a key, 50 with a free API key; NVD recommends
  ~6s sleeps and incremental sync via `lastModStartDate/lastModEndDate`.
  Requesting a key requires agreeing to the NVD Terms of Use (owner action;
  key emailed, single-use activation, never committed).
- **Status rationale:** terms are permissive, but key acquisition needs an
  owner ToU agreement and no consumer need exists - RESTRICTED, not a batch
  candidate today.

## 4. MITRE CWE — VERIFIED_ALLOWED (our use needs no copying)

- **Official URL:** https://cwe.mitre.org (terms
  https://cwe.mitre.org/about/termsofuse.html, verified 2026-10-14)
- **License:** "CWE is free to use by any organization or individual for any
  research, development, and/or commercial purposes"; MITRE grants a
  non-exclusive, royalty-free license; copies must reproduce MITRE's
  copyright designation and the license. CWE is a MITRE trademark.
- **Our use:** own-words summaries + canonical definition links; no MITRE text
  is copied, so the copy-notice condition does not trigger. Even verbatim
  definition use would be permitted with the notice - but that is not needed.
- **Redistribution + commercial:** permitted under the terms above.
- **Attribution:** canonical `https://cwe.mitre.org/data/definitions/<id>.html`
  link per entry (URL shape machine-checked).

## 5. Original Drobon content — BLOCKED (owner license decision)

- No LICENSE file exists; the owner has not chosen license(s) for packs,
  remediation, lessons, templates, engagements, vectors, CWE summaries, or
  planning docs. Original expression, zero third-party copying (PACKS.md
  rule 1), but **no grant exists**, so nothing counts as verified production.
- Next step: owner records the decision in `docs/LICENSE_DECISION_RECORD.md`
  §4 and adds the grant file(s). The corpus LICENSE tripwire flips only then.

## Verification log

| Date | Source | Evidence | By |
|---|---|---|---|
| 2026-10-14 | GHSA | API `license.spdx_id=CC-BY-4.0` + LICENSE.md full text + README "free and open source" | agent lay review |
| 2026-10-14 | OSV | FAQ (dumps/incremental/no rate limit/withdrawn), source.yaml (ghsa+pysec home DBs), maintainer per-home-terms statement | agent lay review |
| 2026-10-14 | PyPA advisory-database | API `license.spdx_id=CC-BY-4.0` | agent lay review |
| 2026-10-14 | NVD | start-here: public domain + notice + rate limits + key process | agent lay review |
| 2026-10-14 | CWE | termsofuse.html: royalty-free research/development/commercial + copy notice | agent lay review |

Owner confirmation still required for every row before any production batch.
