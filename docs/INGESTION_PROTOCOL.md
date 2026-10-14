# INGESTION_PROTOCOL.md — reproducible ingestion and deduplication plan

How production batches move from upstream to verified corpus items. This is a
plan: every run below stays blocked until the four INGESTION_PLAN gates pass.
No step here authorizes ingestion.

## 1. Per-source retrieval

| Source | Endpoint / method | Pagination | Rate limits | Incremental |
|---|---|---|---|---|
| GHSA | REST advisory API (`type=reviewed`, withdrawn excluded) via `import-ghsa.mjs` | `per_page=100`; **gap: importer fetches one page only (no Link-following) - staging must add Link pagination before breadth batches** | 60 req/hr anon, 5000 req/hr with free owner token (confirm at staging); token never committed | `sort=updated` + per-record `retrievedAt`; re-query windows, skip existing files |
| OSV | `POST api.osv.dev/v1/query` per package via `import-osv.mjs`, or GCS dumps | `page_token` loop exists (5-page cap - raise deliberately at staging) | none currently (FAQ); 32 MiB HTTP/1.1 cap - use HTTP/2 | `modified_id.csv` (per-eco + global) streamed until last-processed timestamp |
| NVD | REST API 2.0 (no importer; none needed today) | `startIndex`/`resultsPerPage` | 5 req/30s anon, 50 req/30s keyed; ~6s sleep recommended | `lastModStartDate/lastModEndDate`, poll no more than every 2h |

All retrieval is read-only, server-side, batched, and logged (source, window,
record count, importer version, operator). Failures abort the batch
(fail-closed); partial batches are discarded, never committed.

## 2. Canonical identity + deduplication

- Identity key per COUNTING_POLICY.md §1: advisory items key on
  `(source, sourceId, ecosystem, package)`; other categories key on `id`.
- Same-tuple shards (`<ID>--N.json`) are one item; `scripts/dedup-report.mjs`
  groups files into items and is cross-checked against CORPUS_TARGETS on every
  suite run (84 items in 100 files today).
- **Aliases:** the same upstream flaw under several ids (GHSA+CVE+PYSEC) counts
  once. Alias signals: OSV `aliases[]`, GHSA upstream references. FORMAT v1 has
  no `aliases` field - batches resolve aliases manually at staging and record
  the canonical choice in the batch note; a FORMAT `aliases` field is a future
  v1.x consideration, not implemented.
- Cross-source dedup runs before write: a candidate whose upstream flaw already
  exists under another source id attaches as alias metadata, never as a new item.

## 3. Normalization (source-specific)

- GHSA: reviewed-only; severity mapped low/medium/high/critical (moderate kept
  defensively); ranges in native npm/PyPI syntax, validator-enforced.
- OSV: `PyPI`→`pypi` ecosystem fold; ECOSYSTEM ranges (npm also SEMVER);
  withdrawn re-checked at import (POST queries already exclude them).
- Package names copied as canonical upstream names; normalization rules stay
  owned by the app's SCA parsers (FORMAT.md).

## 4. Provenance, license, attribution per batch

- Every record: `source`, `sourceUrl` (upstream entry), `retrievedAt` (UTC),
  resolved `license` basis. A batch whose license basis is unresolved is
  rejected whole (G5).
- Attribution: GHSA/PYSEC batches carry CC-BY-4.0 credit (source link + license
  link + change notes in the batch record); NVD use (if ever) carries the NVD
  notice; OSV records cite home terms per record.
- Batch record: source, window, count, reviewer, license basis, alias decisions
  → matrix `ingestionLog` row (schema enforced, empty today).

## 5. Integrity, versioning, rollback

- Every batch produces a SHA-256 manifest (`scripts/manifest.mjs`) over the
  corpus scopes; the manifest ships with the corpus version tag.
- Rollback = check out the prior tag, verify the manifest, re-run the suite
  (rehearsed before the first release and after tooling changes).
- Loaders/providers refuse versions whose manifest does not verify (fail-closed).

## 6. Determinism (decision recorded)

Byte-identical re-import is impossible with fresh `retrievedAt` timestamps, so
G9 compares **canonical form excluding `retrievedAt`**: two imports of the same
window must otherwise be byte-identical. Manifests hash full file bytes
(including timestamps) to detect any drift after commit.

## 7. Batch acceptance (all required)

G1 schema, G2 identifiers, G3 dedup (0 duplicate identities), G4 provenance,
G5 license resolved, G6 malformed rejection, G7 xrefs, G8 rule/FP review,
G9 determinism, G10 suite green, G11 manifest match, G12 rollback rehearsed
(first batch), G13 perf budget met. Then human HONESTY review (open every
sourceUrl) and the ingestionLog row. Only then do items count.
