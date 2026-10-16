# INGESTION_PROTOCOL.md — reproducible ingestion and deduplication plan

How production batches move from upstream to verified corpus items. This is a
plan: every run below stays blocked until the four INGESTION_PLAN gates pass.
No step here authorizes ingestion.

## 1. Per-source retrieval

| Source | Endpoint / method | Pagination | Rate limits | Incremental |
|---|---|---|---|---|
| GHSA | REST advisory API (`type=reviewed`, withdrawn excluded) via `import-ghsa.mjs` | `per_page=100`; Link pagination implemented (`--max-pages`, default 10, cap 50; repeated-cursor guard; checkpoint/resume via tmp cursors) — recount 2026-10-16 replaced the earlier "one page only" note | 60 req/hr anon, 5000 req/hr with free owner token (confirm at staging); token never committed | `sort=updated` + per-record `retrievedAt`; re-query windows, skip existing files |
| OSV | `POST api.osv.dev/v1/query` per package via `import-osv.mjs`, or GCS dumps | `page_token` loop with `--max-pages` (default 5, cap 20 - raise deliberately at staging) | none currently (FAQ); 32 MiB HTTP/1.1 cap - use HTTP/2 | `modified_id.csv` (per-eco + global) streamed until last-processed timestamp |
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
## 8. Retry, backoff, checkpointing, idempotent recovery (design)

- Retrieval retries transient failures only (network reset, 429, 5xx):
  max 5 attempts, exponential backoff 2s/4s/8s/16s/32s + jitter, then the
  batch aborts fail-closed. 4xx (except 429) and schema violations never
  retry - they quarantine the item (see section 9).
- Checkpointing: the importer appends completed page/window cursors to
  `ingest-checkpoint-<batch>.json` (tmp, never committed) after every page.
  A re-run resumes from the last cursor; already-written candidate files are
  content-compared, never blindly overwritten (idempotent re-run).
- Crash recovery procedure: re-run the same command; verify resumed output
  against the checkpoint log; re-validate the full batch; any divergence
  discards the batch. Recovery is rehearsed synthetically (test-rehearsal
  section 4) before any authorized batch.

## 9. Rejection and quarantine (design)

- Every candidate lands in exactly one bucket: accepted, rejected
  (schema/identity/range/link failure), duplicate (existing canonical item),
  quarantined (needs human judgment: conflicts, ambiguous alias, license
  doubt), or unresolved (upstream fetch failed after retries).
- Quarantine location: `quarantine/<batch>/<source>-<id>.json` plus a
  `quarantine/<batch>/REASONS.md` row per item (never counted, never
  shipped; reviewed at staging, then accepted or deleted with a note).
- Counts per bucket ship in the batch record; accepted = 0 is a valid
  outcome and still produces a manifest + log row.

## 10. Resource budgets and hostile input (design, draft defaults)

- Proposed staging defaults (calibrate at staging, then pin): one batch
  <= 500 candidates, <= 10 minutes wall-clock, <= 512 MB RSS; a batch
  exceeding any ceiling aborts fail-closed and splits.
- Hostile/malformed input: upstream JSON is parsed with size caps (single
  response <= 8 MB, single string field <= bounds in FORMAT.md); control
  characters, overlong fields, unknown properties, and bad ranges reject
  the item (G6) with the reason logged; nothing upstream is executed,
  interpolated into shell, or written outside the batch dir.
- No credentials in logs: tokens pass only via environment at staging,
  are redacted from every log line, and the leak scan (consistency
  section 13) runs before every commit.

## 11. Synthetic separation and audit retention (design)

- Synthetic rehearsal records (`SYNTH-*`, source `synthetic-rehearsal`)
  live in tmp dirs only, are excluded from every manifest/count, and are
  proven absent from production by the isolation asserts on every run.
- Audit retention: batch records, manifests, quarantine reasons, and gate
  evidence stay in-repo (or attached to the release tag) for the life of
  the corpus version they produced; checkpoint tmp files are deleted after
  the batch verifies. Approval expiry and refresh cadence are owner-set
  (see OWNER_ACTION_REQUIRED.md section 2); until set, approvals are
  single-batch and non-extending.
