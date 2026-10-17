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

## 12. Stage-approval record — GATE-1 evidence template (prepared 2026-10-17, awaiting owner)

Status: `TEMPLATE — NOT AN APPROVAL`. Nothing in this section authorizes any
action. GATE-1 (`docs/INGESTION_GATES.json`) stays `BLOCKED` until the owner
supplies a filled record with decider + date, and the gate file is updated in
the same change. A filled template is evidence; it becomes authorization only
when recorded under the policy below.

### 12.1 What one approval must specify (fill every field; blanks = invalid)

| Field | Content required | Example shape (illustrative only) |
|---|---|---|
| Approval scope | Exactly which work this authorizes: development-only, staging rehearsal, production ingestion of named batch(es), redistribution, publication — each explicitly yes/no | "production ingestion of batch GHSA-2026-001 ONLY; redistribution NO; publication NO" |
| Stage | `staging-rehearsal` or `production-batch-<id>` (never "all"/"future") | `production-batch-GHSA-2026-001` |
| Sources in scope | Named source(s) + exact endpoints/windows; unlisted sources stay prohibited | "GHSA reviewed advisories, window 2026-01-01..2026-06-30, npm+PyPI" |
| Asset classes in scope | Record classes the batch may create (e.g. `advisory-record`); everything else excluded | "`advisory-record` only" |
| Maintainer | Who executes the batch (operator identity) | name/handle |
| License basis per source | The D-2 outcome this batch relies on (per source, with evidence ref) | "D-2 C1 approved 2026-10-XX by …; CC-BY-4.0 attribution per section 4" |
| Conditions | Constraints that travel with the approval: dry-run first, batch size cap, quarantine handling, review requirements | "dry-run first; <= 500 candidates; every sourceUrl opened (GATE-3)" |
| Expiry / re-review | Explicit date or "single-batch, non-extending" (default while D-4 undecided) | "single-batch, non-extending" |
| Prohibited actions | Stated explicitly even though the defaults already prohibit them | "no production DB, no VPS upload, no App bundling, no release/tag" |
| Decider + date | Owner identity + YYYY-MM-DD; the register records exactly this | "Jane Owner, 2026-10-20" |
| Evidence ref | Where the written approval is stored (file path, ticket, signed mail archive) | "docs/owner-approvals/2026-10-20.md" |

### 12.2 Recording rules

1. The filled record is stored verbatim (never paraphrased into existence) and
   cited from `docs/INGESTION_GATES.json` GATE-1 `statusEvidence` when the gate
   flips — the flip commit contains both.
2. GATE-1 evidence alone never suffices: GATE-2 (rights), GATE-3 (reviewer),
   GATE-4 (consumer contract) must each hold their own evidence
   (`scripts/ingestion-gates.mjs` fails closed on any BLOCKED gate).
3. An approval whose expiry passes (once D-4 semantics exist) reverts to
   blocked automatically — stale approval is not silent permission.
4. No approval may authorize: Main App modification, production database
   changes, VPS upload, bundling, release/tag, or history rewriting.

## 13. Source liveness, revocation, and rights staleness (design + acceptance criteria; 2026-10-17)

Status: `DESIGN — NOT IMPLEMENTED`. No liveness checker exists today; source
terms reviews are point-in-time (`docs/LICENSE_REVIEW.md`, reviewed 2026-10-14).
This section defines what must exist before multi-batch production use and how
cadence decisions will be recorded. **BLK-004 stays open until the owner
records the cadence values.**

### 13.1 What can change and what it invalidates

| Change | Effect on retained assets | Required response |
|---|---|---|
| Upstream terms change (license, ToU) | Records ingested under the old terms are suspect; rights decision goes stale | Re-run the per-source review (`docs/LICENSE_REVIEW.md` method); quarantine new batches from that source until re-cleared; never assume grandfathering |
| Source revokes access or withdraws advisories | Provenance may become unverifiable; withdrawn advisories must be excluded | Withdrawn-check at every import (already designed); unverifiable records are quarantined, not silently kept as production |
| Reviewer/owner decision expires (per D-4 cadence) | Approvals lapse | Gate evidence marked stale; importers stay fail-closed until re-approval |
| Upstream advisory is corrected | Retained record may be wrong | Incident rule (`docs/HONESTY.md`): fix forward in a new commit, keep the wrong version visible in history with a `docs/` note |

### 13.2 Staleness detection (how "stale" becomes visible)

- Every rights review carries `reviewedAt` (already in `vuln-intel/sources.json`
  and LICENSE_REVIEW). A review older than the owner-set re-review interval is
  **stale**: the source's `redistribution` must be treated as `UNVERIFIED`
  again until re-reviewed.
- Every gate decision carries `decidedAt` (already in INGESTION_GATES).
  Approvals with expiry (D-4) past their date are stale: GATE-1 evidence no
  longer counts.
- Detection is a **manual review trigger plus a scripted date check** at batch
  time (a validator addition, not a network call): compare `reviewedAt` /
  `decidedAt` against the owner-set interval and fail the batch if stale.
  No scheduled jobs, no third-party services, no polling of upstream terms.

### 13.3 Cadence record (owner decision placeholders — UNDECIDED)

| Cadence parameter | Value | Decider | Decided at |
|---|---|---|---|
| Rights re-review interval | `UNDECIDED` (D-4) | — | — |
| Approval expiry | `UNDECIDED` (D-4; default = single-batch, non-extending) | — | — |
| Corpus refresh cadence | `UNDECIDED` (D-4) | — | — |

Cadence policy (recorded): none yet — see `docs/OWNER_DECISION_CHECKLIST.md`
D-CADENCE. This table fills only from a written owner decision naming decider
and date; nothing else may populate it.

### 13.4 Acceptance criteria (before this design counts as implemented)

1. A batch-time staleness check exists with unit tests (stale review, stale
   approval, fresh both — each outcome pinned).
2. Re-review procedure documented per source with a filled example (what was
   re-read, what changed, who signed).
3. Revocation response rehearsed synthetically (a fixture source "revoked":
   batch fails closed, retained assets flagged, quarantine path exercised).
4. All of the above stay green in `npm test`; no network dependency is
   introduced; the production lock is never weakened by the checker.

Until 1–4 are implemented and tested, source-liveness verification is
**NOT_IMPLEMENTED** — never claim otherwise.
