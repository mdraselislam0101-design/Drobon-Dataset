# PROVENANCE_POLICY.md — source, authorship, evidence, review rules

Date: 2026-10-14. Provenance answers "where did this item come from, and
what proves it?" for every dataset item. Claims without evidence use the
statuses UNKNOWN, UNVERIFIED, or BLOCKED — never a guess.

## 1. Original content (packs, remediation, lessons, templates, aids, vectors, CWE summaries, docs, tooling)

- Authorship evidence is git history: `npm run provenance` reports each
  file's creation commit, date, and author. `--check` fails while any
  in-scope file is PENDING (uncommitted) — run it post-commit.
- "Original" means independently authored for this project: no copied
  vendor rules, signatures, descriptions, or corpus text, and no
  reworded derivatives of proprietary content. Security concepts and
  algorithms may inform design; text and signatures must be our own.
- New items arrive through suite-green commits: schema validation, test
  execution (patterns/checks run against their declared tests), CWE
  resolution, remediation coverage, leak scan, and count-inventory
  updates in the same commit.

## 2. Third-party reference records (vuln-intel/ real records)

- Every record carries `provenance`: source, sourceUrl (upstream entry),
  retrievedAt (UTC), and license basis. Missing or vague provenance
  fails validation.
- Pointers are not permission. Redistribution of any third-party record
  additionally requires: the source's rights review, an owner decision
  with decider + date, and open ingestion gates. All three are absent
  today, so all third-party paths are BLOCKED.

## 3. Synthetic and fixture artifacts

- Synthetic rehearsal records (`SYNTH-*`, source `synthetic-rehearsal`)
  live in tmp dirs only, never in the repo, never in manifests/counts;
  isolation is asserted on every suite run plus a repo-wide leak scan.
- `fixture: true` records use `DROBON-SAMPLE-###` ids and source
  `fixture`; grouping and inventory exclude them by flag (suite-proven).
- Secrets-detection placeholders stay inside `packs/secrets/**` with
  safety markers; the leak scan audits them separately from the strict
  repo-wide scan.

## 4. Review rules

- A human reviewer opens every `sourceUrl` for real-record batches
  (HONESTY.md); no bulk unreviewed ingest ever.
- Conflicting same-identity records quarantine for judgment, never
  auto-merge; alias decisions are recorded per batch, never inferred.
- Evidence retention: batch records, manifests, quarantine reasons, and
  gate evidence persist for the life of the corpus version they made.

## 5. Statuses

RECORDED (git evidence present), PENDING (uncommitted), UNKNOWN (no
evidence found), UNVERIFIED (claimed, unchecked), BLOCKED (must not
proceed). Unknown information is labeled, never filled in.

## 6. License-field semantics (2026-10-16 clarification)

Four distinct concepts must never be conflated (this section resolves the
wording tension between `vuln-intel/sources.json`, `docs/LICENSE_REVIEW.md`,
and `docs/LICENSE_DECISION_RECORD.md`):

1. **Per-record `provenance.license`** — a *pointer* to upstream terms text
   ("Verify terms: …"). It is evidence of where to look, never a grant.
2. **`sources.json` `licenseReview.status`** — the outcome of a *terms-text
   review* (`VERIFIED_ALLOWED` = the license text permits the use under
   stated conditions; `RESTRICTED`; `NOT_APPLICABLE`). Review is evidence,
   not authorization.
3. **`sources.json` `redistribution`** — whether redistribution for our use
   has been *authorized* (owner decision). Stays `UNVERIFIED` until the
   owner signs, regardless of any review outcome.
4. **Repository LICENSE grant** — absent today; original content is
   all-rights-reserved by default.

Invariant (test-enforced): no record or category may carry a
production-verified status while any of (2)+(3)+(4) remain unresolved for
its source. `VERIFIED_ALLOWED` review + `UNVERIFIED` redistribution is the
normal state before an owner decision and is not a contradiction.
