# COUNTING_POLICY.md — unique-item counting and deduplication policy

This policy defines what counts toward the 100,000-item corpus target. It is
enforced by `scripts/validate-corpus.mjs` wherever the rule is machine-checkable
(counts recomputed from files; production claims gated on a LICENSE grant;
volumes unquotable until measured). Everything else is enforced by review.

## 1. Identity rules (one item per identity)

| Category | Identity = one item | Rationale |
|---|---|---|
| `advisory-record` | `(source, sourceId, ecosystem, package)` | The provider matches `(ecosystem, package, version)`; the advisory-package pair is the matchable unit. |
| `sast-rule` / `secrets-rule` / `dast-check` | rule `id` | One tested detection unit. |
| `cwe-entry` | CWE `id` | One weakness definition. |
| `remediation-entry` | `ruleId` | One guidance unit per pack rule. |
| `lesson` / `assessment-template` / `engagement-aid` | `id` | One authored content unit. |
| `provider-vector` | VEC `id` | One pinned matching expectation. |

No category is required to reach 100,000 alone. The target is at least 100,000
genuinely distinct, useful, validated production items in total.

## 2. Aliases are never new items

The same upstream flaw reported under several ids (GHSA + CVE + OSV) or several
spellings counts **once**, under its canonical identity. Which id is canonical
is decided per batch at staging (prefer the most specific upstream id; record
aliases as metadata on the single item, never as sibling items).

## 3. Splits, versions, and packages

- `<ID>--N.json` split files are storage shards of one advisory-package item,
  not separate items (they share the identity key by construction).
- One advisory affecting several packages = one item **per package** (each pair
  matches different coordinates). One advisory with several affected ranges for
  the **same** package = one item (ranges are match data, not identity).
- Re-harvesting the same source id twice (re-import, re-crawl) must dedup to
  the existing item; the importer skips existing files and the suite rejects
  exact-duplicate `affected` entries.

## 4. Verified production (the only count that matters for 100K)

An item counts as **verified production** only when all four hold:

1. **Schema-valid** - passes the repo validators and the full suite.
2. **Deduplicated** - unique under §1 after alias resolution (§2).
3. **License-verified** - redistribution permitted by reviewed terms (records)
   or by the repo LICENSE grant (original content). Unverified = not production.
4. **Provenance-complete** - source, sourceUrl, retrievedAt (records) or
   in-repo authorship with tests (original content).

Anything else is **validated-only**, **seed**, **estimate**, or **excluded** -
reported separately, never summed into the production count.

## 5. Never counted

Duplicates, aliases re-counted as new items, placeholders, empty records,
synthetic test fixtures (always `DROBON-SAMPLE-` / `test/`, excluded by every
counter), repeated metadata minted to inflate the count, unverified data,
prohibited data (threat intel, exploit material), and improperly licensed data.

## 6. Estimate quarantine

Source-volume estimates live only in `docs/SOURCE_ROADMAP.json` with an explicit
labeled basis, and `volumeEstimate` must stay `null` until measured at staging.
Estimates are never added to verified counts, never averaged into progress, and
never quoted without the word "estimate" and the measurement basis.

## 7. Recount procedure

Every COUNTED `validatedCount` in `docs/CORPUS_TARGETS.json` is recomputed from
repository files by the validator on every run. `verifiedProduction` totals are
sums of per-category claims, each gated on the LICENSE tripwire. A claim that
disagrees with recomputation fails the suite - counts cannot go stale silently.
