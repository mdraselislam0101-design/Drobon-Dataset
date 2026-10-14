# HONESTY.md — no-fabrication rules

This dataset feeds security verdicts. A wrong record here becomes a wrong finding in someone's scan. These rules are absolute; anything violating them must be rejected in review even if the validator passes it.

## The five rules

1. **Verified records only.** Every non-fixture record must trace to a real, published upstream advisory (e.g. GHSA, OSV, NVD). The `provenance` block is mandatory: `source` (who published it), `sourceUrl` (https link to the exact advisory), `retrievedAt` (when we fetched it, RFC 3339). A record you cannot link is a record you do not add.
2. **Never invent identifiers.** No synthesized CVE/GHSA/OSV ids, no placeholder ids on real records. Synthetic samples use `"fixture": true` and `DROBON-SAMPLE-###` ids only, and their summaries must start with `SAMPLE FIXTURE — NOT A REAL VULNERABILITY:`.
3. **Severity comes from the source.** Copy the source-published severity; never guess, never "upgrade to be safe", never downgrade to look clean. If the source publishes no severity, do not add the record until severity is verifiable from a second authoritative source (and cite both in `provenance`).
4. **No scores, no CWE guesses, no exploitability claims.** v1 carries no CVSS/score/CWE fields — do not smuggle them into `summary`. Summaries must not claim exploitability, in-the-wild use, or KEV membership unless the linked source states it.
5. **Missing data stays missing.** An empty result for a package means "not in this dataset", never "not vulnerable". Nothing in this repo may be presented as a completeness claim.

## What the machine checks vs what humans must check

| Check | Validator (`scripts/validate.mjs`) | Human reviewer |
|---|---|---|
| Closed shape (no unknown fields) | ✅ | — |
| Bounds (lengths, counts, enums) | ✅ | — |
| `https://` URLs, RFC 3339 timestamps | ✅ | — |
| Fixture labeling (`fixture` flag ↔ id prefix ↔ `source: fixture`) | ✅ | — |
| `sourceUrl` actually resolves to the cited advisory | — | ✅ must verify |
| Severity matches the source-published severity | — | ✅ must verify |
| Range/`fixed` match the source's affected list | — | ✅ must verify |
| Summary faithfully represents the source | — | ✅ must verify |
| License terms allow redistribution (`provenance.license`) | — | ✅ must verify |

## Review checklist (every record PR)

- [ ] `npm test` passes.
- [ ] `provenance.sourceUrl` opened; advisory exists and matches `id`/`package`/`severity`.
- [ ] `affected` ranges cover exactly what the source lists — no more, no less.
- [ ] `summary` adds no claim the source does not make.
- [ ] `provenance.license` cites the upstream terms (or `TODO(license)` blocks the merge).
- [ ] No `DROBON-SAMPLE-` ids outside `*/samples/`; no real-looking ids with `"fixture": true`.

## Incident rule

If a published record is found wrong (bad range, wrong severity, dead source), fix it in a new commit that keeps the wrong version visible in git history with a `docs/` note explaining the correction. Never rewrite history to hide a bad security record.
