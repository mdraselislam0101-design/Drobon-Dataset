# Engine capacity — 1,000-per-engine register (2026-10-21)

> **Measured, not promised.** `node scripts/gen-engine-capacity.mjs --write` renders this page from the tree;
> `--check` runs inside `npm test`, so a count here cannot drift from the packs.

The request behind this file was "1,000 data, 1,000 patterns, 1,000 rules for every engine".
This page states where each engine actually stands, what is left, and what stops it. A row reaches
**AT_TARGET** only when the rule count really is 1,000 — never by renaming, merging or counting padding.

| Engine | Rules | / 1,000 | Patterns | Records | Remediation | Remaining | Status |
|---|---|---|---|---|---|---|---|
| SAST | **1000** | 100% | 1000 | 1000 | 1000 | 0 | AT_TARGET |
| DAST | **510** | 51% | 510 | 510 | 510 | 490 | IN_PROGRESS |
| SECRETS | **97** | 9.7% | 97 | 97 | 97 | 903 | IN_PROGRESS |
| SCA | **0** | 0% | 0 | 0 | 0 | 1000 | BLOCKED_OWNER |
| **Total** | **1607** | — | — | — | — | — | 1 of 4 at target |

## What blocks each engine

- **SAST** — App language catalog (53 ids) — 160 rules cannot fire (GAP-040)
- **DAST** — App response surface (11 headers) — 73 rules cannot fire (GAP-048)
- **SECRETS** — No engine gate; growth is evidence-gated because a token shape must be a real published format
- **SCA** — BLOCKED_OWNER: SCA content is advisory data (GHSA/OSV/NVD), and ingestion is behind the production-data lock (GAP-001) plus an unowned licence (GAP-002)

## Why the counts are not the whole story

- **Rules ≠ reachable rules.** SAST 160 and DAST 73 rules load but cannot fire in the App.
  Reachability is measured in `interop/app-dast-reachability.json` and `docs/APP_LANGUAGE_ID_MAPPING.md`.
- **Patterns ≠ rules.** Every rule links to at least one pattern, so the pattern count tracks the rule
  count by construction (`test-assets` fails on a dangling link). A pattern count above the rule count
  means multi-pattern rules, not extra coverage.
- **SCA is not a rule pack.** Its content is advisory data, which is blocked by the production-data
  lock and an unowned licence; authoring 1,000 "SCA rules" without that data would be fabrication.
- **Secrets growth is evidence-gated.** A secrets rule has to match a real, published token format;
  inventing 900 formats to reach a number is exactly the padding `docs/PACKS.md` forbids.

## Next batches, in order of value

| Order | Engine | Batch | Why first |
|---|---|---|---|
| 1 | DAST | +90 body-evidence rules per batch (console, artefact, credential, PII families) | Largest gap that is fully inside our control; every rule is App-reachable by construction |
| 2 | SECRETS | +40 provider formats per batch, each with a published specification | Real formats only; the leak scanner needs a marker for every shape |
| 3 | SAST | new evidence-backed classes per batch | At target; further growth needs published evidence per class |
| 4 | SCA | **owner decision first** | Unblock the licence + production-data lock, or the engine has no dataset to load |

---

Verify: `node scripts/gen-engine-capacity.mjs --check`. Regenerate: `--write`.
