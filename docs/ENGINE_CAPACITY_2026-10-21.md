# Engine capacity — 1,000-per-engine register (2026-10-21)

> **Measured, not promised.** `node scripts/gen-engine-capacity.mjs --write` renders this page from the tree;
> `--check` runs inside `npm test`, so a count here cannot drift from the packs.

The request behind this file was "1,000 data, 1,000 patterns, 1,000 rules for every engine".
This page states where each engine actually stands, what is left, and what stops it. A row reaches
**AT_TARGET** only when the rule count really is 1,000 — never by renaming, merging or counting padding.

| Engine | Rules | Against target | Patterns | Records | Remediation | Remaining | Status |
|---|---|---|---|---|---|---|---|
| SAST | **1000** | 100% of 1000 | 1000 | 1000 | 1000 | 0 | AT_TARGET |
| DAST | **1007** | 100% of 1000 | 1007 | 1007 | 1007 | 0 | AT_TARGET |
| SECRETS | **1000** | 100% of 1000 | 1000 | 1000 | 1000 | 0 | AT_TARGET |
| SCA | **1000** | 100% of 1000 | 1000 | 1000 | 1000 | 0 | AT_TARGET |
| **Total** | **4007** | — | — | — | — | — | 4 of 4 numeric targets met |

## What blocks each engine

- **SAST** — App language catalog (53 ids) — 160 rules cannot fire (GAP-040)
- **DAST** — App response surface (11 headers) — 73 rules cannot fire (GAP-048)
- **SECRETS** — No engine gate; every rule must name the credential it detects (published token format, credential-named key, or tool-specific carrier)
- **SCA** — Dataset-side only: the App has no sca pack loader, so these declared-dependency rules cannot fire in the product; its SCA seam reads advisory records (apps/api/src/scans/sca/provider.ts) behind the production-data lock (GAP-001)

## Why the counts are not the whole story

- **Rules ≠ reachable rules.** SAST 160 and DAST 73 rules load but cannot fire in the App.
  Reachability is measured in `interop/app-dast-reachability.json` and `docs/APP_LANGUAGE_ID_MAPPING.md`.
- **Patterns ≠ rules.** Every rule links to at least one pattern, so the pattern count tracks the rule
  count by construction (`test-assets` fails on a dangling link). A pattern count above the rule count
  means multi-pattern rules, not extra coverage.
- **SCA now has both halves, kept apart.** The own-authored declaration pack (1,000 rules that
  classify what a project declares) is complete and is what this row measures; production advisory
  breadth stays at 0/100,000 behind the production-data lock and the unowned licence (GAP-001), and
  the two are never added together.
- **Secrets carries a reinstated 1,000-rule target, and the route to it is stated.** The 149
  published-format rules were kept and 851 distinct rule families were authored on top: credential-
  named keys (password, key-material, token and DSN keys), tool flags, credential headers, file
  formats and tool-invocation carriers. Each one has its own literal, pattern, record, remediation,
  declared tests and evaluation pair. The count is a count of authored rules: it does not by itself
  show detection breadth, and overlapping generic rules (`DPK-SEC-003`, `-007`, `-106`) still fire on
  many of the same literals. Nothing was relabelled to get there; the withdrawal recorded in
  `docs/SECRETS_TARGET_DECISION_2026-10-25.md` is superseded in that same file, not deleted.

## Next batches, in order of value

| Order | Engine | Batch | Why first |
|---|---|---|---|
| 1 | DAST | +90 body-evidence rules per batch (console, artefact, credential, PII families) | Largest gap that is fully inside our control; every rule is App-reachable by construction |
| 2 | SECRETS | every remaining documented single-line format, as vendors publish them | No numeric target (owner decision); the leak scanner needs a marker for every shape |
| 3 | SAST | new evidence-backed classes per batch | At target; further growth needs published evidence per class |
| 4 | SCA | further declaration classes only with new evidence | At target; growth needs a question no existing rule asks |

## Per-user-type lenses (not engines)

The four user types are audiences, not App engines: `engines.ts` closes `ScanType` to sast/sca/
secrets/dast, so no per-audience pack can be loaded. Each audience therefore gets a *lens* — the
1,000 most relevant rules from the shared packs, scored and recorded per rule. A lens adds no rule;
counting it as new content would be padding. Source: `docs/USER_TYPE_LENSES.md`.

| UserType | Selected | App-reachable | SAST | SCA | Secrets | DAST |
|---|---|---|---|---|---|---|
| DEVELOPER | **1000** / 1000 | 788 | 972 | 0 | 28 | 0 |
| STUDENT | **1000** / 1000 | 928 | 775 | 0 | 0 | 225 |
| SECURITY_PROFESSIONAL | **1000** / 1000 | 1000 | 63 | 0 | 166 | 771 |
| PENTESTER | **1000** / 1000 | 994 | 29 | 0 | 108 | 863 |

---

Verify: `node scripts/gen-engine-capacity.mjs --check`. Regenerate: `--write`.
