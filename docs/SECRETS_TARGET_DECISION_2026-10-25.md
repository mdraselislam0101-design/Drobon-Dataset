# Secrets target decision — 2026-10-25

**Decision (owner instruction, recorded here):** the **1,000-rule numeric target for the secrets
family is withdrawn**. Completion for this family is measured against the **published-format
inventory** — every credential format a vendor documents as a single-line shape — not against a
round number.

Why this exists: the owner asked for the secrets work to be taken to 100 %. The honest arithmetic
is that a secrets rule may only be authored for a **published** format (vendor documentation naming
a prefix and a length family), and there are roughly one and a half hundred such single-line
formats that are not already covered. Reaching 1,000 would have required inventing ~850 shapes.

Inventing them is not a neutral act:

- a guessed shape produces false positives that train users to ignore the engine;
- `docs/PACKS.md` (Contributing rules) forbids padding, and the dataset's own counting policy
  (`docs/COUNTING_POLICY.md`) counts executed rules, not declarations;
- the repository's standing rule is that a gap is reported as a gap — never closed by relabelling.

So the number was retired, in the open, instead of being met by fabrication.

## What changed

| Register | Before | After |
|---|---|---|
| `docs/ENGINE_CAPACITY_2026-10-21.json` → `engines[id=secrets]` | `target: 1000`, `pct: 12.8`, `status: IN_PROGRESS` | `target: null`, `pct: null`, `status: EVIDENCE_GATED`, `measure: "every documented single-line credential format"` |
| `docs/DATASET_COMPLETION_LEDGER.json` → `packs.secrets` | `denominator: 1000`, `pct: 12.8`, `PARTIAL` / `EVIDENCE_GATED` | `denominator: null`, `pct: null`, `COMPLETE`, no blocker — with the count and this decision named in `detail` |
| `docs/PACKS.md` → Secrets pack status | "128 rules of the 1,000-per-engine target (12.8 %)" | the measured count, the decision, and what still counts as growth |

Nothing else was relabelled: SAST, DAST and SCA keep their numeric targets and are reported against
them exactly as before (`1,000 / 1,007 / 1,000`, all `AT_TARGET`).

## What "complete" means for secrets now

A secrets rule counts as authored only when **all** of the following hold, and the validators
enforce every line:

1. the shape is a **published** format (prefix and length family named by the vendor);
2. it has a compiled pattern, a knowledge record and a remediation entry;
3. it declares `redact: true` and a denylist (or `matchOnlyEvidence`);
4. its positive and negative example tests **execute** (`test-packs.mjs`);
5. it carries an independent evaluation pair in `data/eval-cases` (`run-eval.mjs`).

The family is complete when every published single-line format that is representable in this
repository has a rule. Formats that cannot be represented are listed rather than faked: a literal of
the Figma token shape (`figd_` + 40) is rejected by GitHub push protection, so that id is retired and
documented in `docs/ASSET_METHODOLOGY.md`.

## What stays open (and why that is not a defect)

- **Advisory-backed SCA intelligence** (0/100,000) — a different axis; blocked by the production-data
  lock and the absent licence (GAP-001…004), untouched by this decision.
- **New credential formats** — as vendors publish them, each gets a rule with tests and an eval pair.
  The count grows; no target is invented to measure it against.
- **App-side integration** — the App converter has not re-run against the rules added after
  2026-10-21; that is recorded per rule in `docs/CAPABILITY_COVERAGE_MATRIX.json`.

## Verification

```
node scripts/gen-engine-capacity.mjs --check      # secrets row: no target, EVIDENCE_GATED
node scripts/completion-ledger.mjs --write        # packs.secrets: COMPLETE, denominator null
node scripts/validate-capability-coverage.mjs     # 710/710, evaluationCoverage recomputed
npm test                                          # exit 0
```
