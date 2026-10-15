# OPERABILITY_PLAN.md — performance and one-year operability plan

No zero-maintenance promise is made. This plan reduces manual work through
automation and keeps the corpus maintainable for a year of operation. All
budgets below are set at staging by measurement, not guessed here.

## 1. Performance at 100K scale (design)

- **Sharded layout.** Keep one-file-per-record; shard `vuln-intel/<eco>/` by id
  prefix once a directory exceeds the staging-measured comfort threshold
  (current walks are sorted full-tree reads - fine at seed scale, re-measure
  at 1K/10K staging).
- **Index sidecars.** Maintain a generated identity-key index per batch
  (manifest-adjacent, never hand-edited) so G3 dedup and provider matching
  avoid full-tree scans. The index is validated output, not source data.
- **Streaming validation.** Validators must stream (constant memory per file);
  no step may hold the whole corpus in memory. Memory budget: TBD at staging
  (measure peak RSS at 10K, extrapolate with headroom, pin the budget).
- **Timed gates.** G13 records wall-clock + peak RSS per gate at staged scale;
  release requires budgets met, not just green.
- **No benchmarks are claimed here.** Any number appears only after a staging
  measurement with corpus size, hardware class, and date attached.

## 2. Automated updates (design)

- **Batch cadence.** Per authorized batch (no silent auto-merge): fetch, validate
  (G1-G13), human review of severity/alias/license deltas, manifest update,
  version tag. Cadence proposal (e.g. weekly) is an owner decision at staging.
- **Version validation workflow.** Every corpus version tag carries the manifest
  + gate transcript; the loader/provider refuses versions whose manifest does
  not verify (fail-closed).
- **No data change without a gate run.** CI runs the full suite + all validators
  on every change; corpus files and planning files share the same bar.

## 3. Monitoring, alerting, rollback, recovery (design)

- **Monitoring.** Gate-pass rate, corpus size, per-batch growth, validator
  timings, manifest freshness. Thresholds set at staging.
- **Alerting.** Any gate failure, manifest mismatch, or unexpected growth spike
  pages the owner; the corpus stays pinned to the last good tag until resolved.
- **Rollback.** `git tag corpus-vX` per release + manifest; rollback = check out
  prior tag, verify manifest, re-run suite. Rehearsed before the first release
  and after any tooling change (G12).
- **Recovery.** Documented runbook: restore from tag, re-verify, re-publish.
  Recovery time objective: TBD at staging (measured during rehearsal).

## 4. Backup and restore rehearsal

- The git repository is the backup substrate (all history preserved; no
  force-push, no history rewrites on corpus branches).
- Rehearsal: clone fresh, check out the release tag, verify manifest, run the
  full suite + validators, confirm byte-identical fixture outputs. Required
  before release and yearly thereafter (record the transcript).

## 5. Repository boundaries (release-invariant)

- Dataset never bundles into the app repo or build; the app consumes only via
  the server-side provider seam (`assess(coordinates)`), after its own
  dataset-lock change - an app-repo decision, never this repo's.
- No credentials, paid keys, or subscriptions in this repo, ever.

## 6. One-year maintenance posture

Planned recurring work: batch reviews (severity/alias/license deltas), quarterly
app-re-verification (re-pin `appReferencedCwe`, re-check bounds/enums), yearly
backup rehearsal + dependency/toolchain review. Automation covers fetching,
validation, manifests, and monitoring; humans keep every judgment call.
