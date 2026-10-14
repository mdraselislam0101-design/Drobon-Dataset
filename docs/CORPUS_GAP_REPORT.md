# CORPUS_GAP_REPORT.md — category-by-category 100K gap (evidence-backed)

Date: 2026-10-14. Counts are the suite-recomputed `CORPUS_TARGETS.json`
inventory (validated-only 181). App alignment follows the in-repo capability
contract (`docs/CAPABILITY_COVERAGE.md`, app verified read-only at `c32c797`);
the app repo was not present locally in this run, so no live app re-check was
performed — re-verify that table at the next app check before using this gap
for planning. 100,000 is a quality-gated target, not a promise: no
per-category share of it is justified, so no per-category percentages are
given. Volumes from upstream are unquoted (null / NOT_MEASURED).

## Counted categories (10)

| Category | Actual | Required fields / quality | Identity + dedup | Eligible sources | License eligibility | Validation | Justified target / gap | Limitations + maintenance |
|---|---|---|---|---|---|---|---|---|
| advisory-record | 84 items (100 files, 9 multi-file tuples, 0 conflicts) | Full advisory schema + provenance + license pointer; ranges must parse | (source, id, ecosystem, package); shards collapse, conflicts flagged | GHSA reviewed; OSV per-home (both blocked) | BLOCKED: GHSA/OSV owner decisions unsigned | `validate.mjs`, vectors, SPLIT INTEGRITY | No per-category share justified; conditional ceiling 99,916 IF authorized + app-relevant + quality-held | Breadth blocked; withdrawn exclusion, per-batch license resolution, refresh cadence unset |
| sast-rule | 14 | Original rule + tests + CWE link | Rule id unique | Original authorship | BLOCKED: no grant | `validate-packs.mjs` | None justified (loader-future) | App has 50 self-contained rules; dataset holds extras only |
| secrets-rule | 6 | Original shape-only rule + safe fixtures + denylist | Rule id unique | Original authorship | BLOCKED: no grant | `validate-packs.mjs` + leak-scan fixture audit | None justified (loader-future) | App has 6 self-contained rules |
| dast-check | 8 | Original passive check + evidence | Check id unique | Original authorship | BLOCKED: no grant | `validate-packs.mjs` | None justified (loader-future) | App has 8 passive checks |
| cwe-entry | 17 | Own-words summary + canonical link | CWE id | Original summaries; MITRE links only | Summaries blocked (no grant); links per CWE terms | `validate-cwe.mjs` + pin check | Gap 0 for app need (16/16 referenced + 1 pack-only) | Coverage follows app-referenced ids |
| remediation-entry | 28 | Guidance per pack rule | Pack-rule id | Original authorship | BLOCKED: no grant | `validate-audiences.mjs` + consistency | Gap 0 (28/28 pack rules) | Grows only with pack rules |
| lesson | 3 | Practice content, validator-executed | Lesson id | Original authorship | BLOCKED: no grant | `validate-audiences.mjs` | None justified (loader-future) | Internal catalog |
| assessment-template | 3 | Template, never pre-authorizes | Template id | Original authorship | BLOCKED: no grant | `validate-audiences.mjs` | None justified (loader-future) | Internal catalog |
| engagement-aid | 2 | Standalone passive-only aid | Aid id | Original authorship | BLOCKED: no grant | `validate-audiences.mjs` | None justified (no app consumer) | Standalone |
| provider-vector | 16 | Interop contract case | Vector id | Original authorship | BLOCKED: no grant | `check-vectors.mjs` 16/16 | Gap 0 (contract-fixed set) | Changes only with the contract |

## Excluded categories (7, count 0 by policy)

| Category | Reason (contract evidence) |
|---|---|
| license-intel | Inference out of product scope |
| threat-intel / cvss-scores | No fields; lock forbids feeds |
| sbom-data | App emits CycloneDX 1.5 from its own inventory |
| package-version-metadata | No app consumer contract |
| platform-intel | Self-contained SAST patterns only |
| supply-chain-attestation | No app engine |

## Totals

- Validated-only: 181. License-cleared eligible: 0. Verified production: 0.
- Synthetic rehearsal items (never production): 1,000 + 10,000.
- Remaining to 100,000: 100,000. Release: NO-GO (see report).
