# CAPABILITY_COVERAGE.md — app capability to dataset coverage (point-in-time)

App verified read-only at `c32c797` (2026-10-14; engine facts re-verified 2026-10-16: SAST 50 / Secrets 6 / DAST 8 app rules recounted from `rules.ts`, `VULN_INTEL_PROVIDER` lock and absence of pack loaders re-confirmed). Verdict key: `REQUIRED`
(capability needs dataset intelligence), `SUPPLEMENTAL` (app self-contained;
dataset holds loader-future extras), `NOT_REQUIRED` (evidenced absence of need),
`APP_DECISION` (needs an app-repo change, not data). Machine-checked pointers
name the script that re-verifies the claim on every run.

| Capability (app evidence) | Verdict | Dataset position | Machine check |
|---|---|---|---|
| SCA matching (`sca/provider.ts assess`) | REQUIRED | 100-record validated seed; breadth blocked | `validate.mjs`, `check-vectors.mjs` |
| SAST detection (app catalog-gated engine) | SUPPLEMENTAL | 792 Dataset rules (`DPK-SAST-*`); 549 fully reachable by Main App catalog ids + 11 any-file (omitted `languages`), 207 with no analyzed tag (PACKS.md, Phase 4 recount) | `validate-packs.mjs`, `test-packs.mjs`, `test-consistency.mjs` (reachability) |
| Secrets detection (shape-only) | SUPPLEMENTAL | 97 Dataset rules (`DPK-SEC-*`; recount 2026-10-17 Phase 9, DPK-SEC-108 added); no app secrets pack consumer | `validate-packs.mjs`, `test-packs.mjs` |
| DAST observation (app: 8 hard-coded `DG-DAST-001..008` in `apps/api/src/scans/dast/rules.ts`, code not data) | SUPPLEMENTAL | 65 Dataset rules over 7 closed check types (recount 2026-10-16; loader-future; no app consumer of `packs/dast`) | `validate-packs.mjs`, `test-packs.mjs` (DAST evaluator rows) |
| CWE classification (app-referenced ids) | REQUIRED | 61 entries in `knowledge/cwe/` (count re-derived in Batch 1; app-referenced subset NOT re-counted) | `validate-cwe.mjs`, `test-consistency.mjs` |
| Remediation content (app computes status) | REQUIRED | 954 remediation files, one per pack rule (recount 2026-10-17 Phase 9) | `validate-audiences.mjs`, `test-consistency.mjs` |
| Lessons (internal catalog, loader-future) | SUPPLEMENTAL | 6 lessons (2 `lsn_dev_*`, 4 `lsn_pack_*`), practice validator-executed | `validate-audiences.mjs` |
| Assessment templates (loader-future) | SUPPLEMENTAL | 3 templates, never pre-authorize (count re-derived Pump 4) | `validate-audiences.mjs` |
| Engagement aids (no app consumer) | SUPPLEMENTAL | 2 standalone passive-only aids (count re-derived Pump 4) | `validate-audiences.mjs` |
| SBOM data | NOT_REQUIRED | app emits CycloneDX 1.5 from inventory | - (absence re-grepped per audit) |
| License intelligence | NOT_REQUIRED | inference out of product scope | - |
| CVSS / threat intel / KEV / EPSS | NOT_REQUIRED | no fields; lock forbids feeds | - |
| Platform intel (framework/cloud/IaC/auth/...) | NOT_REQUIRED | self-contained SAST patterns only | - |
| Supply-chain attestation | NOT_REQUIRED | no app engine | - |
| Assistant knowledge | NOT_REQUIRED | deterministic over persisted state | - |
| Report content | NOT_REQUIRED | pure renderers | - |
| Zero-match semantics | APP_DECISION | `ScaDatasetStatus` has no "clean" value | - (app-repo design) |
| Pack/audience/provider loaders | APP_DECISION | contracts documented, no loaders exist | docs (PACKS/AUDIENCES/PROVIDER_MAPPING) |

No schema or compatibility changes are required on the dataset side: record
bounds, enums, and the record-to-advisory projection mirror the app contracts
(verified 2026-10-14 at `c32c797`; NOT re-verified in Pump 4). Dataset counts re-derived again 2026-10-16 (secrets 96 with DPK-SEC-106/107 (Phase 5 probe-gap closure); lessons 6); app-side engine facts re-read at `c32c797` the same day (counts above corrected where stale). Re-verify this table at each app re-check.
