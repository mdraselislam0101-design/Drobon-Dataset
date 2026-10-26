# CAPABILITY_COVERAGE.md — app capability to dataset coverage (point-in-time)

App verified read-only at `9360dd1` (2026-10-21; runtime connection re-verified: all nine dataset categories load from `DATASET_PATH`, and the embedded SAST/Secrets/LESSONS sets are empty at that commit — `docs/APP_CONNECTION_VERIFICATION_2026-10-21.md`). Verdict key: `REQUIRED`
(capability needs dataset intelligence), `SUPPLEMENTAL` (app self-contained;
dataset holds loader-future extras), `NOT_REQUIRED` (evidenced absence of need),
`APP_DECISION` (needs an app-repo change, not data). Machine-checked pointers
name the script that re-verifies the claim on every run.

| Capability (app evidence) | Verdict | Dataset position | Machine check |
|---|---|---|---|
| SCA matching (`sca/provider.ts assess`) | REQUIRED | 100-record validated seed; breadth blocked | `validate.mjs`, `check-vectors.mjs` |
| SAST detection (app catalog-gated engine) | SUPPLEMENTAL | 1000 Dataset rules (`DPK-SAST-*`) load in the App (`getMergedSastRules`); **840/1000 reachable** through the App language catalog, 160 blocked by catalog families (GAP-040) | `validate-packs.mjs`, `test-packs.mjs`, `test-consistency.mjs` (reachability) |
| Secrets detection (shape-only) | SUPPLEMENTAL | 1000 Dataset rules (`DPK-SEC-*`: 149 published-format rules plus the 2026-10-25 batch of credential-key, file-format and tool-carrier families); the App loads all 1000 (`getMergedSecretsRules`) and reproduces 4,660/4,660 declared tests | `validate-packs.mjs`, `test-packs.mjs` |
| DAST observation (passive engine) | SUPPLEMENTAL | 1007 Dataset rules over 7 closed check types; the App evaluates the pack and **934/1007 are reachable** through its 11-header response surface (73 blocked, GAP-048); 3,658/3,673 declared tests agree with the App evaluator | `validate-packs.mjs`, `test-packs.mjs` (DAST evaluator rows) |
| CWE classification (app-referenced ids) | REQUIRED | 102 entries in `knowledge/cwe/`; app-referenced subset recounted 2026-10-18: **16 distinct `DG-*` CWE ids, 16/16 resolve**, 47 entries not App-referenced | `validate-cwe.mjs`, `test-consistency.mjs`, `validate-capability-coverage.mjs` |
| Remediation content (app computes status) | REQUIRED | 4007 remediation files, one per pack rule (recount 2026-10-25, SCA at 1,000 included) | `validate-audiences.mjs`, `test-consistency.mjs` |
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
| Pack/audience/provider loaders | APP_DECISION | **landed in the app 2026-10-20** (filesystem provider + pack/lesson providers); conformance gaps GAP-040…GAP-048 | docs (PACKS/AUDIENCES/PROVIDER_MAPPING), docs/APP_CONNECTION_VERIFICATION_2026-10-21.md |

No schema or compatibility changes are required on the dataset side: record
bounds, enums, and the record-to-advisory projection mirror the app contracts
(verified 2026-10-21 at `9360dd1`). Dataset counts re-derived again 2026-10-20 after the DAST capability-aligned expansion (SAST 1000; secrets 1000; DAST 1007; SCA 1000; lessons 6; pack total 4007) and pin-checked by `scripts/test-current-state.mjs`; app-side engine facts re-read at `9360dd1` on 2026-10-21 by the connection audit (docs/APP_CONNECTION_VERIFICATION_2026-10-21.md). Re-verify this table at each app re-check.

## Canonical row-level matrix (2026-10-18)

This table states per-capability verdicts. The row-level matrix with stable
`DCC-*` ids, asset references, relationships, evaluation evidence, rights and
integration status is `docs/CAPABILITY_COVERAGE_MATRIX.json` (rendered to
`docs/CAPABILITY_COVERAGE_MATRIX.md`) and is gated by
`scripts/validate-capability-coverage.mjs`. Summary at 2026-10-21 (App `9360dd1`):
33 rows — 2 COVERED_VERIFIED, 7 PARTIAL (integration verified, measured gaps open),
1 RIGHTS_BLOCKED (SCA production intelligence), 1 OWNER_DECISION_BLOCKED (the App's new
active-DAST surface), 22 NOT_APPLICABLE. A capability is never marked covered from rule counts alone,
and an App implementation gap is not recorded as a Dataset defect.
