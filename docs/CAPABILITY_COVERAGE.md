# CAPABILITY_COVERAGE.md — app capability to dataset coverage (point-in-time)

App verified read-only at `c32c797` (2026-10-14). Verdict key: `REQUIRED`
(capability needs dataset intelligence), `SUPPLEMENTAL` (app self-contained;
dataset holds loader-future extras), `NOT_REQUIRED` (evidenced absence of need),
`APP_DECISION` (needs an app-repo change, not data). Machine-checked pointers
name the script that re-verifies the claim on every run.

| Capability (app evidence) | Verdict | Dataset position | Machine check |
|---|---|---|---|
| SCA matching (`sca/provider.ts assess`) | REQUIRED | 100-record validated seed; breadth blocked | `validate.mjs`, `check-vectors.mjs` |
| SAST detection (50 self-contained rules) | SUPPLEMENTAL | 18 original rules for a planned loader | `validate-packs.mjs`, `test-packs.mjs` |
| Secrets detection (6 self-contained rules) | SUPPLEMENTAL | 7 original shape-only rules | `validate-packs.mjs`, `test-packs.mjs` |
| DAST observation (8 passive checks) | SUPPLEMENTAL | 9 original passive checks | `validate-packs.mjs`, `test-packs.mjs` |
| CWE classification (16 app-referenced ids) | REQUIRED | 17 entries (16 + pack-only 693) | `validate-cwe.mjs`, pin check |
| Remediation content (app computes status) | REQUIRED | 34/34 pack-rule entries, content-only | `validate-audiences.mjs`, consistency |
| Lessons (internal catalog, loader-future) | SUPPLEMENTAL | 3 lessons, practice validator-executed | `validate-audiences.mjs` |
| Assessment templates (loader-future) | SUPPLEMENTAL | 3 templates, never pre-authorize | `validate-audiences.mjs` |
| Engagement aids (no app consumer) | SUPPLEMENTAL | 2 standalone passive-only aids | `validate-audiences.mjs` |
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
exactly (re-verified 2026-10-14). Re-verify this table at each app re-check.
