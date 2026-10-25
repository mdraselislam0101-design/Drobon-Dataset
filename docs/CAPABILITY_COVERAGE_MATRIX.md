# CAPABILITY_COVERAGE_MATRIX.md — Main App capability ↔ Dataset coverage (generated)

Generated from `docs/CAPABILITY_COVERAGE_MATRIX.json` by `scripts/render-capability-coverage.mjs`.
Do not edit by hand; edit the JSON and re-render.

As of **2026-10-21**. Main App reference: `mdraselislam0101-design/Drobon` @ `9360dd1abdf940cc1bffd942aab0702703aaaaef` (read-only shallow clone (npm ci + npm run build --workspace @drobon/shared, both exit 0) plus executable probes of the dataset providers; no Main App file, test, config or history was modified).

> Canonical Main App capability <-> Dataset coverage matrix. Statuses are evidence-backed; blocked, partial and unassessed work is never counted as covered. Dataset assets never ship inside the Main App.

Rows: **33** · Dataset-relevant: **10** · COVERED_VERIFIED **2** · PARTIAL **7** · RIGHTS_BLOCKED **1** · OWNER_DECISION_BLOCKED **1** · NOT_APPLICABLE **22**

Status vocabulary (closed): `COVERED_VERIFIED`, `PARTIAL`, `MISSING`, `APP_INTEGRATION_BLOCKED`, `RIGHTS_BLOCKED`, `OWNER_DECISION_BLOCKED`, `NOT_ASSESSED`, `NOT_APPLICABLE`.

## 1. Capability inventory and coverage

| ID | Capability | Dataset requirement | Coverage status | Integration | Remaining work |
|---|---|---|---|---|---|
| `DCC-AUTH-SESSION` | Registration, session and UserType classification | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-PLAN-ENTITLEMENT` | Plan, entitlement, quota and rate limits | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-PROJECTS` | Projects, uploaded source snapshots and lifecycle | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-SCAN-JOBS` | Scan orchestration, job lifecycle and worker processing | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-SAST` | SAST detection engine (App engine + Dataset pack rules) | SUPPLEMENTAL | **PARTIAL** | INTEGRATED | App loader conformance and language-id reachability: the packs use 115 language ids, the App catalog resolves 47 of them directly and 2 through aliases, and 66 need a new App family, so 160 of 950 rules can never fire today (docs/APP_LANGUAGE_ID_MAPPING.md, GAP-040). The App also does not execute declared rule tests at load, has no ReDoS regression over pack patterns and puts no pack id/version on findings (GAP-042). Dataset-side eval depth is incomplete too: 60 SAST rules have no positive evaluation case and 746 have no negative control one |
| `DCC-SCA-INVENTORY` | SCA dependency inventory and CycloneDX SBOM | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-SCA-VULN` | Dependency vulnerability assessment (advisory matching) | REQUIRED | **RIGHTS_BLOCKED** | INTEGRATED | Rights and breadth: no LICENSE grant, redistribution unverified per source, 0/100,000 verified production records. Two contract details also need alignment: the App status surface reports the raw file count (100) instead of the canonical 84 items / 78 ids, and a zero-match coordinate maps to scan-level NOT_ASSESSED even when the dataset answered (GAP-043) |
| `DCC-SECRETS` | Secrets detection engine (App engine + Dataset pack rules) | SUPPLEMENTAL | **PARTIAL** | INTEGRATED | App loader conformance: no load-time execution of declared tests, no ReDoS regression, no pack id/version on findings, and the 97 dataset rules are now the only secrets rules (the App embedded set is empty, so an unconfigured dataset detects nothing) — GAP-042/GAP-046 |
| `DCC-DAST` | Passive DAST engine (App engine + Dataset pack rules) | SUPPLEMENTAL | **PARTIAL** | INTEGRATED | App evaluator diverges from this repo on 15 of 1,846 declared DAST tests (App-evaluator profile) (9 rules: Set-Cookie discard/flag-parse cases in DPK-DAST-004/006/008, blank-value header handling in DPK-DAST-002, cross-value array joins) because apps/api/src/external/evaluator.ts is a simplified re-implementation of scripts/lib/set-cookie.mjs; load-time test execution is absent (GAP-041/GAP-042). The App also added active DAST + a payload catalog, which conflicts with both repos' written passive-only boundary (GAP-045) |
| `DCC-FINDINGS` | Finding evidence, lifecycle, notes and verification workflow | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-REMEDIATION` | Remediation guidance per pack rule | REQUIRED | **COVERED_VERIFIED** | CONTRACT_READY_NOT_INTEGRATED | Dataset content is complete (2,104/2,104). The App service loads all 2,104 entries, but nothing consumes them: getRemediationMap has no caller and remediationGuidanceForFinding still returns UNAVAILABLE, so users see no dataset guidance (GAP-041) |
| `DCC-CWE` | CWE classification reference | REQUIRED | **COVERED_VERIFIED** | CONTRACT_READY_NOT_INTEGRATED | Dataset content is complete (68/68 resolvable). The App loads all 68 entries but getCweMap has no caller, so CWE reference text never reaches findings or reports (GAP-041) |
| `DCC-REPORTS` | Reports, exports (JSON/Markdown/SARIF) and SBOM delivery | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-ASSISTANT` | Project-scoped deterministic assistant | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-ADMIN-PAYMENTS` | Administration, payments and partner programme | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-ACCOUNT-LIFECYCLE` | Account enabled/disabled lifecycle | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope); App-side feature decision only |
| `DCC-DEV-WORKSPACE` | Developer workspace and manual scan/report flow | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-DEV-GITCI` | Live Git hosting / CI provider integration | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope); App-workstream decision only |
| `DCC-STUDENT-WORKSPACE` | Student explanations, next steps and progress/history | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-LESSONS` | Learning-path lesson content (audience dataset) | SUPPLEMENTAL | **PARTIAL** | INTEGRATED | The App merges the 6 dataset lessons through lessonProvider (the embedded catalog is now empty), so the API returns 6, not the 10 claimed in docs/DATASET_CONNECTION.md; no App test asserts the merged catalog (GAP-041) |
| `DCC-STUDENT-CWE-ENC` | Student CWE encyclopedia navigation | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope); App product decision only |
| `DCC-PRO-ASSESSMENT` | Security Professional assessment planning and lifecycle | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-ASSESSMENT-TEMPLATES` | Assessment templates (audience dataset) | SUPPLEMENTAL | **PARTIAL** | CONTRACT_READY_NOT_INTEGRATED | The App loads the 3 templates and reports them on GET /api/v1/dataset/status, but no assessment-create picker consumes them yet (GAP-041) |
| `DCC-PENTEST-DAST` | Pentester passive DAST presentation | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-ENGAGEMENTS` | Passive-only engagement aids (audience dataset) | SUPPLEMENTAL | **PARTIAL** | CONTRACT_READY_NOT_INTEGRATED | The App loads the 2 passive engagement aids and reports them on the status surface, but no workflow consumes them yet (GAP-041) |
| `DCC-INTEROP` | Provider interop contract vectors | SUPPLEMENTAL | **PARTIAL** | CONTRACT_READY_NOT_INTEGRATED | The App re-implemented the range semantics as apps/api/src/scans/sca/range.ts (541 lines) and never reads interop/provider-vectors.json, so the pinned vectors do not guard the App. Either the App runs the vectors as a conformance test or the two range implementations must be kept in lockstep by a shared fixture (GAP-044) |
| `DCC-THIRD-PARTY-AUTH` | Third-party permission / DAST authorization recordkeeping | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-EXPLOIT-RESERVED` | Exploit PoC, payload library, vulnerability chaining, custom attack scripts | NONE | **OWNER_DECISION_BLOCKED** | NOT_APPLICABLE | The App added apps/api/src/scans/dast/{activeEngine,crawler,payloads}.ts at 9360dd1: crawl + a bounded XSS/SQLi/redirect/traversal/CRLF payload catalog behind a consent gate. Both repositories' written boundaries (docs/SCOPE.md, docs/PACKS.md, CORPUS_TARGETS.json dcc-exploit-reserved) say active probing and payload libraries are out of scope. Owner must either revert the App feature or authorize it with a written consent/authorization model, rate-limit evidence and a boundary-document amendment (GAP-045) |
| `DCC-CVSS-KEV-EPSS` | CVSS scoring, KEV and EPSS enrichment | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope); would require an App contract change plus an owner decision |
| `DCC-COMPLIANCE-MAPPING` | Compliance framework mapping (PCI/ISO/OWASP) dashboard | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope); App product decision only |
| `DCC-SUPPLY-CHAIN` | Supply-chain attestation / provenance verification | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-LICENSE-INTEL` | Dependency license intelligence | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope) |
| `DCC-THREAT-MODEL` | Threat modelling (STRIDE / attack trees) | NONE | **NOT_APPLICABLE** | NOT_APPLICABLE | none (Dataset scope); App product decision only |

## 2. Dataset-relevant rows — assets, relationships, evidence, rights

### DCC-SAST — SAST detection engine (App engine + Dataset pack rules)

- Status: **PARTIAL** (basis: `APP_CONSUMER_VERIFIED_WITH_GAPS`); requirement: SUPPLEMENTAL; integration: INTEGRATED.
- Contract: drobon.pack.sast/v1 rule packs: lexical line rules with executable positive/negative examples, rule-fixed severity, CWE mapping, remediation 1:1, and an omitted-languages convention for any-file rules.
- Assets: `packs/sast/v1/rules` — 1000 (*.json rule files); `knowledge/patterns` — 2171 (*.json pattern files (all families)); `knowledge/remediation` — 2171 (*.json remediation files (all families)).
- Relationships: rule.patternRefs <-> pattern.linkedRules: 1310/1310 both directions, 0 dangling; 1310/1310 rules have a remediation entry keyed by ruleId; every rule CWE resolves in knowledge/cwe.
- Evaluation: pack-tests: all 950 SAST rules execute >=1 positive and >=1 negative example; independent evaluation recount (2026-10-21): 812 SAST cases (807 assessed, 5 UNASSESSED); 890 rules appear in a positive detection; 499 rules appear as a forbidden detection in a negative case. Cases are counted by their EVAL-SAST-* namespace; a rule is counted positive only when it is named in expected.detections of such a case. The machine-checked numbers live in evaluationCoverage; dataset-wide: 1,876 cases naming all 2,104 pack rules; 1,437 rules appear in a positive detection across the three engines and 1,014 also appear as a forbidden detection in a negative control; preserved failure: EVAL-SAST-008 (1 FP, docstring trap - a lexical rule cannot see Python string context); 11 UNASSESSED cases kept out of scoring; App-side verified 2026-10-21: all 950 rules convert and merge into the App engine (getMergedSastRules) and 3,843/3,843 declared SAST tests reproduce through the App converter (0 mismatches); reachability measured 2026-10-21 and machine-gated: scripts/validate-app-language-ids.mjs (147 assertions) pins every id to the App catalog, an alias, or a missing-family declaration.
- Production eligibility: `NOT_ELIGIBLE_NO_LICENSE`; rights: `NO_GRANT_ALL_RIGHTS_RESERVED`; owner decision: none for Dataset content.
- Verification: `npm run validate:packs`, `node scripts/test-assets.mjs`, `node scripts/test-consistency.mjs`, `npm run test:eval`, `npm run eval:coverage`.

### DCC-SCA-VULN — Dependency vulnerability assessment (advisory matching)

- Status: **RIGHTS_BLOCKED** (basis: `ASSET_VALIDATED_PRODUCTION_BLOCKED`); requirement: REQUIRED; integration: INTEGRATED.
- Contract: drobon.vuln-intel/v1 advisory records with closed schema (id/severity/summary/url bounds), identity (source, id, ecosystem, package), parseable version ranges, source provenance and license pointer; provider seam assess(coordinates) -> datasetStatus + advisories.
- Assets: `vuln-intel/npm` — 50 (real *.json advisory files (samples/ excluded)); `vuln-intel/pypi` — 50 (real *.json advisory files (samples/ excluded)); `interop/provider-vectors.json` — 16 (pinned vector cases).
- Relationships: 100 files collapse to 78 advisory ids and 84 identity items; 9 multi-file shards; 0 conflict tuples; 16/16 provider vectors pin coordinate -> advisory behaviour including zero-hit cases.
- Evaluation: npm run validate: 103 files (100 real + 3 labelled fixtures), 0 errors; npm run test:vectors: 16/16; npm run dedup-report: 0 conflict tuples; production matching: 0 verified production records; no live provider exists; App read-only test pins the seam: Null provider -> NOT_ASSESSED / NO_DATA_LOADED / providerId none with zero advisories, and a stub provider round-trips one synthetic advisory end-to-end (apps/api/test/scaEngine.test.ts); App-side verified 2026-10-21 (filesystem provider, this tree mounted): fast-jwt@6.2.4 -> 6 advisories, msgpack5@6.0.0 -> 7, mariadb@2.0.0 (13-file shard package) -> 2 unique ids, @adonisjs/http-server@5.0.0 (split shard) -> 1, django@3.0.0 -> 1, lodash@4.17.21 -> 0; status DATASET_AVAILABLE, providerId filesystem; App-side verified 2026-10-21: 100 files load as 100 records; shard dedup is by advisory id at match time, so the counting mismatch is confined to the status surface, not to findings.
- Production eligibility: `BLOCKED_PRODUCTION_LOCK`; rights: `UNVERIFIED_THIRD_PARTY`; owner decision: D-GHSA / D-OSV / D-NVD / D-CWE plus GATE-1/GATE-3/GATE-4.
- Verification: `npm run validate`, `npm run test:vectors`, `npm run dedup-report`, `node scripts/ingestion-gates.mjs`.

### DCC-SECRETS — Secrets detection engine (App engine + Dataset pack rules)

- Status: **PARTIAL** (basis: `APP_CONSUMER_VERIFIED_WITH_GAPS`); requirement: SUPPLEMENTAL; integration: INTEGRATED.
- Contract: drobon.pack.secrets/v1 shape-only rules with rule-fixed severity/confidence, mandatory redaction, denylist veto unless matchOnlyEvidence, executable examples.
- Assets: `packs/secrets/v1/rules` — 97 (*.json rule files); `knowledge/remediation` — 2171 (*.json remediation files (all families)).
- Relationships: 97/97 rules carry redact:true; 96 carry a denylist and 1 uses matchOnlyEvidence; 97/97 have remediation and resolvable CWE.
- Evaluation: pack-tests: 97/97 secrets rules execute positive+negative examples; independent evaluation recount (2026-10-20): 203 secrets cases (202 assessed, 1 UNASSESSED); 97 rules appear in a positive detection and 97 in a negative case. The machine-checked numbers live in evaluationCoverage; secret-userinfo cohort: 11 assessed cases, 5 TP / 0 FP / 0 FN; leak scan clean outside the audited fixture zone; App-side verified 2026-10-21: 97/97 rules merge and 441/441 declared secrets tests reproduce through the App converter incl. the denylist veto (0 mismatches); positional redaction is implemented in apps/api/src/scans/secrets/engine.ts.
- Production eligibility: `NOT_ELIGIBLE_NO_LICENSE`; rights: `NO_GRANT_ALL_RIGHTS_RESERVED`; owner decision: none for Dataset content.
- Verification: `npm run validate:packs`, `node scripts/test-packs.mjs`, `node scripts/test-assets.mjs`, `node scripts/test-consistency.mjs`.

### DCC-DAST — Passive DAST engine (App engine + Dataset pack rules)

- Status: **PARTIAL** (basis: `APP_CONSUMER_VERIFIED_WITH_GAPS`); requirement: SUPPLEMENTAL; integration: INTEGRATED.
- Contract: drobon.pack.dast/v1 passive observation checks over the closed 7-type check vocabulary, bounded evidence, no active probing.
- Assets: `packs/dast/v1/rules` — 1007 (*.json rule files); `knowledge/patterns` — 2171 (*.json pattern files (all families)).
- Relationships: 2,104/2,104 rules have a pattern, a record and a remediation entry, 0 dangling; 510/520 DAST rules have executed observation examples; 510/510 have remediation and every declared CWE resolves.
- Evaluation: pack-tests: 1007/1007 rules execute positive+negative observation examples; EVAL-DAST-001 exercises the DAST evaluator; passive-only semantics asserted by the pack validator; independent evaluation recount (2026-10-21, app-surface batch 5): 772 DAST observation cases cover 510/1007 rules positively and 510/1007 negatively (the ten rules added on 2026-10-21 carry pack tests but no eval-case entry yet) (synthetic objects, no request sent). The machine-checked numbers live in evaluationCoverage; overlap gate: docs/DAST_OVERLAP_LEDGER.json records every evidence-subset pair; scripts/validate-dast-overlaps.mjs fails on a new unreviewed one; App-side verified 2026-10-21: 510 of the 510 rules present at that time merge; 1,846 declared observation tests evaluated through the App-evaluator profile (scripts/lib/app-evaluator-profile.mjs, a port of App 9360dd1 semantics) produced 15 mismatches on 9 rules (Node-realistic lowercased headers), i.e. 2,137/1,846 = 99.2% parity — recorded honestly, not rounded up.
- Production eligibility: `NOT_ELIGIBLE_NO_LICENSE`; rights: `NO_GRANT_ALL_RIGHTS_RESERVED`; owner decision: none for Dataset content; the App-side active-DAST addition is an owner boundary decision (GAP-045).
- Verification: `npm run validate:packs`, `node scripts/test-packs.mjs`, `node scripts/test-assets.mjs`, `node scripts/test-consistency.mjs`.

### DCC-REMEDIATION — Remediation guidance per pack rule

- Status: **COVERED_VERIFIED** (basis: `DATASET_SIDE_EXECUTABLE`); requirement: REQUIRED; integration: CONTRACT_READY_NOT_INTEGRATED.
- Contract: drobon.knowledge.remediation/v1: exactly one entry per pack rule, keyed by ruleId, with whyItMatters/actions/verification and a resolvable standardId.
- Assets: `knowledge/remediation` — 2171 (*.json remediation files).
- Relationships: 2171/2171 pack rules have exactly one remediation entry; 0 orphans in either direction.
- Evaluation: npm run validate:audiences (1321 files) executes audience content; consistency suite pins the 1:1 remediation relationship; validate-assets rejects remediation with unknown ruleId; App-side verified 2026-10-21: dataset service reports remediation AVAILABLE with 1310 entries; the guidance resolver is still hard-wired to UNAVAILABLE (dead path).
- Production eligibility: `NOT_ELIGIBLE_NO_LICENSE`; rights: `NO_GRANT_ALL_RIGHTS_RESERVED`; owner decision: none for Dataset content.
- Verification: `npm run validate:audiences`, `node scripts/test-consistency.mjs`.

### DCC-CWE — CWE classification reference

- Status: **COVERED_VERIFIED** (basis: `DATASET_SIDE_EXECUTABLE`); requirement: REQUIRED; integration: CONTRACT_READY_NOT_INTEGRATED.
- Contract: drobon.knowledge.cwe/v1 own-words entries with canonical MITRE link and cweVersion pinned to the repo catalog version; every pack/remediation CWE reference resolves.
- Assets: `knowledge/cwe` — 100 (*.json CWE entries).
- Relationships: all 16 CWE ids used by Main App rules (DG-SAST/DG-SEC/DG-DAST) resolve in the Dataset; every pack/remediation CWE reference resolves; 0 unresolved; all 83 entries carry cweVersion 4.20.
- Evaluation: npm run validate:cwe: 100 files, 0 errors, version pinned; consistency suite resolves every CWE reference; App-side verified 2026-10-21: dataset service reports cwe AVAILABLE with 100 entries; no resolver consumer exists in apps/ yet.
- Production eligibility: `NOT_ELIGIBLE_NO_LICENSE`; rights: `NO_GRANT_ALL_RIGHTS_RESERVED`; owner decision: D-CWE confirmation (own-words + links scope) remains an owner acknowledgement, not a Dataset gap.
- Verification: `npm run validate:cwe`, `node scripts/test-consistency.mjs`.

### DCC-LESSONS — Learning-path lesson content (audience dataset)

- Status: **PARTIAL** (basis: `ASSET_VALIDATED_NO_CONSUMER`); requirement: SUPPLEMENTAL; integration: INTEGRATED.
- Contract: drobon.learning.lesson/v1 lessons with concept text, objectives, synthetic practice fixtures and a validator-executed practice target; loader contract in docs/AUDIENCES.md.
- Assets: `learning/lessons` — 6 (*.json lesson files).
- Relationships: every lesson target resolves to an existing pack rule (consistency-tested).
- Evaluation: npm run validate:audiences executes lesson practice against the target rule; 6 lessons: 2 lsn_dev_* and 4 lsn_pack_*; App-side verified 2026-10-21: dataset service reports lessons AVAILABLE 6 (DEVELOPER 2 / STUDENT 6); the App embedded catalog is empty at 9360dd1.
- Production eligibility: `NOT_ELIGIBLE_NO_LICENSE`; rights: `NO_GRANT_ALL_RIGHTS_RESERVED`; owner decision: none for Dataset content.
- Verification: `npm run validate:audiences`, `node scripts/test-audiences.mjs`.

### DCC-ASSESSMENT-TEMPLATES — Assessment templates (audience dataset)

- Status: **PARTIAL** (basis: `ASSET_VALIDATED_NO_CONSUMER`); requirement: SUPPLEMENTAL; integration: CONTRACT_READY_NOT_INTEGRATED.
- Contract: drobon.assessment.template/v1 templates that never pre-declare authorization; loader contract documented in docs/AUDIENCES.md.
- Assets: `assessments/templates` — 3 (*.json template files).
- Relationships: templates carry no authorization grant; banned-phrase lint enforced.
- Evaluation: npm run validate:audiences: 3 templates validate; template-declaration lint passes.
- Production eligibility: `NOT_ELIGIBLE_NO_LICENSE`; rights: `NO_GRANT_ALL_RIGHTS_RESERVED`; owner decision: none for Dataset content.
- Verification: `npm run validate:audiences`.

### DCC-ENGAGEMENTS — Passive-only engagement aids (audience dataset)

- Status: **PARTIAL** (basis: `ASSET_VALIDATED_NO_CONSUMER`); requirement: SUPPLEMENTAL; integration: CONTRACT_READY_NOT_INTEGRATED.
- Contract: drobon.engagement.template/v1 passive-only aids that never claim authorization; loader contract documented in docs/AUDIENCES.md.
- Assets: `engagements` — 2 (*.json engagement files).
- Relationships: passive-only contract lint; no pre-declared authorization.
- Evaluation: npm run validate:audiences: 2 engagement aids validate.
- Production eligibility: `NOT_ELIGIBLE_NO_LICENSE`; rights: `NO_GRANT_ALL_RIGHTS_RESERVED`; owner decision: none for Dataset content.
- Verification: `npm run validate:audiences`.

### DCC-INTEROP — Provider interop contract vectors

- Status: **PARTIAL** (basis: `ASSET_VALIDATED_NO_CONSUMER`); requirement: SUPPLEMENTAL; integration: CONTRACT_READY_NOT_INTEGRATED.
- Contract: drobon.vuln-intel/vectors/v1 pinned coordinate -> advisory expectations, including zero-hit cases.
- Assets: `interop/provider-vectors.json` — 16 (pinned vector cases).
- Relationships: each vector resolves to a real seed advisory or an explicit zero-hit expectation.
- Evaluation: npm run test:vectors: 16/16 pass; Dataset vectors mirror the shape the App stub-provider test accepts (id/severity/summary/url, re-validated by isScaAdvisory); no Dataset file is loaded by that test; App-side verified 2026-10-21: no reference to provider-vectors.json exists anywhere in the App tree; range behaviour is duplicated instead of pinned.
- Production eligibility: `NOT_ELIGIBLE_NO_LICENSE`; rights: `UNVERIFIED_THIRD_PARTY`; owner decision: GATE-4 (App workstream).
- Verification: `npm run test:vectors`.

## 3. UserType × capability view

The four UserTypes are presentation/workflow layers over one shared engine set and one Dataset. No profile has, or may add, a duplicate rule pack.

| UserType | Workflow evidence | Mapped capabilities | Profile-specific Dataset assets |
|---|---|---|---|
| DEVELOPER | docs/DEVELOPER.md + docs/USER_TYPE_CAPABILITY_AUDIT.md (developer workspace) | 16 (`DCC-AUTH-SESSION`, `DCC-PLAN-ENTITLEMENT`, `DCC-PROJECTS`, `DCC-SCAN-JOBS`, `DCC-SAST`, `DCC-SCA-INVENTORY`, `DCC-SCA-VULN`, `DCC-SECRETS`, `DCC-FINDINGS`, `DCC-REMEDIATION`, `DCC-CWE`, `DCC-REPORTS`, `DCC-ASSISTANT`, `DCC-DEV-WORKSPACE`, `DCC-DEV-GITCI`, `DCC-ACCOUNT-LIFECYCLE`) | 0 |
| STUDENT | docs/STUDENT.md + docs/USER_TYPE_CAPABILITY_AUDIT.md (student workspace) | 17 (`DCC-AUTH-SESSION`, `DCC-PLAN-ENTITLEMENT`, `DCC-PROJECTS`, `DCC-SCAN-JOBS`, `DCC-SAST`, `DCC-SCA-INVENTORY`, `DCC-SCA-VULN`, `DCC-SECRETS`, `DCC-FINDINGS`, `DCC-REMEDIATION`, `DCC-CWE`, `DCC-REPORTS`, `DCC-ASSISTANT`, `DCC-STUDENT-WORKSPACE`, `DCC-LESSONS`, `DCC-STUDENT-CWE-ENC`, `DCC-ACCOUNT-LIFECYCLE`) | 0 |
| SECURITY_PROFESSIONAL | docs/SECURITY_PROFESSIONAL.md + docs/USER_TYPE_CAPABILITY_AUDIT.md (assessment workflow) | 18 (`DCC-AUTH-SESSION`, `DCC-PLAN-ENTITLEMENT`, `DCC-PROJECTS`, `DCC-SCAN-JOBS`, `DCC-SAST`, `DCC-SCA-INVENTORY`, `DCC-SCA-VULN`, `DCC-SECRETS`, `DCC-DAST`, `DCC-FINDINGS`, `DCC-REMEDIATION`, `DCC-CWE`, `DCC-REPORTS`, `DCC-ASSISTANT`, `DCC-PRO-ASSESSMENT`, `DCC-ASSESSMENT-TEMPLATES`, `DCC-THIRD-PARTY-AUTH`, `DCC-ACCOUNT-LIFECYCLE`) | 0 |
| PENTESTER | docs/USER_TYPE_CAPABILITY_AUDIT.md (Pentester passive DAST) + docs/DAST.md | 18 (`DCC-AUTH-SESSION`, `DCC-PLAN-ENTITLEMENT`, `DCC-PROJECTS`, `DCC-SCAN-JOBS`, `DCC-SAST`, `DCC-SCA-INVENTORY`, `DCC-SCA-VULN`, `DCC-SECRETS`, `DCC-DAST`, `DCC-FINDINGS`, `DCC-REMEDIATION`, `DCC-CWE`, `DCC-REPORTS`, `DCC-ASSISTANT`, `DCC-PENTEST-DAST`, `DCC-ENGAGEMENTS`, `DCC-THIRD-PARTY-AUTH`, `DCC-ACCOUNT-LIFECYCLE`) | 0 |

- **DEVELOPER**: The Phase 20 Developer feature list does not present DAST (USERTYPES.md rows 1-21), so this workflow map excludes DCC-DAST; the engine is still account-scoped and Dataset coverage is recorded once under DCC-DAST. No DEVELOPER-specific Dataset asset exists or is required.
- **STUDENT**: The Phase 20 Student list presents basic SAST/SCA/Secrets only (no DAST); this map therefore excludes DCC-DAST. STUDENT uses the same engines and records as other profiles. Lessons in the Dataset are not consumed by the App lesson catalog; that is an integration gap, not a coverage defect. No STUDENT-specific rules or duplicated packs are created.
- **SECURITY_PROFESSIONAL**: Assessment state is App-owned; Dataset templates are a loader-future audience asset. No Professional-specific detection dataset is required.
- **PENTESTER**: Offensive/exploit data is a reserved App boundary; the Dataset intentionally contains none. Pentester coverage is the shared passive core plus optional engagement aids.

## 4. Closed App-inventory mapping

Every row of the Main App capability inventory maps to at least one capability; the mapping is closed in both directions (validator-enforced).

| Inventory ref | App evidence | Capability rows |
|---|---|---|
| AUDIT-S1 | USER_TYPE_CAPABILITY_AUDIT.md: registration/session/classification | `DCC-AUTH-SESSION` |
| AUDIT-S2 | USER_TYPE_CAPABILITY_AUDIT.md: role/plan/entitlement/quota | `DCC-PLAN-ENTITLEMENT` |
| AUDIT-S3 | USER_TYPE_CAPABILITY_AUDIT.md: projects/source/lifecycle | `DCC-PROJECTS` |
| AUDIT-S4 | USER_TYPE_CAPABILITY_AUDIT.md: SAST/SCA/Secrets/DAST scan lifecycle | `DCC-SCAN-JOBS`, `DCC-SAST`, `DCC-SCA-INVENTORY`, `DCC-SCA-VULN`, `DCC-SECRETS`, `DCC-DAST` |
| AUDIT-S5 | USER_TYPE_CAPABILITY_AUDIT.md: findings/explanation/remediation/verification | `DCC-FINDINGS`, `DCC-REMEDIATION`, `DCC-CWE` |
| AUDIT-S6 | USER_TYPE_CAPABILITY_AUDIT.md: reports and integrity | `DCC-REPORTS` |
| AUDIT-S7 | USER_TYPE_CAPABILITY_AUDIT.md: deterministic assistant | `DCC-ASSISTANT` |
| AUDIT-S8 | USER_TYPE_CAPABILITY_AUDIT.md: dependency-vulnerability intelligence | `DCC-SCA-VULN`, `DCC-INTEROP` |
| AUDIT-S9 | USER_TYPE_CAPABILITY_AUDIT.md: account enabled/disabled lifecycle | `DCC-ACCOUNT-LIFECYCLE` |
| AUDIT-S10 | USER_TYPE_CAPABILITY_AUDIT.md: administrator and payment review | `DCC-ADMIN-PAYMENTS` |
| AUDIT-P1 | USER_TYPE_CAPABILITY_AUDIT.md: Developer workspace | `DCC-DEV-WORKSPACE` |
| AUDIT-P2 | USER_TYPE_CAPABILITY_AUDIT.md: Developer Git/CI | `DCC-DEV-GITCI` |
| AUDIT-P3 | USER_TYPE_CAPABILITY_AUDIT.md: Student explanations/progress | `DCC-STUDENT-WORKSPACE` |
| AUDIT-P4 | USER_TYPE_CAPABILITY_AUDIT.md: Student course catalog/assignments/grades | `DCC-LESSONS`, `DCC-STUDENT-CWE-ENC` |
| AUDIT-P5 | USER_TYPE_CAPABILITY_AUDIT.md: Professional assessment planning | `DCC-PRO-ASSESSMENT`, `DCC-ASSESSMENT-TEMPLATES` |
| AUDIT-P6 | USER_TYPE_CAPABILITY_AUDIT.md: Professional/Pentester third-party permission | `DCC-THIRD-PARTY-AUTH`, `DCC-ENGAGEMENTS` |
| AUDIT-P7 | USER_TYPE_CAPABILITY_AUDIT.md: Pentester passive DAST | `DCC-PENTEST-DAST`, `DCC-DAST` |
| AUDIT-P8 | USERTYPES.md Pentester rows 5/6/8/13 (exploit/payload/chaining/scripts) | `DCC-EXPLOIT-RESERVED` |
| AUDIT-P9 | USERTYPES.md Professional row 10 / Student row 10 (CVSS, OWASP guide) | `DCC-CVSS-KEV-EPSS`, `DCC-COMPLIANCE-MAPPING` |
| AUDIT-P10 | USERTYPES.md Professional row 7 / row 15 (compliance dashboard, threat modelling) | `DCC-COMPLIANCE-MAPPING`, `DCC-THREAT-MODEL` |
| AUDIT-P11 | CAPABILITY_COVERAGE.md NOT_REQUIRED rows (attestation, licence intel) | `DCC-SUPPLY-CHAIN`, `DCC-LICENSE-INTEL` |

## 5. Decision rules

- COVERED_VERIFIED requires: a documented Dataset requirement, every required asset class present, all relationships validated, executable Dataset evidence passing, and a verification basis that does not depend on a missing App loader. Rule counts alone never qualify a row.
- APP_INTEGRATION_BLOCKED = the Dataset assets are complete and validated, but the Main App ships no consumer (pack/lesson/template/engagement/vector loader or a permitted SCA provider), so coverage cannot be demonstrated in-product.
- RIGHTS_BLOCKED = the capability additionally requires production intelligence breadth or a recorded grant that does not exist; production eligibility is never inferred from technical validity.
- NOT_APPLICABLE = no documented Dataset requirement exists, and the reason cites the App document that settles it (NOT_IMPLEMENTED / RESERVED / NOT_REQUIRED). An App implementation gap is never recorded as a Dataset defect.
- Dataset-side completeness is never pooled with rights, production eligibility, integration or release status; those are separate fields and separate percentages.

## 6. Notes

- A capability the Main App implements without any Dataset input is NOT_APPLICABLE, not MISSING; an App implementation gap is never scored as a Dataset defect.
- The runtime connection was verified on 2026-10-21 at App 9360dd1: all nine dataset categories load from DATASET_PATH and SCA matching returns verified advisories. SUPPLEMENTAL rows are therefore no longer APP_INTEGRATION_BLOCKED for "no loader exists"; they are PARTIAL where a verified integration still has measurable gaps (language-id reachability, evaluator parity, loader conformance) and INTEGRATED/CONTRACT_READY_NOT_INTEGRATED distinguishes consumed data from data that is loaded but unused.
- Rights, production eligibility and engineering completion are separate fields. No row is production-eligible without a recorded grant, and the App now READS this corpus at runtime, so the missing grant blocks any deployment, not only redistribution.
- Counting surface: the App reports 100 vuln-intel files while this repo counts 84 identity items / 78 advisory ids (docs/COUNTING_POLICY.md). The disagreement is recorded, not hidden.
- Four UserTypes share one engine set and one Dataset; no UserType-specific rules or packs exist, and creating duplicates would be a defect.
- Row set is a closed inventory: every capability named by the Pump 22 audit, the Phase 20 USERTYPES matrix or CAPABILITY_COVERAGE.md has a row (see appInventoryCoverage). App-doc conflicts are resolved toward the newer Phase 22 evidence and recorded in section 9 of the audit report.
- Verification of the connection: docs/APP_CONNECTION_VERIFICATION_2026-10-21.md (probe commands, per-family converter parity, SCA results, and the nine defects found).
