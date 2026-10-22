> **Superseded in part — 2026-10-21.** This audit was taken at App `c32c797`
> (2026-10-14) and reports "no loader / not integrated" for every pack, knowledge
> and audience row. The App has since landed the runtime connection at
> `9360dd1abdf940cc1bffd942aab0702703aaaaef`: all nine dataset categories load from
> `DATASET_PATH` and SCA matching was verified against this tree. The figures below
> are **kept unchanged as the historical baseline** — they were not re-scored,
> because a re-score needs a full ledger recompute against the new revision. For the
> verified current state read `docs/APP_CONNECTION_VERIFICATION_2026-10-21.md` and
> `docs/CAPABILITY_COVERAGE_MATRIX.md`; the underlying blockers (no `LICENSE`,
> production lock, 0/100,000 records) are unchanged.

# DROBON MASTER COVERAGE AUDIT — Dataset vs Main App capability matrix vs paid tools

**Audit date:** 2026-10-16 (Asia/Dhaka)

| Header field | Value |
|---|---|
| Main App repository | `https://github.com/mdraselislam0101-design/Drobon` — **read-only**; verified revision `c32c797a549453802bd6d82c5673d2a1728457a3` (shallow clone at `/home/user/Drobon-app-ref`, never modified — `git status` clean) |
| Dataset repository | `https://github.com/mdraselislam0101-design/Drobon-Dataset` — branch `arena/9fe99288-drobon-dataset`, HEAD `fca2c39d1553bb76613d0821bf76e91ee5e8e868` (= remote tip, tree clean at audit start) |
| Arena.ai workspace | `/home/user`; Dataset checkout `/home/user/Drobon-Dataset`; no production DB, credentials, or Main App build present |
| Input documents inspected | App: `USER_TYPE_CAPABILITY_AUDIT.md`, `SAST.md`, `SCA.md`, `SECRETS.md`, `DAST.md`, `FINDINGS.md`, `REPORTS.md`, `ASSISTANT.md`, `USERTYPES.md`, `SECURITY.md`, `README.md`, `apps/api/src/scans/sca/provider.ts`, `config.ts`, `sast/rules.ts`+`languages.ts`, `secrets/rules.ts`, `dast/rules.ts`. Dataset: `SCOPE.md`, `PROVIDER_MAPPING.md`, `CAPABILITY_COVERAGE.md`, `REQUIREMENTS_MATRIX.json`, `COVERAGE_MAP.json`, `BLOCKER_REGISTER.json`, `OWNER_DECISIONS.json`, `OWNER_ACTION_REQUIRED.md`, `LICENSE_DECISION_RECORD.md`, `CORPUS_TARGETS.json`, `PACKS.md`, `interop/provider-vectors.json`, all `vuln-intel/` records (parsed), packs/knowledge trees (counted) |
| Commands actually executed | `git`/`gh` state checks; `python3` record parsers (100 advisory files, 84 identities, 78 ids, 100 provenance-complete); `npm test` (9 runners); `npm run validate` ×9 variants; `node scripts/test-doc-drift.mjs`; `node scripts/check-vectors.mjs`; `node scripts/manifest.mjs --check`; web_search ×4 (vendor docs, 2026-10-16) |
| Limitations & unverified claims | (1) App test suites **NOT_RUN** in this workspace — app evidence cited from its docs/CI record at `c32c797` (1,131 tests documented); (2) vendor comparison = documented capability only, not detection quality; (3) Dataset shallow clone — pre-`12edda1` history unverifiable; (4) importer live dry-run **NOT_RUN** (production lock). |

Machine-readable evidence: `DROBON_COVERAGE_EVIDENCE.json` (64-row ledger).
Calculation rules: `DROBON_COVERAGE_METHODOLOGY.md`. CSVs: traceability,
engine, usertype, report-outcome, paid-tool benchmark, remaining work.

---

## 1. Dashboard (every figure = numerator/denominator from the ledger)

| Metric | Result | Numerator / Denominator | Evidence |
|---|---|---|---|
| **Main App-to-Dataset verified coverage** | **74.9%** | 38.97 pts / 52 dataset-dependent requirements | ledger §5.1 (recomputed 2026-10-17 Master Completion Pump: R-SEC-P-05 stale 43/46 → 46/46 VERIFIED_FULL; supersedes the Phase 5 recount note) |
| — Dataset-required-only (runtime seam) | 68.5% | 15.76 / 23 | SCA-intel + CWE + remediation rows |
| SAST (packs) | 69.0% | 6.21 / 9 | 792 rules; reachability 560/792 |
| SCA / vuln-intel | 66.7% | 9.33 / 14 | 100-file seed; 0/100,000 breadth |
| Secrets | 83.3% | 5.00 / 6 | 97 rules (DPK-SEC-105 Shopify; DPK-SEC-106/107 probe-gap closure; DPK-SEC-108 short-alnum userinfo Phase 9); 46/46 named subrequirements closed (42 classes + Shopify + 3 GAP-013 probe-gap items) |
| DAST | 75.0% | 3.00 / 4 | 65 rules / 7 check types |
| Other: Remediation | 50.0% | 1.00 / 2 | 954 files; loader missing |
| Other: Findings/CWE | 100.0% | 3.00 / 3 | 61 CWE entries; MITRE CWE 4.20 pinned + per-entry `cweVersion` (Phase 5) |
| Other: Audience | 75.0% | 3.00 / 4 | 5+3+2 assets; loaders missing |
| Other: Reports | 84.3% | 8.43 / 10 | 13 report outcomes, see §4 |
| DEVELOPER workflow | 73.6% | 18.40 / 25 | tagged ledger rows |
| STUDENT workflow | 72.5% | 12.33 / 17 | lessons+remediation+findings |
| SECURITY_PROFESSIONAL | 78.5% | 28.26 / 36 | assessments+intel+packs |
| PENTESTER | 73.0% | 15.33 / 21 | engagement aids+dast packs+intel |
| **Intended report-outcome coverage** | **72.5%** | 9.43 / 13 report types (A–G subreqs) | §4 |
| **End-to-end verified capability** | **67.3%** | 35 / 52 fully verified | evidence-chain complete rows |
| **Dataset quality/test verification** | **100%** | 954/954 rule packs with ≥1 executed positive+negative test; 100/100 advisory rows schema+provenance valid; 16/16 interop vectors | pack-tests 3,982; validate-packs 957 files; check-vectors (2026-10-17 Master Completion Pump recount) |
| Comparable documented capability — vs GHAS | 52.6% | 10.0 / 19 documented dims | benchmark CSV |
| — vs Snyk | 57.5% | 11.5 / 20 | benchmark CSV |
| — vs Semgrep AppSec Platform | 53.3% | 8.0 / 15 | benchmark CSV |
| — vs Burp Suite Pro/DAST | 63.6% | 7.0 / 11 | benchmark CSV |
| **Technical implementation completion** | **80.8%** | 42 / 52 (FULL+PARTIAL+IMPLEMENTED_NOT_VERIFIED) | ledger |
| **Production release readiness** | **NO-GO** | G6/G16/G17 BLOCKED_OWNER_DECISION; G8 BLOCKED_PRODUCTION_LOCK; 0/100,000 | RELEASE_READINESS_MATRIX.json |

No percentages were averaged into a composite. FREE/PRO entitlements are
product gating, not intelligence coverage (see §6).

## 2. Requirement ledger totals (denominators fixed in methodology §5)

- Total unique requirements: **64** (semantic duplicates merged; nothing silently dropped).
- Dataset-dependent (scored): **52** — of which REQUIRED 23, SUPPLEMENTAL 29.
- Excluded with justification (`NOT_APPLICABLE_WITH_JUSTIFICATION`): **7** (app-code/platform/entitlement rows with no dataset seam).
- Status breakdown (52): **VERIFIED_FULL 35 · VERIFIED_PARTIAL 6 · IMPLEMENTED_NOT_VERIFIED 1 · MISSING_ENGINE_OR_INTEGRATION 6 · NOT_IMPLEMENTED 1 · BLOCKED 3** (1 production-lock, 1 license, 1 owner-decision). Recounted 2026-10-17 (R-SEC-P-05 → VERIFIED_FULL).
- App-side rows tracked (not scored): 3 NOT_IMPLEMENTED (Git/CI integration, account lifecycle, exec-summary contract unverified) + 4 N/A.

## 3. Engine dashboard (dataset-dependent requirements only)

| Engine | Full | Partial | Impl≠verified | Missing engine | Blocked | NotAssessed | Verified % | Top gap |
|---|---|---|---|---|---|---|---|---|
| SAST | 5 | 2 | 0 | 2 | 0 | 0 | 69.0% (6.21/9) | pack loader (GAP-005); reachability 560/792 |
| SCA-intel | 8 | 2 | 1 | 0 | 3 | 0 | 66.7% (9.33/14) | breadth 0/100k (GAP-001); license (GAP-002) |
| Secrets | 5 | 0 | 0 | 1 | 0 | 0 | 83.3% (5.00/6) | loader (GAP-006); probe-gap rules closed (DPK-SEC-106/107/108, GAP-013; R-SEC-P-05 46/46) |
| DAST | 3 | 0 | 0 | 1 | 0 | 0 | 75.0% (3.00/4) | loader (GAP-007) |
| Remediation | 1 | 0 | 0 | 1 | 0 | 0 | 50.0% (1.00/2) | merge-loader (GAP-008) |
| Findings/CWE | 3 | 0 | 0 | 0 | 0 | 0 | 100.0% (3.00/3) | — (version metadata implemented Phase 5; all rows verified) |
| Audience | 3 | 0 | 0 | 1 | 0 | 0 | 75.0% (3.00/4) | audience loaders (GAP-009) |
| Reports | 7 | 2 | 0 | 1 | 0 | 0 | 84.3% (8.43/10) | CVSS/OWASP/prioritization (GAP-010) |

\* The executive-summary report row (`NOT_ASSESSED`, scopeClass NONE) is
outside this dataset-dependent subset; it sits in the 13-row
report-outcome set (§4). Dataset-side gaps (intelligence breadth) and app-side
gaps (loaders, mappings) are kept distinct in `DROBON_ENGINE_COVERAGE.csv`.

## 4. Report-outcome coverage (A contract · B fields · C intel · D exec · E evidence · F e2e · G prod-auth)

| Report | Status | Subreqs | Key gap |
|---|---|---|---|
| SAST findings + source evidence | VERIFIED_FULL | 6/6 (G N/A) | – |
| SCA findings + advisory provenance | VERIFIED_PARTIAL | 6/7 | G: production intel unauthorized (seed-only) |
| Secrets findings (safe evidence) | VERIFIED_FULL | 6/6 | – |
| DAST findings (passive req/resp) | VERIFIED_FULL | 6/6 | – |
| Severity/CWE/confidence (+CVSS/OWASP/prio) | VERIFIED_PARTIAL | 4/7 | CVSS/OWASP/KEV-EPSS absent (lock + no fields) |
| Exploitability findings | MISSING_ENGINE_OR_INTEGRATION | 0/7 | no engine; feeds locked |
| Remediation recommendations | VERIFIED_FULL | 6/6 | – |
| SBOM + inventory | VERIFIED_FULL | 6/6 (dataset N/A) | – |
| License compliance report | NOT_IMPLEMENTED | 0/7 | out of product scope (app decision) |
| Technical summary | VERIFIED_FULL | 6/6 | – |
| Executive summary | NOT_ASSESSED | – | contract not documented in REPORTS.md |
| Forensic/evidence (integrity) | VERIFIED_FULL | 6/6 | – |
| UserType report views | VERIFIED_FULL | 6/6 | – |

**Total: 72.5% (9.43/13).** A rendered template is not proof of findings
validity: every row above was scored on intelligence + evidence + tests, not on
template existence.

## 5. Paid commercial tool benchmark (documented capability, 2026-10-16)

Fixed comparable list: 22 dimensions (CSV header), equal weights (one
documented capability each; no vendor-internal weighting invented).
Vendor sources: GitHub docs/feature summaries (code scanning CodeQL, secret
scanning + validity checks, Dependabot + GitHub Advisory Database, SPDX SBOM,
dependency-review license rules); docs.snyk.io + snyk.io (Open Source, Code,
Secrets, Container, IaC, API & Web); Semgrep public product pages (Code
dataflow, Supply Chain reachability, Secrets validation); PortSwigger/Burp
public material (active+passive scanner, crawl, BChecks/Montoya, HTML/XML/JUnit
reports). Full per-dimension table with citations: `DROBON_PAID_TOOL_BENCHMARK.csv`.

| Tool (edition) | Documented-comparable DROBON coverage | Numerator/denominator | DROBON strongest | DROBON weakest vs this tool |
|---|---|---|---|---|
| GitHub Advanced Security | 52.6% | 10.0/19 | SCA matching provenance, secrets redaction, SBOM | secrets active validation, license review, IDE, reachability |
| Snyk (platform) | 57.5% | 11.5/20 | passive DAST, SCA, remediation, evidence | active DAST, secrets validation, container/IaC engines, license |
| Semgrep AppSec Platform | 53.3% | 8.0/15 | SAST packs, secrets semantics, remediation | reachability SCA, active validation, policy plane |
| Burp Suite Pro/DAST | 63.6% | 7.0/11 | passive checks, evidence, report exports | active scanning/crawl/fuzz (by-design boundary) |

**Interpretation rules applied:** no claim about any proprietary rule count or
DB size; `UNKNOWN` vendor details excluded per-tool (Snyk ×2, Semgrep ×4);
different scopes (e.g. Burp is DAST-only) are not treated as equivalent
products; similar names ≠ equal detection quality; no blended cross-tool
percentage is reported. App capability parity (engines) and Dataset
intelligence coverage are separate columns in the CSV.

## 6. FREE/PRO entitlements (reported separately — not coverage)

App `SUBSCRIPTIONS.md`/`USAGE.md`: FREE scan quota + shared-device anti-abuse;
PRO is server-derived and exempts quota. Role/UserType never grant PRO
(`USER_TYPE_CAPABILITY_AUDIT.md`). Entitlement limits affect *volume*, not
intelligence; they are excluded from every coverage denominator above.

## 7. Dataset audit highlights (Phase D, real records parsed)

| Category | Files | Valid | Unique usable | Dup/overlap | Provenance complete | Tested pos+neg | In functioning engine | E2E verified | Production authorized |
|---|---|---|---|---|---|---|---|---|---|
| SAST rules | 792 | 792 | 792 | 0 | original content (n/a) | 792 | 0 (loader future) | via pack-tests | 0 |
| Secrets rules | 94 | 94 | 94 | 0 | original | 94 | 0 (loader future) | pack-tests | 0 |
| DAST rules | 65 | 65 | 65 | 0 | original | 65 | 0 (loader future) | pack-tests | 0 |
| SCA rule packs | 0 | – | – | – | – | – | – | – | – (planning target 1,000; owner-gated) |
| Advisory records | 100 files | 100 | 84 items / 78 ids | 9 split shards (0 conflicts) | 100/100 | vectors 16/16 | dataset-side matcher (simulator) | check-vectors | **0 (lock)** |
| Patterns/records | 950/910 | 1549/1550* | 950/910 | 0 | original | mirrored tests | generator pipeline | asset-tests 7,490 | 0 |
| Remediation | 950 | 950 | 950 | 0 | original | audience-tests | 0 (loader future) | validate-audiences | 0 |
| CWE | 61 | 61 | 61 | 0 | MITRE links pinned | consistency | shared | validate-cwe | 0 |
| Lessons/templates/engagements | 5/3/2 | 10 | 10 | 0 | original | practice validators | 0 (loaders future) | validate-audiences | 0 |

\* pattern/record layer: 40 legacy patterns have no record counterpart
(owner decision §6.11, tracked BLK-013) — counted as documented exception,
never as extra capability. Blind spots: rule-pattern depth (lexical packs),
217 untagged rules, version-less coordinates never match (by contract).

## 8. Work completed safely during this pump

1. Read-only Main App verification at `c32c797` (seam inventory re-confirmed:
   `VULN_INTEL_PROVIDER` locked to `none`; Null provider `NO_DATA_LOADED`;
   SAST 50 / Secrets 7 / DAST 8 app rules recounted from source).
2. Built the 64-row canonical requirement ledger + 6 CSV artifacts + evidence JSON.
3. Recomputed every dataset count from real files (100/84/78 identities,
   100/100 provenance) — no historical figure reused unchecked.
4. **Safe technical fix (Phase K):** `scripts/test-doc-drift.mjs` grew 16
   assertions (section 8) that re-derive the evidence ledger's file counts from
   the tree — stale audit numbers now fail `npm test`.
5. Full dataset regression re-run (below) with all gates intact.

## 9. Test execution record (Dataset, this commit)

`npm test` exit 0 — tests 600/600 · pack-tests 3,966/3,966 · audience-tests
2,891/2,891 · asset-tests 7,490/7,490 · consistency 208/208 · rehearsal 78/78 ·
importer-tests 49/49 · **doc-drift 104/104** (88 + 16 new) · determinism 5/5.
Validators exit 0: validate 103 · sources 1 · corpus 3 · packs 953 · assets
1,860 · audiences 960 · cwe 61 · matrix · vectors 16/16 · manifest 3,995 files.
**NOT_RUN:** app suites (see header), live importer dry-run (lock), browser E2E
(none configured in app).

## 10. Production & licensing blockers (unchanged, verified intact)

- Production Intelligence Lock holds: `vuln-intel/` untouched this pump;
  `verifiedProductionCount = 0` everywhere; 0/100,000; fixtures test-only.
- Owner gates open: license grant (BLK-001), per-source redistribution
  (BLK-002, 5/5 `OWNER_DECISION_REQUIRED`), production stage authorization
  (BLK-003), cadence (BLK-004), plus the §6/§7 policy cluster
  (`docs/BLOCKER_REGISTER.json` BLK-001…020; `docs/OWNER_DECISION_PACKET.md`).

## 11. Remaining work (top of 25-row backlog; full list `DROBON_REMAINING_WORK.csv`)

| Gap | Prio | Class | What | Can do now |
|---|---|---|---|---|
| GAP-001 | P0 | D production-auth | advisory breadth 0/100,000 | no — owner batch authorization |
| GAP-002 | P0 | C licensing | license grant + per-source terms | no — owner only |
| GAP-003/004 | P1 | D/B | live dry-run; refresh cadence | no — owner |
| GAP-005…009 | P1/P2 | E app workstream | pack/audience/remediation loaders | no — Main App repo |
| GAP-010/011 | P1/P2 | E + D | CVSS/OWASP/prioritization; exploitability | no — app + intel unlock |
| GAP-012 | P2 | F evidence | Shopify `shpat_` doc verification | partly — public docs research |
| GAP-013/014/016/022/024 | P2/P3 | B owner + A | probe-gap rules, universal ids, rule growth, D5, denylist | evidence-gated / owner |
| GAP-015/025 | P3 | A safe | flow-DSL design doc; lesson content | **yes** |

**Another pump?** Yes — one *Dataset-side* pump to (a) execute GAP-012 evidence
research and GAP-015 design doc + GAP-025 content with validators (all safe),
and (b) after owner replies land in `OWNER_DECISION_PACKET.md`, process D-1…D-4
into gate evidence. No further coverage measurement is useful until either the
owner gates move or the app workstream lands the loaders.

---

## 12. Gap-closure pump addendum (2026-10-16, this repository state)

Safe authorized work completed on top of the baseline audit (all verified):

1. **GAP-012 CLOSED — Shopify `shpat_` rule authored (DPK-SEC-105).** Official
   source evidence obtained: Shopify's own developer docs set
   `adminApiAccessToken` to an `shpat_`-prefixed value
   (https://shopify.dev/docs/api/shopify-app-remix/latest/guide-custom-apps,
   retrieved 2026-10-16). Body format is NOT officially documented — the rule
   lower-bounds the body at 32 alphanumerics and says so in its limitation;
   `shpss_`/`shpca_` are pinned as non-matches (different token types). No
   category change was needed (`service-token` retained). Generated via
   `data/asset-cells/secrets-4.json`; full count cascade updated (secrets 94,
   pack total 951, patterns 951, remediation 951, records 911, Σvalidated
   2074). Resolves COVERAGE_MAP BE-1 and BLOCKER_REGISTER BLK-020
   (`resolvedForRecord` BLK-R03).
2. **GAP-015 CLOSED — flow-DSL design documentation** (`docs/PACK_FLOW_DSL_PROPOSAL.md`,
   PROPOSAL ONLY; no schema change; owner decision surface A/B/C).
3. **GAP-025 CLOSED — lesson content**: `lsn_pack_shelltrue_fix` (Dropping
   shell=True, paired with DPK-SAST-003; practice files validator-executed;
   lessons 5 → 6).
4. **Stale-claim fixes**: app secrets rule count corrected 7 → 6
   (DG-SEC-001..006, recounted from source); `docs/AUDIENCES.md` prose drift
   fixed (911/52 → 951/61); CAPABILITY_COVERAGE method note re-dated.
5. Coverage recomputed (dashboard above reflects post-closure numbers); the
   baseline remains in git history (`640808e`).

**Remaining classes after closure:** (a) owner/license/production
authorization — 19 open blockers (`docs/BLOCKER_REGISTER.json`), P0s GAP-001..004;
(b) Main App workstream (class E) — 5 loaders + engine/mapping work
(GAP-005..011, 017..020, 023); (c) evidence/owner-gated growth (GAP-013/014/016/
022/024). No safe authorized Dataset-side work remains in this workspace.

---

## Final verdict (exactly one)

> ## BLOCKED — TECHNICAL GAPS AND OWNER AUTHORIZATION REQUIRED

Both blocker classes remain after all safe authorized work was completed this
pump: (1) owner/license/production authorization (19 open blockers; G6/G8/G16/G17
blocked; 0/100,000 verified-production; release NO-GO), and (2) genuine
technical gaps at product level — Main App loaders/integration (class E, 6
rows), flow-rule expressibility (R-SAST-P-04), reachability (R-SAST-P-03),
CVSS/OWASP/prioritization + exploitability outputs (R-REP-05/06). Verified
Dataset-dependent coverage stood at 74.8% (38.90/52) post-closure (Phase 5
recount 2026-10-17 after DPK-SEC-106/107 + R-CWE-03); superseded by the
Master Completion Pump recount the same day: **74.9% (38.97/52)** after
R-SEC-P-05's stale 43/46 was corrected to 46/46. This
verdict applies to the defined scope in this document; it is not a claim of
vulnerability-detection completeness or parity with any commercial product.
