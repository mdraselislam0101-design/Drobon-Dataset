# CAPABILITY GAP MATRIX — DROBON AEGIS platform (Phase 4, 2026-10-17)

Scope: this matrix records what the **DROBON platform** (Dataset workstream +
documented Main App contracts) can actually do today, what is missing, and how
each gap would be closed — evidence-first. Baseline: branch
`arena/9fe99288-drobon-dataset` @ `7b683d9` (= remote tip at inspection).
Companion canon (not duplicated here): `docs/CAPABILITY_COVERAGE.md` (app
capability → dataset position), `DROBON_COVERAGE_EVIDENCE.json` (64-requirement
ledger, 74.9% verified coverage), `DROBON_REMAINING_WORK.csv` (GAP-001..047, 43 rows, recount 2026-10-21),
`docs/COMPLETION_MATRIX.json` (CAP-* rows), `docs/AGENT_ARCHITECTURE.md`
(AI-agent design; area F detail), `docs/DATASET_APP_CONTRACT.md`.

**Status vocabulary (mutually exclusive):** `VERIFIED` (behavior proven by
executed tests this run) · `PARTIAL` (some sub-behavior proven, named remainder)
· `NOT_IMPLEMENTED` (no implementation exists) · `NOT_VERIFIED` (implementation
exists but was not exercised in this workstream) · `BLOCKED` (external
dependency named) · `NOT_APPLICABLE_WITH_REASON`.

**Honesty rules applied:** a schema field, dataset record, or plan is never
sufficient for `VERIFIED`; lexical detection is never described as semantic
analysis; no real-world precision/recall is claimed without a defensible
ground-truth set (I2); app-side capabilities are marked `NOT_VERIFIED` here
unless this workstream executed evidence (read-only source inspection is
recorded as such). Test counts below are from the Phase 4 validation run
(§ "Validation" at the end).

---

## A. Code understanding

### CGM-A1 · Language and framework identification
1. **ID:** CGM-A1. 2. **Outcome:** route each file/unit to the right analysis
rules. 3. **Status:** `PARTIAL`. 4. **Evidence:** rules tag language ids
(`packs/*/v1/rules/*.json` `languages`; 111 distinct SAST ids post Phase 4
fix); app catalog snapshot (53 ids, `docs/PACKS.md` ```app-language-catalog```
block, `test-consistency` re-checks reachability counts against it);
`hcl→terraform` alias in `scripts/generate-assets.mjs`. Framework id: absent
(cell `fw` variable is title text only). 5. **Tests:**
`test-consistency.mjs` reachability tripwire (PASS 2026-10-17); `validate-packs`
language regex. 6. **Gap:** no framework identity field; hyphenated catalog ids
(`github-actions`, `shell-posix`, `android-manifest`) inexpressible in the
schema (`^[a-z][a-z0-9]{0,31}$`); subformat tags (`k8s`, `compose`, …) have no
app family. 7. **Proposed approach:** keep rule-level language tags; framework
identity stays app-side (file classification); add `framework` only with a
consumer (no-seam-no-field). 8. **Alternatives:** alias map (rejected:
over-broad); hyphen schema change (deferred: contract change needs app
co-design, GATE-4). 9. **Security:** broadening tags fires rules on unrelated
files (noise → alert fatigue). 10. **Acceptance:** reachability counts stay
machine-pinned; no untested language claims. 11. **Deps:** app catalog (class
E, GAP-014). 12. **Perf/maintenance:** O(1) per rule. 13. **Owner note:** BLK-009
resolved Phase 4 (keep schema; see BLOCKER_REGISTER).

### CGM-A2 · Parser / AST / symbol-scope / control- & data-flow / call-graph
(Phase 6 assessment: `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md` — NOT IMPLEMENTED
verified by inventory; Main App dependency spec SEM-A1..D1 recorded.)
1. **ID:** CGM-A2 (grouped: parser/AST, symbols & scope, CFG/DFG,
interprocedural). 2. **Outcome:** semantic program understanding. 3. **Status:**
`NOT_IMPLEMENTED`. 4. **Evidence:** detection signals are regex line matches
(`knowledge/patterns` `signal.kind: 'regex'`) and 7 closed DAST check types
(`docs/FORMAT.md`); `docs/PACK_FLOW_DSL_PROPOSAL.md` is **proposal only**. 5.
**Tests:** n/a (negative evidence: no parser module exists in `scripts/`; app
engine is lexical matcher functions, SCOPE.md rows 5–7). 6. **Gap:** entire
semantic layer. 7. **Proposed approach:** phase 1 = structural extractors
(language-scoped token/sink tables) feeding lexical rules; phase 2 = a
dataflow IR for the top languages only, validated on synthetic corpora before
any detection claim. 8. **Alternatives:** embed an existing analysis framework
(license/originality risk under the originality policy — requires legal review
first); LLM-based analysis (see CGM-F rows: hypothesis-only, never confirmed
without deterministic evidence). 9. **Security:** mis-analysis must fail toward
"no finding", never toward fabricated findings. 10. **Acceptance (future):**
synthetic vulnerable/safe pairs with defined expected results before each
detector runs (research pipeline, `docs/AGENT_ARCHITECTURE.md` §4). 11. **Deps:**
none to document; implementation gated on capacity + originality review. 12.
**Perf/maintenance:** high cost — do not start without measured need. 13.
**Status note:** honestly `NOT_IMPLEMENTED`; no partial credit for schemas.

### CGM-A3 · Framework-specific source / sink / sanitizer semantics
1. **ID:** CGM-A3. 2. **Outcome:** know framework taint sources, sinks, and
sanitizers. 3. **Status:** `PARTIAL`. 4. **Evidence:** 62 rule categories cover
framework-flavored sinks lexically (e.g. `cross-site-scripting` 26,
`sql-injection` 66, `code-injection` 76 rules; cell classes like
`xss-sink-call` per language); **no sanitizer semantics** (escaping/parameter-
binding awareness absent). 5. **Tests:** every rule has executed positive +
negative fixtures (`test-packs` 3978/3978 PASS). 6. **Gap:** sources and
sanitizers unmodeled; sink lists are lexical strings, not framework APIs. 7.
**Proposed approach:** extend cell classes with source/sanitizer annotations
once a consumer can use them (CGM-A2 phase 2). 8. **Alternatives:** none
feasible today. 9. **Security:** claiming sanitization wrongly suppresses
findings — never add sanitizer logic without tests. 10. **Acceptance:** future
annotations must ship pos+neg tests per annotation. 11. **Deps:** CGM-A2. 12.
**Perf:** n/a now. 13. **Limits:** sink coverage ≠ vulnerability coverage.

## B. Detection intelligence

### CGM-B1 · Original lexical & structural detectors
1. **ID:** CGM-B1. 2. **Outcome:** find insecure code/HTTP patterns. 3.
**Status:** `PARTIAL` (lexical `VERIFIED`-grade; structural not present). 4.
**Evidence:** 954 original rules (792 SAST + 97 Secrets + 65 DAST), 954
patterns, 954 remediations; provenance `origin: 'original-authored'` + cell
lineage (954 = 914 cell-generated + 40 legacy); DAST rules are structured
header/cookie/body checks over parsed HTTP input (`docs/FORMAT.md` closed
vocabulary). (Counts re-recomputed 2026-10-17 Master Completion Pump.) 5.
**Tests:** `test-packs` 3982, `test-assets` 7522, `validate-packs` 957
files, `validate-assets` 1868 — all PASS this run. 6.
**Gap:** no structural AST detectors (see CGM-A2); reachability <100% (560/792
fully reachable under app catalog; documented per-rule in `docs/PACKS.md`). 7.
**Approach:** status quo is the correct baseline; extend via cell classes with
evidence + tests (research pipeline §9). 8. **Alternatives:** DSL (proposal
only). 9. **Security:** rules fire conservatively; `limitation` field mandatory
per rule. 10. **Acceptance:** every new rule ≥1 positive + ≥1 negative executed
test (enforced by `test-assets` linkage). 11. **Deps:** none. 12. **Perf:**
linear regex scan; deterministic. 13. **Status note:** "1868 rules" is breadth,
not measured real-world detection rate (see CGM-I2).

### CGM-B2 · Semantic vulnerability conditions & taint / data-flow detection
1. **ID:** CGM-B2 (grouped: semantic conditions, data-flow/taint). 2.
**Outcome:** prove attacker-controlled reachability to a sink. 3. **Status:**
`NOT_IMPLEMENTED`. 4. **Evidence:** all signals are line-local regex
(`knowledge/patterns`); several rules *document* this as a limitation
(`limitation` fields); `PACK_FLOW_DSL_PROPOSAL.md` flow concept unimplemented.
5. **Tests:** negative evidence only. 6. **Gap:** taint tracking, path
sensitivity, sanitization awareness. 7. **Approach:** synthetic-corpus-first
(ground truth defined before detector runs); promote nothing to production
without the release process. 8. **Alternatives:** LLM hypotheses + deterministic
verification (must never self-confirm). 9. **Security:** false "confirmed"
verdicts are the worst failure mode — verification must be independent
(CGM-F3). 10. **Acceptance:** defined TP/FP/FN on an original synthetic suite;
no precision claims beyond it. 11. **Deps:** CGM-A2. 12. **Perf:** unknown;
measure before rollout. 13. **Status note:** explicitly out of current scope.

### CGM-B3 · Authentication / authorization weakness detection
1. **ID:** CGM-B3. 2. **Outcome:** flag broken access control & auth patterns.
3. **Status:** `PARTIAL`. 4. **Evidence:** categories `access-control` (33),
`authentication` (4), `broken-auth` (4), `session-security` (3),
`privilege-management` (3), `csrf-protection` (4), `permissions` (15) — all
lexical; e.g. missing-auth sink patterns, permissive CORS
(`cors` 2, DPK-DAST-058 `null` origin). 5. **Tests:** pos+neg per rule. 6.
**Gap:** no authorization-model analysis (role/permission graphs); authz logic
flaws invisible to line regex. 7. **Approach:** keep lexical; framework-auth
annotations (CGM-A3) later. 8. **Alternatives:** none today. 9. **Security:**
low-FP conservative patterns preferred. 10. **Acceptance:** per-rule tests
already enforced. 11. **Deps:** —. 12. **Perf:** linear. 13. **Limits:** presence
checks ≠ absence of flaws.

### CGM-B4 · Injection-class detection (SQL/command/code/XSS/LDAP/XPath/…)
1. **ID:** CGM-B4. 2. **Outcome:** catch injection sinks. 3. **Status:**
`PARTIAL` (lexical per class). 4. **Evidence:** `sql-injection` 66,
`command-injection` 47, `code-injection` 76, `cross-site-scripting` 26,
`ldap-injection` 3, `xpath-injection` 2, `template-injection` 2,
`http-response-splitting` 2, `html-injection` 1; CWE-89/78/79/95 mapped. 5.
**Tests:** pos+neg executed; Phase 7 eval corpus (18 assessed) + Phase 8
`sql-concat-xlang` cohort (26 assessed: 16 detection opportunities + 10
traps; **before** 1 TP / 15 FN / 0 FP → **after** 16 TP / 0 FN / 0 FP,
recall 1.0, precision 1.0, exact-evidence 16/16 on THAT population only) +
Phase 9 `cmd-injection` cohort (23 assessed: 13 opportunities + 10 traps;
**before** 11 TP / 2 FN / 0 FP → **after** 13 TP / 0 FN / 0 FP — ruby
backtick `#{}` and `curl|zsh` defects fixed in `shell-risk`/`curl-pipe-shell`
cells; 3 UNASSESSED boundary cases).
All 12 family variants now carry the Phase-7-proven nested-paren scan
(11 fixed Phase 8 via `data/asset-cells/sast-calls-2.json` sinks —
source-of-truth, regenerated); interpolation alts added where the language
has one (go `fmt.Sprintf`, groovy GString `${`, scala s-interp `${`,
csharp SQL-verb-set interpolation scope). 6. **Gap:** context/flow-blind;
string-concat heuristics FP on constant concatenation; comment/docstring
matches are inherent line-lexical FPs (EVAL-SAST-008 pins one honestly);
semantic assembly through unknown callees stays UNASSESSED (not claimed). 7.
**Approach:** taint later (CGM-B2). 8. **Alternatives:** —.
9. **Security:** injection rules must never suggest auto-fixes (H1). 10.
**Acceptance:** unchanged. 11. **Deps:** —. 12. **Perf:** linear. 13. **Limits:**
documented per rule (`fpNotes` in patterns).

### CGM-B5 · Deserialization / path handling / crypto misuse / memory safety
1. **ID:** CGM-B5 (grouped). 2. **Outcome:** flag unsafe parsing, path, crypto,
memory classes. 3. **Status:** `PARTIAL` (lexical). 4. **Evidence:**
`unsafe-deserialization` 29 + `deserialization` 2 (pickle, YAML load,
XMLDecoder, SpEL added SAST Batch 4); `path-traversal` 37 (CWE-22);
`weak-cryptography` 85 (CWE-327/328/330-family); `buffer-overflow` 5,
`integer-overflow` 2, `format-string` 2, `memory-safety` 2, `timing-side-channel`
5 (CWE-208 timing-equality across 5 languages). 5. **Tests:** pos+neg per rule
(e.g. `yaml.load` flag excludes `Loader=` calls — boundary pinned). 6. **Gap:**
no algorithm-strength reasoning beyond name patterns (e.g. no key-size math).
7. **Approach:** keep lexical; extend classes with evidence. 8. **Alternatives:**
—. 9. **Security:** crypto name matching must not claim "broken" beyond the
named primitive (severity rationale field). 10. **Acceptance:** per-rule
boundary tests. 11. **Deps:** —. 12. **Perf:** linear. 13. **Limits:** naming
≠ weakness proof; `limitation` field says so.

### CGM-B6 · Configuration & trust-boundary errors
1. **ID:** CGM-B6. 2. **Outcome:** flag insecure config / boundary mistakes.
3. **Status:** `PARTIAL` (lexical + passive HTTP). 4. **Evidence:**
`secure-configuration` 89, `container-security` 35, `transport-security` 43,
`security-headers` 23 + `response-headers` 5 + DAST header checks (65 rules /
7 check types), `ci-security` 9 (GitHub Actions patterns), `cookie-flags` 4,
`cors` 2, `csp-weakness` 3. 5. **Tests:** pos+neg; DAST evaluator rows in
`test-packs`. 6. **Gap:** no config *semantics* (e.g. effective IAM policy
analysis); `gha` rules unreachable in app engine (GAP-014, class E). 7.
**Approach:** subfamily support is app-catalog work (class E); dataset keeps
honest reachability accounting. 8. **Alternatives:** —. 9. **Security:**
trust-boundary claims stay at header/flag level. 10. **Acceptance:** unchanged.
11. **Deps:** app catalog for reach. 12. **Perf:** linear. 13. **Limits:** passive
observation only (CGM-E rows).

### CGM-B7 · Framework-aware / API-specific security conditions
1. **ID:** CGM-B7. 2. **Outcome:** catch insecure framework API usage. 3.
**Status:** `PARTIAL` (API-specific lexical). 4. **Evidence:** API-call classes
(`sast-calls-*` cells: e.g. `addJavascriptInterface` java/kotlin pair,
`SimpleDateFormat` static fields, `ListenAndServe` without timeouts,
`badCertificateCallback`, Ecto SQL concat, JAAS PlainLoginModule); 62
categories total. 5. **Tests:** pos+neg; language-split pairs dedup-reviewed
(TRUE_DUPLICATE=0, `test-consistency` §dup-review). 6. **Gap:** API semantics
beyond the named call (overloads, wrappers). 7. **Approach:** keep naming-based
with per-call boundary tests. 8. **Alternatives:** —. 9. **Security:** wrapper
blindness is a documented limitation class. 10. **Acceptance:** unchanged. 11.
**Deps:** —. 12. **Perf:** linear. 13. **Limits:** direct-call only.

## C. SCA and supply-chain analysis

### CGM-C1 · Manifest / lockfile parsing
1. **ID:** CGM-C1. 2. **Outcome:** extract declared dependencies. 3. **Status:**
`NOT_VERIFIED` (app-side). 4. **Evidence:** implemented in Main App
`apps/api/src/scans/sca/parsers.ts` (read-only inspection 2026-10-14,
SCOPE.md row 8); Dataset holds no parsers. 5. **Tests:** not run in this
workstream (app tests are app-side). 6. **Gap:** none in-repo; verification
gap. 7. **Approach:** app workstream. 8. **Alternatives:** —. 9. **Security:**
parsing untrusted manifests must stay fail-closed (app concern). 10.
**Acceptance:** app suite green at app releases. 11. **Deps:** app repo
(read-only reference). 12. **Perf:** n/a here. 13. **Status note:** never claim
app capability as dataset-verified.

### CGM-C2 · Package identity & version resolution / range matching
1. **ID:** CGM-C2. 2. **Outcome:** map (ecosystem, name, version) to
vulnerable ranges. 3. **Status:** `PARTIAL` (range matching `VERIFIED`;
breadth blocked). 4. **Evidence:** `scripts/range.mjs` npm-semver subset + PEP
440 subset; 16 interop vectors (`interop/provider-vectors.json`,
`check-vectors` 16/16 PASS); identity key `(source, id, ecosystem, package)`
(`docs/COUNTING_POLICY.md`). 5. **Tests:** `test.mjs` 600 (range + vectors);
`test-importers` 49 (mapping). 6. **Gap:** 0/100,000 verified-production
advisories (D-2/GAP-001); ecosystems limited to npm+PyPI (GAP-023, app
contract `ScaEcosystem`); D5 local-labels rejected fail-closed (BLK-017
resolved: keep). 7. **Approach:** owner-authorized batches only (lock). 8.
**Alternatives:** —. 9. **Security:** version-less coordinates never match
(pinned); multi-file shards collapse to one item. 10. **Acceptance:** vectors
stay green per change. 11. **Deps:** D-2, GATE-1/3. 12. **Perf:** O(ranges)
per coordinate. 13. **Limits:** no real matching possible until authorized
intelligence exists.

### CGM-C3 · Dependency graph accuracy
1. **ID:** CGM-C3. 2. **Outcome:** transitively resolved dependency trees. 3.
**Status:** `NOT_VERIFIED` (app-side inventory exists; graph depth unknown
here). 4. **Evidence:** app `inventory.ts` + CycloneDX emission (SCOPE.md row
8); no dataset role. 5. **Tests:** app-side. 6. **Gap:** transitive-resolution
accuracy unverified in this workstream. 7. **Approach:** app workstream. 8.
**Alternatives:** —. 9. **Security:** graph errors propagate to SCA results —
app must test. 10. **Acceptance:** app suite. 11. **Deps:** app. 12. **Perf:**
app-side. 13. **Status note:** `NOT_VERIFIED`, not `VERIFIED`.

### CGM-C4 · Original package-risk heuristics
1. **ID:** CGM-C4. 2. **Outcome:** score supply-chain risk beyond known CVEs
(typosquat, maintainer churn, install scripts…). 3. **Status:**
`NOT_IMPLEMENTED`. 4. **Evidence:** `docs/CORPUS_TARGETS.json` category
`package-version-metadata` = 0 (no fields proposed); SCOPE.md rule: no seam, no
directory. 5. **Tests:** n/a. 6. **Gap:** entire capability. 7. **Approach:**
future original heuristics would need a consumer seam + honest scoring
(no fabricated scores). 8. **Alternatives:** —. 9. **Security:** risk scores
must never be presented as vulnerability facts. 10. **Acceptance:** defined
before implementation. 11. **Deps:** app seam (class E). 12. **Perf:** —. 13.
**Status note:** NOT_IMPLEMENTED with reason; not planned this phase.

### CGM-C5 · Honest handling of unknown version-specific status
1. **ID:** CGM-C5. 2. **Outcome:** never claim "affected"/"safe" without data.
3. **Status:** `VERIFIED`. 4. **Evidence:** `ScaDatasetStatus` has no "clean"
value (contract); `NO_DATA_LOADED` / zero-match semantics documented
(`docs/DATASET_APP_CONTRACT.md` §3, `docs/PROVIDER_MAPPING.md`); production
counts honest (0). 5. **Tests:** `test.mjs` vector negatives (version-less
never matches); doc-drift corpus asserts (`verifiedProductionCount = 0`). 6.
**Gap:** app zero-match wording is an app decision (GAP/APP_DECISION). 7.
**Approach:** status quo. 8. **Alternatives:** —. 9. **Security:** absence of
data ≠ absence of vulnerabilities (stated in contract). 10. **Acceptance:**
keep asserts. 11. **Deps:** —. 12. **Perf:** —. 13. **Limits:** semantic kept.

### CGM-C6 · Code-based risk vs known-vulnerability catalog matching
1. **ID:** CGM-C6. 2. **Outcome:** keep the two analyses distinct. 3.
**Status:** `VERIFIED`. 4. **Evidence:** `docs/CORPUS_TARGETS.json`
`verifiedProductionDefinition`; `docs/COUNTING_POLICY.md` vocabulary;
`docs/HONESTY.md`; rules never claim CVE identity; Production Intelligence
Lock separates them operationally. 5. **Tests:** `validate-corpus` +
`test-consistency` corpus block PASS. 6. **Gap:** none known. 7. **Approach:**
status quo. 8. **Alternatives:** —. 9. **Security:** conflation would fabricate
coverage. 10. **Acceptance:** invariants stay machine-checked. 11. **Deps:** —.
12. **Perf:** —. 13. **Limits:** —.

## D. Secrets and sensitive-data exposure

### CGM-D1 · Context-aware secret detection
1. **ID:** CGM-D1. 2. **Outcome:** detect credential shapes with context. 3.
**Status:** `PARTIAL`. 4. **Evidence:** 97 rules (`DPK-SEC-*`) shape-only with
`confidence`, `denylist` veto, `matchOnlyEvidence` class; context = line regex
+ allowlisted non-secret placeholders (e.g. `password=EXAMPLE` negatives).
Phase 5 probe-gap closure (2026-10-17): DPK-SEC-106 (unquoted password
assignments — env `export`/`DB_PASSWORD=`, YAML `password:`, ADO `Password=;`)
and DPK-SEC-107 (URL userinfo passwords containing symbols) authored via
`data/asset-cells/secrets-5.json`. 5. **Tests:** `test-packs` denylist-veto
mutants; `test-assets` linkage 1868/1868; edge tests for DPK-SEC-105 (11);
DPK-SEC-106 carries 16 executed tests and DPK-SEC-107 carries 14 (pos/neg/
boundary/malformed with exact outcomes). 6. **Gap:** Phase 8 added a Dataset-side evidence-gated CANDIDATE evaluator
(`scripts/secret-candidates.mjs`, `drobon.secret.candidate/v1` — Shannon
entropy + charset/length signals + placeholder/hash/UUID/template vetoes +
mandatory assignment-like context evidence; strongest state is CANDIDATE,
never CONFIRMED; outputs redacted to prefix+length fingerprints; synthetic
population 14 cases: 4 TP / 0 FP / 0 FN / 8 TN, 2 UNASSESSED). Liveness
remains forbidden; no confirmed-secret engine exists. GAP-013 probe gaps
CLOSED 2026-10-17 — documented residual recall boundary: pure-alphanumeric
userinfo passwords shorter than 12 characters match neither DPK-SEC-063 nor
DPK-SEC-107. 7. **Approach:**
probe-gap rules authored evidence-gated via `data/asset-cells/secrets-5.json`
(BLK-008 resolved Phase 4: no owner gate on technical authoring). 8. **Alternatives:** liveness probing (forbidden
policy). 9. **Security:** shape ≠ live credential (mandatory limitation text).
10. **Acceptance:** each new rule ≥1 pos + ≥2 neg + leak-scan safety. 11.
**Deps:** —. 12. **Perf:** linear. 13. **Limits:** documented per rule;
candidate signals are triage leads — entropy alone is never a credential
claim (tested). Phase 9: GAP-013 reassessed with a pre-authored probe (both existing
rules missed every short mixed-alnum userinfo password) and closed for the
8-11 mixed-class window by DPK-SEC-108 (LOW confidence, placeholder-vetoed,
disjoint from the 12+ and symbol rules; cohort `secret-userinfo` 5 TP / 0 FP /
0 FN + 1 UNASSESSED version-token ambiguity). Residual: pure-lowercase words
and pure numbers in the password slot remain unflagged BY DESIGN (documented
FP classes). 6-7 char alphanumeric userinfo values sit below the COMMITTED
EVIDENCE FLOOR — EVAL-SEC-104 (ASSESSED, no-issue) pins that below 8
characters the evidence is too weak and DPK-SEC-108 must not fire, and the
Phase 9 verdict recorded the 6-7 window as a documented residual, not a
defect. (Master Completion Pump 2026-10-17: earlier CGM prose said "remains
open", contradicting the tested floor; the tested artifact governs and the
wording is reconciled here. Ratify the floor or authorize an EVAL-SEC-104
relabel plus weaker rule — decision item GAP-026; no rule is authored
against committed ground truth.)

### CGM-D2 · Safe credential handling & redaction (findings + evidence)
1. **ID:** CGM-D2 (grouped: safe handling, redaction, evidence minimization).
2. **Outcome:** never leak candidate secrets in reports/tests/logs. 3.
**Status:** `VERIFIED`. 4. **Evidence:** every secrets rule `redact: true`
(contract `docs/DATASET_APP_CONTRACT.md` §2); synthetic fixtures use
placeholder bodies (`z`×32 non-hex — GitHub push-protection lesson);
leak scanner in `test-consistency` §13 asserts no credential shapes outside
`packs/secrets` fixtures (it caught a real slip in Phase 3 packet wording —
proof it works). 5. **Tests:** leak-scan fires on all 5 synthetic shapes + stays
silent on safe lines (`test-consistency` PASS 222/222). 6. **Gap:** none
in-repo; app finding-render must honor `redact` (contract). 7. **Approach:**
status quo. 8. **Alternatives:** —. 9. **Security:** primary control. 10.
**Acceptance:** leak-scan stays in CI. 11. **Deps:** —. 12. **Perf:** scan cost
small. 13. **Limits:** scanners see shapes, not liveness. Phase 9 Workstream A: candidate→finding promotion contract
(`promoteCandidate` + `drobon.secret.candidate/v1` mapping onto
`drobon.finding.evidence/v1` — one vocabulary): entropy/charset/length/regex/
model-assertion/test-label can NEVER yield VERIFIED; only independent rule
family + exact redacted span evidence can; liveness verification NOT
IMPLEMENTED (contract boundary tested, 35/35).

### CGM-D3 · False-positive rejection
1. **ID:** CGM-D3. 2. **Outcome:** suppress placeholder/example matches. 3.
**Status:** `PARTIAL`. 4. **Evidence:** `denylist` veto + `EXAMPLE`
placeholder denylist generated per rule; DPK-SEC-007 `${`/`<` tuning decided
keep-as-is (BLK-007 resolved Phase 4 — vetoing `${` would hide real values).
5. **Tests:** veto-mutant regressions (3 original + generator mutants);
Phase 7 FP-trap eval cases (static f-string, static template, parameterized
binding, safe branch, call-guard) all clean — 0 FPs on the 6 trap cases. 6.
**Gap:** known FP class remains (documented; EVAL-SAST-008 docstring FP
intentionally still reported, not suppressed); contextual allowlists primitive.
7. **Approach:** per-rule denylist growth only with evidence. 8.
**Alternatives:** broader veto (rejected). 9. **Security:** over-veto hides
real secrets — conservative direction chosen deliberately. 10.
**Acceptance:** mutants stay detected. 11. **Deps:** —. 12. **Perf:** —. 13.
**Limits:** line-local.

### CGM-D4 · Safe synthetic regression cases
1. **ID:** CGM-D4. 2. **Outcome:** regression suite without real secrets. 3.
**Status:** `VERIFIED`. 4. **Evidence:** fixtures DROBON-SAMPLE-001..003
flagged `fixture: true`; cell tests use `EXAMPLE-NOT-A-REAL-VALUE` style
negatives; non-hex bodies policy recorded (BLK-R03). 5. **Tests:** rehearsal
78/78 (fixture twin excluded by flag, not breakage); validator rejects
fixture-impostors. 6. **Gap:** —. 7. **Approach:** status quo. 8.
**Alternatives:** —. 9. **Security:** fixture contamination of production
counts is validator-enforced. 10. **Acceptance:** keep invariants. 11.
**Deps:** —. 12. **Perf:** —. 13. **Limits:** —.

## E. DAST and API security

### CGM-E1 · Safe request/response analysis (passive)
1. **ID:** CGM-E1. 2. **Outcome:** observe HTTP exchanges without probing. 3.
**Status:** `PARTIAL` (passive checks verified; request-side testing
unimplemented). 4. **Evidence:** 65 DAST rules over 7 check types
(`http-url`, `missing-response-header`, `response-header-missing-directive`,
`response-header-matches`, `cookie-missing-flag`, `response-body-matches`,
`response-header-host-differs` — closed vocabulary, `docs/FORMAT.md`);
engagement aids passive-only (`engagements/`, banned-phrase lint). 5.
**Tests:** `test-packs` DAST evaluator rows; `validate-packs` 65/65. 6. **Gap:**
no request crafting, no auth flows, no API schema awareness. 7. **Approach:**
keep passive; any active probing requires owner-authorized environment + rules
(not proposed). 8. **Alternatives:** —. 9. **Security:** passive-only is a hard
product constraint. 10. **Acceptance:** closed vocabulary enforced by
evaluator. 11. **Deps:** —. 12. **Perf:** per-response. 13. **Limits:** one
observation ≠ exposure proof (per-rule limitations say so).

### CGM-E2 · Authentication/authorization testing & active-probe approvals
1. **ID:** CGM-E2 (grouped: auth testing boundaries, approval/safe-env for
active probes). 2. **Outcome:** controlled authenticated testing. 3.
**Status:** `NOT_APPLICABLE_WITH_REASON` (active probing not expressible in the
current DAST contract; not authorized; no live probing performed this phase).
4. **Evidence:** evaluator has 7 passive check types only; `docs/HONESTY.md`;
no importer/executor for active checks. 5. **Tests:** negative evidence
(assert: no active-check code exists). 6. **Gap:** if ever needed: written
approval, isolated environment, per-scope authorization — out of scope now. 7.
**Approach:** keep blocked by policy. 8. **Alternatives:** —. 9. **Security:**
unauthorized probing is prohibited (brief §13). 10. **Acceptance:** n/a. 11.
**Deps:** owner + safe environment (future, if ever). 12. **Perf:** —. 13.
**Limits:** deliberate.

### CGM-E3 · Scope enforcement
1. **ID:** CGM-E3. 2. **Outcome:** stay inside authorized targets. 3.
**Status:** `PARTIAL` (dataset-side aids only). 4. **Evidence:** engagement
templates carry `authorization`/`scope`/`evidence`/`safety` checklist kinds
(`engagements/`, `validate-audiences` banned-phrase lint); never pre-declare
authorization. 5. **Tests:** audience-tests 2897/2897. 6. **Gap:** runtime
scope enforcement is app-side (not implemented anywhere). 7. **Approach:** app
workstream when a scanner runtime exists. 8. **Alternatives:** —. 9.
**Security:** templates must never imply authorization granted. 10.
**Acceptance:** lint stays. 11. **Deps:** app. 12. **Perf:** —. 13. **Limits:**
checklist ≠ enforcement.

### CGM-E4 · Non-destructive testing guarantee
1. **ID:** CGM-E4. 2. **Outcome:** analyses never mutate targets. 3.
**Status:** `VERIFIED`. 4. **Evidence:** dataset DAST checks read
request/response records only (evaluator is pure); no write/mutate verbs in
check vocabulary; brief + policy forbid active/mutating operations. 5.
**Tests:** evaluator tests (pure functions); `test-rehearsal` isolation. 6.
**Gap:** —. 7. **Approach:** status quo. 8. **Alternatives:** —. 9.
**Security:** core safety property. 10. **Acceptance:** closed vocabulary. 11.
**Deps:** —. 12. **Perf:** —. 13. **Limits:** —.

## F. AI-agent architecture

Full design, workflows, and security model: `docs/AGENT_ARCHITECTURE.md`
(Phase 4). Current state: **no agent runtime is configured** — nothing in this
matrix claims agent execution. Deterministic policy core implemented + tested
this phase (`scripts/agent-policy.mjs`, `scripts/test-agent-policy.mjs`).

### CGM-F1 · Task planning, bounded delegation & tool selection
1. **ID:** CGM-F1. 2. **Outcome:** decompose analysis tasks, pick tools. 3.
**Status:** `PARTIAL` (deterministic planner + machine-checked W1 contract
implemented and tested; agent runtime still absent). 4. **Evidence:**
`scripts/agent-workflows.mjs` (`planFromMetadata` deterministic planning,
`validatePlan` permission/budget machine-check, frozen W1 contract with
denied tools); `docs/AGENT_ARCHITECTURE.md` §3 W1 spec. 5. **Tests:**
`test-agent-workflows` 40/40 (planning: permitted-tools only, unknown
languages => NOT_ASSESSED, injection in metadata grants zero expansions,
bounded task list, deterministic). 6. **Gap:** model-backed planning and
delegation (needs runtime); planning is metadata-driven only. 7. **Approach:**
runtime-approved model calls the same contract; deterministic tools stay
invocable without it. 8. **Alternatives:** fully deterministic pipelines
(current reality). 9. **Security:** delegation must inherit least privilege
(CGM-F5). 10. **Acceptance:** W1 acceptance criteria in AGENT_ARCHITECTURE §3
(met for the deterministic planner: 100% of planned calls pass checks). 11.
**Deps:** approved model runtime (none configured). 12. **Perf:** —. 13.
**Limits:** no agent runtime exists or is claimed.

### CGM-F2 · Evidence collection & traceability
1. **ID:** CGM-F2. 2. **Outcome:** every claim carries evidence refs. 3.
**Status:** `PARTIAL` (dataset-side provenance verified; agent traces not
implemented). 4. **Evidence:** advisory `provenance.{source,sourceUrl,
retrievedAt,license}` validator-enforced (100/100); rule/pattern/remediation
cell lineage + `origin`; `scripts/provenance-report.mjs`; SHA-256 manifest
(`data/asset-cells/.manifest.json`, `manifest.mjs`). 5. **Tests:**
`validate.mjs` 103 files; `test-assets` lineage; determinism digest. 6.
**Gap:** execution traces for agent runs (needs runtime); finding-level
evidence schema is app-side. 7. **Approach:** trace format defined
(AGENT_ARCHITECTURE §5) so a future runtime cannot skip evidence. 8.
**Alternatives:** —. 9. **Security:** evidence-grounded findings only. 10.
**Acceptance:** future runs must emit trace + evidence refs. 11. **Deps:**
runtime. 12. **Perf:** —. 13. **Limits:** provenance ≠ rights (D-1/D-2).

### CGM-F3 · Independent verification & uncertainty management
1. **ID:** CGM-F3 (grouped: finding verification, confidence/uncertainty). 2.
**Outcome:** unverified candidates never become "confirmed". 3. **Status:**
`PARTIAL` (deterministic analogues exist). 4. **Evidence:** dedup/TRUE_DUPLICATE
tripwires (0 duplicates); cross-engine consistency checks
(`test-consistency`); secrets `confidence` field; `HONESTY.md` review
checklist; rule `limitation` fields mandatory. 5. **Tests:** dup-review
asserts; negative fixtures. 6. **Gap:** no counter-evidence search agent; no
confidence calibration. 7. **Approach:** W2 spec (independent verifier step,
separate prompts/tools from generator). 8. **Alternatives:** self-review
(rejected — not independent). 9. **Security:** hypothesis ≠ confirmed (brief
§8). 10. **Acceptance:** verifier must be able to reject; rejection rate
reported. 11. **Deps:** runtime. 12. **Perf:** —. 13. **Limits:** current
verification is deterministic-only.

### CGM-F4 · Prompt-injection resistance for untrusted repository content
1. **ID:** CGM-F4. 2. **Outcome:** content can never override policy. 3.
**Status:** `PARTIAL` (deterministic core implemented + tested; runtime
integration pending). 4. **Evidence:** `scripts/agent-policy.mjs`
(`classifyUntrusted`, `detectEmbeddedInstructions`, instruction-hierarchy
constant: system policy > task > untrusted content); synthetic injection cases
in `scripts/test-agent-policy.mjs`. 5. **Tests:** `test-agent-policy` 91/91 (Phase 5 run) — 12 injection shapes
flagged; 8 safe texts unflagged; untrusted content cannot widen permissions; +19 Phase 5
hardening asserts (deep-frozen policy constants, own-property requester/tool/
budget identity vs prototype aliasing, hostile `toString` values denied without
throwing, control-character log-injection echoes sanitized, alternate field
names fail closed). 6. **Gap:** no live agent to
enforce at runtime yet. 7. **Approach:** any future agent MUST route
untrusted content through this module (contract documented). 8.
**Alternatives:** regex-only filtering (insufficient alone; ours is
defense-in-depth policy + tests). 9. **Security:** highest-priority agent risk.
10. **Acceptance:** new injection classes added as tests when discovered. 11.
**Deps:** —. 12. **Perf:** O(n) scans. 13. **Limits:** detection heuristics are
not a proof of non-exploitability; policy = fail-closed permissions + hierarchy.

### CGM-F5 · Tool permission enforcement & resource budgets (timeout/retry/cancel)
1. **ID:** CGM-F5 (grouped: permissions, budgets/timeouts/retry/cancellation).
2. **Outcome:** least-privilege, bounded execution. 3. **Status:** `PARTIAL`.
4. **Evidence:** `scripts/agent-policy.mjs` (`checkToolPermission` fail-closed:
unknown tool/missing policy/insufficient scope → deny; `checkBudget` fail-closed:
NaN/negative/overflow → deny); importer resilience primitives exist
(`scripts/retry.mjs`, `checkpoint.mjs`, per-page checkpoints);
`requireGates()` fail-closed startup. 5. **Tests:** `test-agent-policy` permission/budget suites (within the
91/91; Phase 5 hardening: concrete-scope tools deny missing/non-string scope
`scope-missing`, prototype-inherited budget limits rejected); `test-importers`
49 (mocked retry/checkpoint). 6. **Gap:** runtime executor to enforce budgets live;
cancellation semantics need a runtime. 7. **Approach:** W3 + shared core; spec
defines timeouts/cancellation for future runtime. 8. **Alternatives:** —. 9.
**Security:** fail-closed on any policy gap. 10. **Acceptance:** deny-by-default
asserted. 11. **Deps:** runtime for live enforcement. 12. **Perf:** negligible.
13. **Limits:** policy core without an executor is enforceable only when wired.

### CGM-F6 · Reproducible execution traces
1. **ID:** CGM-F6. 2. **Outcome:** same inputs → same trace/artifacts. 3.
**Status:** `PARTIAL` (deterministic layer verified; agent traces absent). 4.
**Evidence:** determinism suite (generation + whole-tree sha256 reproducible,
5/5); `rehearse.mjs` pure PRNG corpora; manifest digests; W3 evaluation
foundation (`scripts/eval-foundation.mjs`, `drobon.eval.report/v1`)
byte-identical across runs with case-manifest hashes unchanged (Phase 6). 5.
**Tests:** `test-determinism.mjs` 5/5; `test-eval` 43/43 (determinism +
ground-truth-hash invariants). 6. **Gap:** agent-run traces (needs runtime). 7.
**Approach:** trace schema in AGENT_ARCHITECTURE §5. 8. **Alternatives:** —. 9.
**Security:** reproducibility enables audit. 10. **Acceptance:** future runs
pin model id + prompt hash + tool trace. 11. **Deps:** runtime. 12. **Perf:** —.
13. **Limits:** LLM nondeterminism acknowledged in design (temperature 0 where
supported; trace records residual variance).

## G. Findings and reports

### CGM-G1 · Exact source snapshot & scan identity
1. **ID:** CGM-G1. 2. **Outcome:** findings tied to a precise scan. 3.
**Status:** `PARTIAL` (dataset provenance verified; scan identity app-side). 4.
**Evidence:** per-record `provenance.retrievedAt/sourceUrl`; tree digest
(`manifest.mjs`); app report layer does canonical JSON + integrity verify
(SCOPE.md row 21, read-only). 5. **Tests:** `validate.mjs`; determinism. 6.
**Gap:** app scan-identity fields not verified here. 7. **Approach:** app
workstream. 8. **Alternatives:** —. 9. **Security:** stale-snapshot confusion
must be impossible. 10. **Acceptance:** app tests. 11. **Deps:** app. 12.
**Perf:** —. 13. **Limits:** `NOT_VERIFIED` for app-side fields.

### CGM-G2 · Finding payload quality (paths, lines, context, root cause, severity rationale)
1. **ID:** CGM-G2 (grouped G2–G5). 2. **Outcome:** actionable findings. 3.
**Status:** `PARTIAL` (dataset content side strong; rendering app-side
unverified). 4. **Evidence:** every rule has `description`, `remediation`,
`limitation`; patterns carry `examples` (pos+neg), `fpNotes`, `scope`;
remediation 1868 entries keyed `ruleId`; CWE 63 own-words summaries with
canonical links; severity is rule-fixed (contract §2). 5. **Tests:**
`validate-audiences` 1174 files; `test-consistency` CWE resolution;
`test-finding-evidence` 31/31 (evidence record: exact path/line-range/excerpt/
context computed, remediation separate, CVSS never invented — Phase 6
`docs/FINDING_EVIDENCE_CONTRACT.md`). 6. **Gap:**
no CVSS/OWASP mapping (GAP-010, lock + app decision); app rendering of
finding fields not verified here. 7. **Approach:** app workstream
for rendering; dataset keeps evidence content. 8. **Alternatives:** —. 9.
**Security:** severity without rationale is disallowed in content
(`severity` + `limitation` pair). 10. **Acceptance:** content validators. 11.
**Deps:** app. 12. **Perf:** —. 13. **Limits:** no scoring feeds imported (lock).

### CGM-G3 · Confidence & uncertainty on findings
1. **ID:** CGM-G3. 2. **Outcome:** findings carry calibrated doubt. 3.
**Status:** `PARTIAL`. 4. **Evidence:** secrets `confidence` field
(HIGH/MEDIUM); rule `limitation` mandatory; contract forbids certainty
claims beyond evidence. 5. **Tests:** schema-enforced. 6. **Gap:** no
cross-engine confidence model; app rendering unverified. 7. **Approach:** W2
verifier + calibrated labels later. 8. **Alternatives:** —. 9. **Security:**
overconfidence harms triage. 10. **Acceptance:** future calibration tests. 11.
**Deps:** app + runtime. 12. **Perf:** —. 13. **Limits:** per-rule only today.

### CGM-G4 · Stable finding identity, before/after comparison, fix verification
1. **ID:** CGM-G4 (grouped G7–G8). 2. **Outcome:** track findings across scans;
verify fixes. 3. **Status:** `PARTIAL` (dataset-side identity + transition
contract implemented + tested; app scan store/retest flow still missing). 4.
**Evidence:** `scripts/finding-evidence.mjs` — `identityOf` stable finding
identity (rule+path+normalized-span hash; line-shift tolerant) and
`classifyTransition` implementing the five statuses (FIXED_VERIFIED /
PARTIALLY_FIXED / STILL_PRESENT / CHANGED_REQUIRES_REVIEW /
NOT_OBSERVED_UNVERIFIED) per `docs/FINDING_EVIDENCE_CONTRACT.md`; dataset
contributes stable rule ids (never reused — 26 retired reservations pinned). 5.
**Tests:** `test-finding-evidence` 31/31 (all five statuses, line-shift
stability, disappearance is never remediation, change detection). 6.
**Gap:** scan/finding store + retest execution flow (app/DB workstreams,
SCOPE.md rows 9–11). 7. **Approach:** app workstream consumes the contract. 8.
**Alternatives:** —. 9. **Security:** identity instability corrupts metrics;
false FIXED claims corrupt remediation trust — both contract-tested. 10.
**Acceptance:** contract + tests (met); app integration (pending). 11.
**Deps:** app. 12. **Perf:** —. 13. **Limits:** no live scan has been tracked;
synthetic transitions only.

### CGM-G5 · Tamper-evident history
1. **ID:** CGM-G5. 2. **Outcome:** detect unauthorized record edits. 3.
**Status:** `PARTIAL`. 4. **Evidence:** SHA-256 manifest +
`manifest.mjs --scope all` byte-identical check (CI); git history (no rewrite
policy); app report integrity verify (read-only). 5. **Tests:** determinism
manifest asserts; CI integrity check (Batch H). 6. **Gap:** signed
attestations (would need keys/owner); app-side history store unverified. 7.
**Approach:** status quo until a signing story exists. 8. **Alternatives:** —.
9. **Security:** digests detect drift, not malice by a key holder. 10.
**Acceptance:** manifest stays green. 11. **Deps:** owner key policy (future).
12. **Perf:** digest cost measured (whole tree <2s here). 13. **Limits:**
unsigned.

## H. Remediation and developer workflow

### CGM-H1 · Proposed fix guidance only (advisory snippets/diffs)
1. **ID:** CGM-H1. 2. **Outcome:** suggest, never apply. 3. **Status:**
`VERIFIED`. 4. **Evidence:** 954 remediation entries are guidance text
(`knowledge/remediation/`, schema `drobon.knowledge.remediation/v1` content
fields only; status stays app-computed); contract: fixes shown as advisory
snippets/diffs only (DATASET_APP_CONTRACT); code-mutation ban is a standing
product rule. 5. **Tests:** `validate-audiences`/consistency (content
bounds); doc-drift count pins. 6. **Gap:** —. 7. **Approach:** status quo. 8.
**Alternatives:** auto-apply (forbidden). 9. **Security:** auto-modification of
user code is prohibited — no such code path exists (grep-audited this run). 10.
**Acceptance:** keep prohibition + audits. 11. **Deps:** —. 12. **Perf:** —. 13.
**Limits:** guidance quality varies per rule (per-entry text).

### CGM-H2 · Safe regression tests & manual acceptance (no auto commit/push/deploy)
1. **ID:** CGM-H2 (grouped H2–H5). 2. **Outcome:** developer-in-the-loop. 3.
**Status:** `NOT_APPLICABLE_WITH_REASON` for auto-commit/push/deploy (no such
component exists in this workstream; app-side apply/commit features are
app-repo scope and none exist per SCOPE.md); regression-test *content*
support = `VERIFIED` via per-rule tests as executable regression examples. 4.
**Evidence:** rules carry `tests` arrays (executed by `test-packs`); policy
docs (`docs/HONESTY.md`, contract); no `git push`/deploy code in `scripts/`
(grep-audited). 5. **Tests:** full suite green; negative audit. 6. **Gap:** an
app-side "proposed fix diff" renderer (app workstream). 7. **Approach:** app
workstream per contract. 8. **Alternatives:** —. 9. **Security:** automation
boundaries are architectural, not cosmetic. 10. **Acceptance:** absence audits
re-run per release. 11. **Deps:** app. 12. **Perf:** —. 13. **Limits:** —.

## I. Quality and operations

### CGM-I1 · Determinism & reproducibility
1. **ID:** CGM-I1. 2. **Outcome:** byte-stable generation & validation. 3.
**Status:** `VERIFIED`. 4. **Evidence:** `test-determinism.mjs` 5/5 (fresh-copy
generation byte-identical, whole-tree sha256 reproducible); `rehearse.mjs` pure
PRNG. 5. **Tests:** executed this run (digest recorded in §Validation). 6.
**Gap:** —. 7. **Approach:** status quo. 8. **Alternatives:** —. 9.
**Security:** reproducibility underpins audit. 10. **Acceptance:** digest
asserts. 11. **Deps:** —. 12. **Perf:** digest ≈ seconds. 13. **Limits:** —.

### CGM-I2 · False-positive / false-negative measurement
1. **ID:** CGM-I2. 2. **Outcome:** quantify detector error. 3. **Status:**
`PARTIAL`. 4. **Evidence:** per-rule synthetic pos/neg fixtures give
fixture-level TP/FN (954 rules × executed tests); FP classes documented
(`fpNotes`, limitations); **no** real-world precision/recall — no defensible
real ground-truth set exists (explicitly not claimed anywhere). 5. **Tests:**
`test-packs`/`test-assets` totals (§Validation); Phase 6 W3 evaluation
foundation (11 cases) + Phase 7 growth to **23 cases** (18 assessed, 5
UNASSESSED): before detection-quality fix 9 TP / 3 FN / 1 FP (recall 0.75,
precision 0.9) → after **12 TP / 0 FN / 1 FP (recall 1.0, precision 0.9231)**
over THAT synthetic population only; exact-evidence match rate 12/12 on
declared detections; `test-eval` 30/30. 6. **Gap:** real-world
measurement (needs authorized corpora + methodology — future research
pipeline). 7. **Approach:** synthetic-benchmark growth via the W3 research
pipeline (`run-eval.mjs`, AGENT_ARCHITECTURE §3 W3) with expected results
defined before runs. 8.
**Alternatives:** paid benchmarks (forbidden without approval; vendor
comparison stays documented-capability-only). 9. **Security:** fabricated
metrics are disqualifying. 10. **Acceptance:** any future number names its
corpus + limits. 11. **Deps:** —. 12. **Perf:** —. 13. **Limits:** synthetic
≠ production (stated in every report).

### CGM-I3 · Performance & memory cost
1. **ID:** CGM-I3. 2. **Outcome:** bounded scan cost. 3. **Status:**
`NOT_VERIFIED` (no engine-runtime benchmarks; toolchain cost measured). 4.
**Evidence (real measurements, Phase 4 run):** full `npm test` ≈ 10.4 s wall;
validators ≈ 0.8 s combined; whole-tree digest run ≈ 3.9 s — recorded from
actual command timings this run. No claim about app scan performance.
5. **Tests:** timings captured, not asserted. 6. **Gap:** per-rule matching cost
benchmarks (app runtime). 7. **Approach:** app workstream; dataset stays
linear-regex by construction. 8. **Alternatives:** —. 9. **Security:** resource
exhaustion via pathological regex — patterns are linear-ish literals (bounded
by generator shape). 10. **Acceptance:** future budgets in AGENT_ARCHITECTURE
§5. 11. **Deps:** app. 12. **Perf:** see measurements. 13. **Limits:** sandbox
timings ≠ production hardware.

### CGM-I4 · Coverage transparency
1. **ID:** CGM-I4. 2. **Outcome:** honest, recomputable coverage. 3.
**Status:** `VERIFIED`. 4. **Evidence:** `DROBON_COVERAGE_METHODOLOGY.md`
(fixed denominators, no weighting, PARTIAL = pass/total subreqs);
`DROBON_COVERAGE_EVIDENCE.json` 64-req ledger recomputed (74.8% = 38.90/52 —
re-derived Phase 3 + unchanged Phase 4); doc-drift count-recompute asserts. 5.
**Tests:** doc-drift (asserts grew Phase 4 — see §Validation). 6. **Gap:** —.
7. **Approach:** status quo. 8. **Alternatives:** —. 9. **Security:** inflated
coverage misleads buyers. 10. **Acceptance:** percentages carry numerator/
denominator triplets (asserted). 11. **Deps:** —. 12. **Perf:** —. 13.
**Limits:** measures verified capability, not market completeness.

### CGM-I5 · Regression resistance & maintainability/observability
1. **ID:** CGM-I5 (grouped I5–I6). 2. **Outcome:** changes cannot silently
degrade. 3. **Status:** `PARTIAL` (regression resistance proven; observability
is docs+CI only). 4. **Evidence:** 15,496 assertions across 10 runners + 9
validators (Phase 4 run); doc-drift (119 asserts incl. the Phase 4 pins);
consistency tripwires (reachability, dedup, leak scan, quarantine); CI
workflow runs validate:assets + integrity manifest (Batch H).
5. **Tests:** all green this run (§Validation). 6. **Gap:** observability is
docs + CI only (no metrics pipeline). 7. **Approach:** status quo; add metrics
only with a consumer. 8. **Alternatives:** —. 9. **Security:** disabled tests
are forbidden (standing rule). 10. **Acceptance:** suite stays green; failures
fixed at root cause. 11. **Deps:** —. 12. **Perf:** suite ~11 s. 13. **Limits:**
sandbox CI parity assumed.

---

## Summary (Phase 4 baseline; rows reassessed Phase 6, 2026-10-17)

| Area | VERIFIED | PARTIAL | NOT_IMPLEMENTED | NOT_VERIFIED | N/A-with-reason | IDs |
|---|---|---|---|---|---|---|
| A code understanding | 0 | 2 | 1 | 0 | 0 | 3 |
| B detection intelligence | 0 | 6 | 1 | 0 | 0 | 7 |
| C SCA/supply-chain | 2 | 1 | 1 | 2 | 0 | 6 |
| D secrets | 2 | 2 | 0 | 0 | 0 | 4 |
| E DAST/API | 1 | 2 | 0 | 0 | 1 | 4 |
| F AI-agent | 0 | 6 | 0 | 0 | 0 | 6 |
| G findings/reports | 0 | 5 | 0 | 0 | 0 | 5 |
| H remediation workflow | 1 | 0 | 0 | 0 | 1 | 2 |
| I quality/ops | 2 | 2 | 0 | 1 | 0 | 5 |
| **Total (grouped IDs)** | **8** | **26** | **3** | **3** | **2** | **42** |

Counted per grouped capability ID (CGM-A1..I5 = 43 ids). Top gaps by value:
CGM-A2/B2 semantic analysis (architectural; Phase 6 assessment + SEM-A1..D1
dependency spec in `docs/SEMANTIC_ANALYSIS_ASSESSMENT.md`), agent runtime
(F1/F2/F3 now have tested deterministic contracts; execution needs a model
runtime — none configured), CGM-G4 app scan store (dataset contract + tests
shipped Phase 6), CGM-C1/C3 app-side verification, CGM-D1 context analysis
(entropy/liveness — probe gaps GAP-013 closed 2026-10-17 by DPK-SEC-106/107).

## Validation (Phase 4 run, 2026-10-17; Phase 5 run appended 2026-10-17)

- **Phase 4:** `npm test` exit 0 — test 600/600, pack-tests 3970/3970, audience-tests
  2897/2897, asset-tests 7498/7498, consistency 208/208, rehearsal 78/78,
  importers 49/49, **agent-policy 72/72 (new)**, doc-drift 119/119 (104 →
  119: Phase 4 pins added), determinism 5/5 — **15,496 assertions total**
  (runner sums recomputed; note: the Phase 3 report's "15,569" was an
  arithmetic slip — its runner set actually summed to 15,409; runner outputs
  themselves were correct).
- Validators (each exit 0): validate 103, validate-packs 954,
  validate-audiences 962, validate-cwe 61, validate-matrix (no license file),
  validate-sources, validate-corpus, validate-assets 1862, check-vectors
  16/16.
- Fail-closed: `requireGates()` throws "production ingestion BLOCKED by 4/4
  gates" (reproduced).
- **Phase 5 (2026-10-17):** `npm test` exit 0 — test 600/600, pack-tests
  3978/3978, audience-tests 2903/2903, asset-tests 7514/7514, consistency
  216/216 (CWE version-metadata asserts added), rehearsal 78/78, importers
  49/49, **agent-policy 91/91 (Phase 5 hardening, 72 → 91)**, doc-drift
  119/119, determinism 5/5 — **15,553 assertions total** (runner sums
  recomputed). Validators (each exit 0): validate-packs 956, validate-assets
  1866, validate-audiences 964, validate-cwe 61 (all entries carry
  `cweVersion: "4.20"`), validate-matrix (inventory recomputed; no license
  file), validate-sources, validate-corpus, check-vectors 16/16.
  Fail-closed: `requireGates()` throws "production ingestion BLOCKED by 4/4
  gates" (reproduced). Coverage: **74.8% (38.90/52)** recomputed on the
  canonical methodology (formula reproduced all 18 pre-change buckets
  exactly before the R-CWE-03 flip; denominator unchanged). finalStatusCounts
  now: CLOSED_VERIFIED 35 · BLOCKED_OWNER_AUTHORIZATION 5 ·
  BLOCKED_APP_IMPLEMENTATION 8 · NOT_APPLICABLE_WITH_REASON 8 ·
  BLOCKED_MISSING_REQUIREMENT 5 · OPEN_DATASET_WORK 1 ·
  IMPLEMENTED_NOT_VERIFIED 1 · BLOCKED_SOURCE_LICENSE 1.

- **Phase 6 (2026-10-17):** `npm test` exit 0 — test 600/600, pack-tests
  3,978/3,978, audience-tests 2,903/2,903, asset-tests 7,514/7,514,
  consistency 216/216, rehearsal 78/78, importers 49/49, agent-policy 91/91,
  **agent-workflows 40/40 (new)**, **finding-evidence 24/24 (new)**,
  **eval-tests 25/25 (new)**, doc-drift 119/119, determinism 5/5 —
  **15,642 assertions total** (runner sums recomputed). Validators each
  exit 0 (packs 956, assets 1866, audiences 964, cwe 61, matrix recomputed
  + no license file, sources, corpus, vectors 16/16). Fail-closed
  `requireGates()` reproduced (4/4 gates block). Coverage ledger REPRODUCED
  on the canonical methodology — **no requirement row moved in Phase 6;
  coverage stays 74.8% (38.90/52)** (documentation/contracts are not counted
  as working capability for ledger rows whose acceptance requires a runtime).

- **Phase 7 (2026-10-17):** `npm test` exit 0 — test 600/600, pack-tests
  3,978/3,978, audience-tests 2,903/2,903, asset-tests 7,514/7,514,
  consistency 216/216, rehearsal 78/78, importers 49/49, agent-policy 91/91,
  agent-workflows 57/57, finding-evidence 31/31, eval-tests 30/30,
  doc-drift 119/119, determinism 5/5 — **15,671 assertions total** (runner
  sums recomputed; +29 vs Phase 6 baseline 15,642 = new Work A regression
  suite +5, Work C/E boundary+safety +17, Work D tracking-edge +7 — no
  assertion removed or weakened). Corpus counts UNCHANGED (953 = 792+96+65
  rules; patterns 953; records 913; remediation 953; cwe 61) — the 12 new
  eval cases are test-only fixtures outside every counted directory
  (inventory validators re-run, identical). Detection-quality closure
  documented at CGM-B4/I2 (before 9 TP/3 FN/1 FP → after 12 TP/0 FN/1 FP on
  the synthetic population; EVAL-SAST-008's documented FP preserved, not
  suppressed). Coverage ledger REPRODUCED — no requirement row moved;
  coverage stays **74.8% (38.90/52)**. `requireGates()` fail-closed (4/4).

- **Phase 8 (2026-10-17):** `npm test` exit 0 — test 600/600, pack-tests
  3,978/3,978, audience-tests 2,903/2,903, asset-tests 7,514/7,514,
  consistency 216/216, rehearsal 78/78, importers 49/49, agent-policy 91/91,
  agent-workflows 57/57, finding-evidence 31/31, **secret-candidates 20/20
  (new)**, eval-tests 37/37, doc-drift 119/119, determinism 5/5 —
  **15,698 assertions total** (runner sums recomputed; +27 vs Phase 7
  15,671 = secret-candidates +20 and eval-tests 30→37; no assertion removed
  or weakened — prior pins preserved or deliberately strengthened; D4
  vacuous-trap defect closed with tests-first discipline). Eval populations scored
  SEPARATELY per cohort (core: 12 TP / 0 FN / 1 documented FP; sql-concat-
  xlang: 16 TP / 0 FN / 0 FP; secret-candidate synthetic set: 4 TP / 0 FP /
  0 FN / 8 TN + 2 UNASSESSED) — never mixed into one score. Corpus counts
  UNCHANGED (953 = 792+96+65 rules; patterns 953; records 913; remediation
  953; cwe 61) — 51 eval cases + candidate fixtures are test-only, outside
  every counted directory. SoT audit: 0 orphan refs, 0 signal-mirror
  mismatches, 0 unused patterns, 0 rules missing remediation (40-rule legacy
  record exception retained as documented). Coverage ledger REPRODUCED — no
  requirement row moved; coverage stays **74.8% (38.90/52)**.
  `requireGates()` fail-closed (4/4).

- **Phase 9 (2026-10-17):** `npm test` exit 0 — test 600/600, pack-tests
  3,982/3,982, audience-tests 2,906/2,906, asset-tests 7,522/7,522,
  consistency 216/216, rehearsal 78/78, importers 49/49, agent-policy 91/91,
  agent-workflows 57/57, finding-evidence 31/31, secret-candidates 35/35,
  eval-tests 39/39, doc-drift 119/119, determinism 5/5 — **15,730 assertions
  total** (runner sums recomputed; +32 vs Phase 8 15,698 = secret-candidates
  +15 promotion-boundary, eval-tests +2 cohort pins, pack +4 (DPK-SEC-108),
  audience +3, asset +8, consistency same count re-pinned). Corpus counts
  CHANGED WITH CAUSE: rules **954 = 792+97+65**, patterns **954**, records
  **914**, remediation **954**, cwe 61 — one evidence-gated rule
  (DPK-SEC-108, GAP-013 8-11 mixed-class window) with 16 executed tests,
  LOW confidence, placeholder-vetoed, disjoint from DPK-SEC-063/107; all
  count documents reconciled (README, REQUIREMENTS_MATRIX, CORPUS_TARGETS
  totals.validated 2080, COVERAGE_MAP, AUDIENCES.md, CORPUS_GAP_REPORT,
  CAPABILITY_COVERAGE) — no padding, no duplicate patterns (dup-review
  snapshot re-pinned 32 groups/87 rules: ruby backtick diverged from perl
  on language-native #{} interpolation). Eval populations scored per cohort
  (core 12/0/1 documented FP; sql-concat-xlang 16/0/0; cmd-injection
  13/0/0; secret-userinfo 5/0/0; 46 TP / 0 FN / 1 FP totals; 11 UNASSESSED
  excluded; trap execution rate 32/32 = 100%). SoT audit: 0 orphans, 0
  mirror mismatches, 0 unused patterns, 0 missing remediation. Coverage
  ledger REPRODUCED — no requirement row moved; coverage stays **74.8%
  (38.90/52)**. `requireGates()` fail-closed (4/4).

- **Master Completion Pump (2026-10-17):** baseline re-restored at
  `800445f` (clean tree, HEAD == remote tip) and FULLY REPRODUCED before
  any edit: `npm test` exit 0 — tests 600/600, pack-tests 3982/3982,
  audience-tests 2906/2906, asset-tests 7522/7522, consistency 216/216,
  rehearsal 78/78, importers 49/49, agent-policy 91/91, agent-workflows
  57/57, finding-evidence 31/31, secret-candidates 35/35, eval-tests
  39/39, doc-drift 119/119, determinism 5/5 — **15,730 assertions total**
  (same runner sums as Phase 9). Validators: packs 957, assets 1868,
  audiences 995, cwe 61, matrix ("no license file"), sources 1, corpus 3 —
  all PASS. Inventory re-recomputed UNCHANGED (954 = 792+97+65 rules, 954
  patterns, 914 records, 954 remediation, 61 cwe, 89 test-only eval cases):
  no new rules were authored. Probe battery (evidence-first, tests-first)
  over the generated detectors: assignment space (env export/DB_PASSWORD=,
  YAML password:, ADO Password=, PGPASSWORD=, quoted JDBC/Kafka) fully
  covered by DPK-SEC-106/007; userinfo family covered by DPK-SEC-063/107/
  108; the 6-7 alnum userinfo window is NOT authored because committed
  ground truth (EVAL-SEC-104: no-issue below 8, DPK-SEC-108 forbidden to
  fire) contradicts authoring — the evidence gate fails closed (GAP-026
  records the ratification decision). Ledger reconciliation: R-SEC-P-05
  stale accounting corrected 43/46 → **46/46 VERIFIED_FULL** (named
  subrequirements from the original row: 42 classes + Shopify DPK-SEC-105
  + 3 GAP-013 probe-gap rule items = DPK-SEC-106 ×2 + DPK-SEC-107 ×1, all
  authored with committed evidence and tests in Phases 5–9; the row never
  advanced after Phase 5). GAP-021 closed (cweVersion 4.20 on 61/61 since
  Phase 5, validate-cwe enforced). COVERAGE_MAP BE-2 moved to
  resolvedExpansions. Coverage recomputed on the unchanged formula and the
  unchanged 52-row denominator: **74.9% (38.97/52)** (was 74.8% (38.90/52)
  — only R-SEC-P-05's stale partial score advanced; no denominator or
  weight changed). `requireGates()` fail-closed (4/4); publication NO-GO
  unchanged (D-1/D-2, GATE-1..4, BLK-003/004 all still BLOCKED external).
