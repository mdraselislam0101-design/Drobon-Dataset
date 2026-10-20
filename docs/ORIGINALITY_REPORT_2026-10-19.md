# ORIGINALITY_REPORT_2026-10-19.md — duplication and provenance verification

Scope: the authored intelligence tree (954 pack rules, 954 patterns, 914 concept
records, 954 remediation entries). Read-only, deterministic, no network.
Tool: `scripts/originality-report.mjs` (new; `npm run originality`,
`npm run originality:check` in `npm test` and CI).

## 1. Method

| Check | Rule |
|---|---|
| Duplicate canonical ids | per class: rule id, pattern id, record id, remediation `ruleId` |
| Exact duplicate content | JSON with identity fields removed (records: `id`/`cell`/refs; remediation: `ruleId`) |
| Near-duplicate wording | token 4-shingle Jaccard; records and rules on title+description, remediation on `whyItMatters`; report bands ≥0.85 / ≥0.90 |
| Repeated remediation | exact identical `whyItMatters` strings |
| Provenance hygiene | `origin` declared on patterns/records; no `source`/`sourceUrl`/`retrievedAt`/`license` on authored assets |
| Cross-references | rule↔pattern, pattern↔rule, record↔pattern/rule, remediation→rule |

Exit code 1 only for **hard defects**: duplicate ids, exact duplicate record
bodies, broken references, unexpected `origin`. Similarity output is a **review
flag** for a human; it is not evidence of copying, and absence of flags does not
prove independent authorship of ideas.

## 2. Results — final run (2026-10-19)

| Result | Count |
|---|---|
| Hard defects | **0** |
| Duplicate ids (all classes) | 0 |
| Exact duplicate record bodies | 0 |
| Broken cross-references | 0 |
| Rules without a pattern | 0 |
| Patterns without a record | **40** (pre-generator legacy set; owner decision D-13, see §4) |
| Record wording pairs ≥ 0.85 | **0** of 417,233 compared (highest 0.714) |
| Rule wording pairs ≥ 0.90 | **1** of 454,581 (artifact — see §3) |
| Remediation `why` pairs ≥ 0.90 / ≥ 0.85 | **8** / **19** of 386,038 (highest 1.0) |
| Exact repeated `whyItMatters` | **0** after the fixes in §3 |

## 3. Findings and disposition

**Fixed in this pump.** The first run found one pair of remediation files with
byte-identical bodies (`DPK-SAST-782`/`-783`) and five exact-repeated
`whyItMatters` groups (`782/783`, `792` with `793`–`796`). Root cause: two cell
classes authored language-agnostic text, and sibling language cells therefore
emitted identical remediation. The class-level wording now names the language
(`{lang}`), the generator was re-run, and **7 remediation files** were
regenerated. Exact duplicates and exact repeats are now **0**.

**Remaining flags — accepted with a documented caveat.** The 8 near-duplicate
`why` pairs (e.g. `DPK-SAST-038`/`-049`, `-184`/`-185`, `-416`/`-417`) and the
single rule-description pair are sibling language/framework rules whose
explanatory text is authored once per detection class. Their identity, regex and
language differ; only the class explanation is shared. Additionally, the
shingle tokenizer ignores tokens of length ≤ 2, so language tags such as `c`,
`r` or `js` collapse — part of the measured similarity is an artifact of the
method, not of the content.
Caveat: if remediation is ever surfaced per rule in product, class text should
be diversified per language. This is recorded as remaining work, not ignored.

## 4. The 40-pattern gap

`patterns 954 / records 914` is a structural asymmetry, not a duplication
finding: `DPK-SAST-001..022`, `DPK-SEC-001..008`, `DPK-DAST-001..010` have a
rule, a pattern and remediation, but no concept record.

Closing it is owner decision **D-13** (`BLOCKED_OWNER_DECISION`; the recorded
decision reserves “create or keep the retention exception” to the owner). A
complete, validated proposal — 40 authored records, the exact generator patch
and an activation checklist — is parked at
`docs/proposals/D13-legacy-records/`. **No records were created in this pump**
and no count or status changed.

## 5. Limitations

- No lexical check can establish independent creation. Public catalogs were not
  consulted (production lock), so the tool can detect internal duplication and
  provenance anomalies but cannot prove absence of external derivation.
- Paraphrased reuse and translated text score low under shingles; short tokens
  (language tags such as `c`, `r`) are ignored, inflating similarity for
  sibling rules.
- Provenance for authored content is a declaration (`origin:
  "original-authored"`) plus the authoring method in `docs/ASSET_METHODOLOGY.md`;
  it is not an external attestation.
- Remediation duplicates are structural (one fix per class); the count will not
  reach zero without per-language authoring.

## 6. Re-run

```
node scripts/originality-report.mjs          # human summary
node scripts/originality-report.mjs --json   # machine summary
node scripts/originality-report.mjs --check  # hard-defect gate
```

---

## 7. Update — evaluation-layer originality (same day, later batch)

The tool now also checks the independent evaluation layer, because an eval case
is an authored asset too:

| New check | Rule |
|---|---|
| Duplicate eval case | identical fixture (lines or observation) **and** identical expectation (detections + forbidden ids) |
| Case provenance | every case must declare `provenance.origin: "original-authored"` |
| Case → rule reference | every rule named by a case must exist in the packs |

Re-run after the evaluation-breadth batch (132 cases, 58 distinct rules):

| Result | Count |
|---|---|
| Hard defects (all checks incl. eval layer) | **0** |
| Duplicate eval cases | **0** |
| Cases with non-original origin | **0** |
| Cases referencing unknown rules | **0** |

The 43 cases added in this batch were each written from the rule's own
documented mechanism. No case reuses another product's corpus, and no case
reuses another case's fixture.
