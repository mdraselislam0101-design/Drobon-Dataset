# FINDING_EVIDENCE_CONTRACT.md — Phase 6 Work D (2026-10-17)

Machine-verifiable evidence contract for DROBON findings and reports.
Implemented by `scripts/finding-evidence.mjs` (`drobon.finding.evidence/v1`)
and tested by `scripts/test-finding-evidence.mjs` (24/24). Dataset-side
contract and synthetic tests only: no App runtime or database changes.

## 1. Confirmed-finding evidence requirements

A confirmed finding must, when applicable, be traceable to the fields below.
The extractor COMPUTES every location from actual scanned text; **nothing is
ever invented** (source code, line numbers, scores, signatures, timestamps,
or test results). A span that cannot be located yields an explicit error.

| Requirement | Field(s) | Rule |
|---|---|---|
| Scanned source snapshot / commit identity | `snapshot.snapshotId`, `snapshot.commitId` | commitId recorded only when a real hex id is supplied (7–40 hex chars); otherwise omitted |
| Exact file path and line range | `location.path`, `location.lineFrom..lineTo` | computed from text offsets; multi-line spans supported |
| Actual source excerpt + context | `source.excerpt`, `source.matchedText`, `source.context[]`, `contextFrom/To` | excerpt = the actual matched line; context = ±2 lines |
| Language / framework context | `analysis.language`, `analysis.framework` | language from path extension; framework only when declared; unknown ⇒ `null` |
| Detection/analysis method | `analysis.method` | e.g. `line-regex`, `observation`; always named |
| Data-flow / call-chain evidence | `dataFlowEvidence`, `callChainEvidence` | `NOT_ASSESSED` with a note while no such analysis exists — absence is explicit, never faked |
| Confidence and uncertainty | `confidence.level`, `confidence.uncertainty` | shape matches are `SHAPE_MATCH` with mandatory uncertainty text |
| Severity / CWE / CVSS | `cwe`, `severity` (optional) | carried ONLY from a declared rule (validated format); **CVSS is never invented** — field absent by design under the production lock |
| Why this is a security issue | `whyItMatters` | separate from source text |
| Proposed remediation | `remediation` | always a separate field (filled from `knowledge/remediation/`), never merged into source |

## 2. Finding identity (scan-to-scan)

`findingId = FIND-<sha256(ruleId, path, normalized-span)[0:16]>` —
`identityOf()` in `finding-evidence.mjs`. Line numbers deliberately do not
participate: identity is **stable across line shifts** when the cited evidence
content is unchanged (tested). When the span content changes at the same site,
the finding is `CHANGED_REQUIRES_REVIEW` — identity mapping is only claimed
where the evidence supports it. Who made a change and why are never inferred.

## 3. Remediation-tracking statuses

`classifyTransition(prevFinding, currScan, opts)` returns exactly one of:

| Status | Meaning | Required evidence |
|---|---|---|
| `FIXED_VERIFIED` | issue absent and fix positively verified | span absent in current scan AND the file WAS covered by that scan AND explicit `fixEvidence {note, snapshotId}` supplied |
| `PARTIALLY_FIXED` | some evidence spans fixed, others remain | multi-span finding with mixed FIXED_VERIFIED / STILL_PRESENT spans |
| `STILL_PRESENT` | identical evidence still observed | span content found in current scan (line may have shifted) |
| `CHANGED_REQUIRES_REVIEW` | same site, different evidence content | `currentMatch.excerpt` differs from the prior span |
| `NOT_OBSERVED_UNVERIFIED` | not seen — proof unknown | DEFAULT for absence: disappearance alone is **not** proof of remediation; also used when the file was not covered by the current scan or input is malformed |

Precedence: any CHANGED span > all-still > all-fixed > mixed-fixed/present
(PARTIALLY_FIXED) > otherwise NOT_OBSERVED_UNVERIFIED. Malformed inputs never
throw and never yield a confirmed/fixed status.

## 4. What this contract deliberately does not do

- No App runtime/scan-store/database implementation (app workstream, CGM-G4).
- No CVSS/OWASP scoring (GAP-010; production lock; owner decisions D-1/D-2 open).
- No attribution of changes to people or intents.
- No promotion of synthetic fixtures to production intelligence (eval cases
  are `testOnly`; corpus counts exclude them).

## 5. Synthetic demonstration

`scripts/test-finding-evidence.mjs` exercises all five statuses against
synthetic before/after snapshots (line-shift stability, disappearance ≠
remediation, change detection, partial fixes). These are synthetic tests of
the contract — they do not claim any live scan has been tracked.
