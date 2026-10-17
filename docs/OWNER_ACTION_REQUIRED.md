# OWNER_ACTION_REQUIRED.md — decisions only the owner can make

Date: 2026-10-14. Companion to `docs/OWNER_DECISIONS.json` (all 5 entries
`OWNER_DECISION_REQUIRED`) and `docs/INGESTION_GATES.json` (all 4 gates
BLOCKED). Agent research in `docs/LICENSE_REVIEW.md` is evidence, never
authorization. Nothing below is decided until the owner replies in writing;
the reply must name the decider and date so the registers can record it.

## 1. Per-source license decisions

### GHSA (reviewed advisories, npm + PyPI)
- Lay finding: CC-BY-4.0 (repository LICENSE.md); withdrawn advisories must
  be excluded; per-batch license-field resolution still required.
- Decide: (a) authorize GHSA batches for production ingestion with per-record
  CC-BY-4.0 attribution (license link + change notes)? (b) confirm scope:
  reviewed-only, withdrawn-excluded, `advisory-record` full schema fields?
  (c) counsel review needed before first batch?

### OSV (aggregated vulnerabilities, npm + PyPI)
- Lay finding: NO single OSV license — terms differ per home database.
- Decide: (a) authorize the per-record home-terms resolution policy with
  fail-closed exclusion? (b) which home terms are acceptable (e.g. only
  CC-BY-4.0 / public-domain homes)? (c) who resolves unmapped homes?

### NVD (CVE feeds)
- Lay finding: public-domain data but notice + API Terms of Use + rate limits
  (5/50 per 30s) still apply; NO verified consumer need today; no key used.
- Decide: (a) is there a verified consumer need for NVD data? If no, keep
  blocked. (b) if yes, authorize API-key acquisition under the NVD Terms of
  Use and approve the product-notice placement?

### CWE (definitions)
- Lay finding: royalty-free including commercial use, reproduce-notice on
  copies; current scope copies no MITRE text (own-words + links).
- Decide: confirm the own-words-plus-links scope needs no further clearance.

### Original Drobon content
- Fact: NO license grant exists (no LICENSE file; all rights reserved).
- Decide: choose license(s) + scope per asset class (packs, remediation,
  lessons, templates, engagements, vectors, CWE summaries, planning docs),
  then add the grant file(s) and update the decision register + matrix.

## 2. Ingestion-gate evidence

- GATE-1: written stage approval naming stage, source(s), maintainer, and
  license basis per source.
- GATE-3: named reviewer(s) + capacity statement (a human opens every
  source URL; no bulk unreviewed ingest ever).
- GATE-4 (app workstream): provider design accepted — range policy,
  zero-match semantics, config-lock amendment, consumer contract.
- Policy gap (no semantics exist yet): approval expiry / re-review cadence
  and corpus refresh cadence. Owner to set both; until then, any approval
  is single-batch and non-extending.

## 3. What stays blocked meanwhile

All production ingestion (importers exit 1), all per-category volume
promises (volumes stay null / NOT_MEASURED), and any release (NO-GO).
Synthetic rehearsals continue; they never count toward production.

## 4. Prepared decision packages (2026-10-17 blocker-resolution pump)

The evidence each decision above needs is now prepared — nothing is decided
by preparing it:

- GATE-1 approval template (fill every field): `docs/INGESTION_PROTOCOL.md` §12
- GATE-3 reviewer checklist + package + sign-off format: `docs/REVIEW_PACKAGE.md`
- GATE-4 provider acceptance requirements (P1–P9):
  `docs/DATASET_APP_CONTRACT.md` §9
- Per-source rights checklist: `docs/SOURCE_RELEASE_GATE.md` S1–S6;
  draft grant (**DRAFT — NOT APPROVED**): `docs/PROPRIETARY_LICENSE_DRAFT.md`
- Source-liveness/staleness design + cadence record (D-CADENCE fills
  `docs/INGESTION_PROTOCOL.md` §13.3): §13
- Per-subject open questions incl. retention: `docs/OWNER_DECISION_PACKET.md`
  addendum P1; blocker details + verification commands:
  `docs/BLOCKER_REGISTER.json`

Reply format reminder: decision ID + choice + decider + date (see
`docs/OWNER_DECISION_CHECKLIST.md` header).

## 6. Pump 5 owner decisions (2026-10-15)

Nothing below is decided. Each item needs a written reply that names the decider and the date. Evidence and options are in `docs/PACKS.md` (Pump 5) and `docs/FORMAT.md`.

1. **PEP 440 exclusive-bound defects D1–D3** (`docs/FORMAT.md`). **Status (Pump 7): resolved.** D1–D4 were fixed in Pump 6 and D5 in Pump 7, under the Pump 6/7 briefs; no further decision is needed. The original question is kept for the record. The engine violated three MUST requirements. (a) Approve a fix to `satisfiesRange` (`>V` excludes post-releases of V unless V is a post-release; `<V` excludes pre-releases of V unless V is a pre-release; reject local versions in bounds), with the pinned `KNOWN DEFECT` rows and the Main App provider updated together? Or (b) record the current behaviour as the provider contract?
2. **npm prerelease policy** (`docs/FORMAT.md`). Adopt npm's default (a prerelease needs a comparator with the same major.minor.patch and a prerelease tag), keep inclusion, or make it configurable?
3. **PyPI pre-release default** (`docs/FORMAT.md`). PEP 440 SHOULD exclude pre-releases by default. Keep inclusion, adopt the default, or make it a per-coordinate flag?
4. **Secrets veto test design** (`docs/PACKS.md`, Secrets OPEN GAP). **Status (Pump 7): rule-level regression in place** in the existing `scripts/test-packs.mjs` (in-memory fixtures, no new file); the three original mutants and the Pump 7 generator mutants are detected. Options (a) and (b) are no longer needed for this. The original question follows. Three veto mutants survived. Choose (a) `test-assets` applies the rule's denylist to mirrored `ruleRef` examples, or (b) the generator stops mirroring veto-only negatives.
5. **DPK-SEC-007 denylist** (`docs/PACKS.md`). Add `${` and `<` to veto `<password>` and `${DB_PASSWORD}` false positives? This could also veto real values that contain `${`.
6. **Secrets probe gaps** (`docs/PACKS.md`). Approve new secrets rules (new files) for JDBC `password=`, ADO `Password=`, unquoted `DB_PASSWORD=` and `export DB_PASSWORD=`, unquoted YAML `password:`, and URIs with symbol passwords?
7. **Hyphenated language ids** (`docs/PACKS.md`). Change the schema regex and the pinned test to allow `github-actions`, `shell-posix`, and `android-manifest`? Or keep them out of the Dataset?
8. **DPK-SAST-018 `python` tag** (`docs/PACKS.md`). No Python-shaped test exists. Keep the tag and add a Python test, or remove the tag?
9. **`bash` tag on the 25 `shell` rules** (`docs/PACKS.md`, Language-id count). Pump 4 added this through the generator. It is not in base commit `dd487175`. Confirm it?
10. **CROSS_CWE 13 groups** (unchanged from Pump 3). Owner/CWE review still open. CWE-470 is not in any group.
11. **Records for the 40 legacy patterns** (new files). Create them, or keep them as the legacy retention exception?

## 7. Pump 7 owner decisions (2026-10-15)

Nothing below is decided. Each item needs a written reply that names the decider and the date.

1. **Confirm the generator denylist change** (`scripts/generate-assets.mjs`, `runLineTests`). The denylist was case-sensitive and is now case-insensitive, as `docs/PACKS.md` documents. Generator output is byte-identical (0 changed files). Confirm, or ask for a different correction?
2. **`universal` language id on 10 SAST rules** (DPK-SAST-026, -063, -138, -190, -247, -277, -307, -361, -409, -448). The Main App has no `universal` family. Its convention for "any file" is to omit `languages`, as DPK-SAST-004 does. These 10 rules can never run in the Main App. Remove the `languages` field from each (rule change), or keep the tag and accept that they are unreachable?
3. **Hyphenated and alias ids** (`shell-posix`, `github-actions`, `android-manifest`, `gha`, `k8s`, `compose`). Keep these out of the Dataset, change the schema for hyphenated ids (see §1), or accept the existing alias mapping? Aliases to `github-actions` or `yaml` would be broadening, so they are not proposed here.
4. **`shell` vs `shell-posix` vs `bash`.** The 25 `shell`/`bash` rules reach only extensionless bash scripts. Ordinary `.sh` files are `shell-posix`, which has no Dataset rule. Add `shell-posix` (needs item 3), or accept PARTIAL reach?
5. **DPK-SAST-018 `python` tag** (repeats item 8 of §6). Still no Python test evidence, and its patterns are HCL-shaped. Keep it with new Python tests, or remove the tag?
6. **CWE version pinning.** The MITRE relationships were read from the 4.20 page. The Dataset stores no CWE version and no hierarchy. Pin a CWE version for `knowledge/cwe/`, or leave it unpinned?
7. **D5 local labels with `-` or `_`** (for example `1.0+ubuntu-1`). These are spec-valid, and the parser rejects them fail-closed. Widen the local-label grammar (in `validateRange` and `parsePypiVersion`), or keep the rejection?

