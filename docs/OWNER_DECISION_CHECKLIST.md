# OWNER_DECISION_CHECKLIST.md — answer sheet for the owner (plain language)

Date: 2026-10-14. Each item is one decision. Reply with the decision ID,
your choice (A/B/C), your name, and today's date. Example reply line:

`D-GHSA: choice B, by Jane Owner, 2026-10-15`

This checklist, and any filled copy of it, is NOT consent by itself. A
decision takes effect only when the owner reply is recorded in
`docs/OWNER_DECISIONS.json` / `docs/INGESTION_GATES.json` (decider + date),
the suite is green, and the change is committed. Until then everything
stays `OWNER_DECISION_REQUIRED` / `BLOCKED`. States: `BLOCKED` (no path),
`READY_FOR_OWNER_REVIEW` (evidence ready, awaiting your answer below),
authorized (your recorded answer + green suite — nothing is there yet).

## D-GHSA — GitHub reviewed advisories (npm + PyPI)

Facts: upstream repo says CC-BY-4.0 (credit + license link + change notes).
Withdrawn advisories are always excluded. Per-batch license check required.

- A: Yes, ingest reviewed-only GHSA batches with per-record CC-BY-4.0
  credit. Consequence: unlocks GHSA pilot batches (still needs D-STAGE,
  D-REVIEW, D-PROVIDER).
- B: Yes, but a lawyer reviews the first batch first. Consequence: GHSA
  waits for that review; nothing ingested meanwhile.
- C: No / not now. Consequence: GHSA stays blocked; no GHSA records.

## D-OSV — OSV aggregated vulnerabilities (npm + PyPI)

Facts: OSV has NO single license; each home database sets its own terms.
Unmapped homes are excluded automatically (fail-closed).

- A: Yes, ingest with per-record home-terms checks, and I accept these
  home terms: ___ (list them, e.g. "only CC-BY-4.0 and public-domain
  homes"). Consequence: unlocks OSV pilot batches for listed homes only.
- B: Yes, but the agent must show me the home-terms list for approval
  before every batch. Consequence: slower, batch-by-batch approval.
- C: No / not now. Consequence: OSV stays blocked; no OSV records.

## D-NVD — NVD CVE feeds

Facts: data is public-domain but a product notice is required, API keys
have Terms of Use, and no app need for NVD is verified today.

- A: Yes, there IS a verified need: ___ (describe it), and I authorize
  getting an API key under the NVD Terms of Use. Consequence: NVD pilot
  path opens (still needs D-STAGE, D-REVIEW, D-PROVIDER).
- B: Keep blocked, no NVD work. Consequence: nothing changes.
- (There is no "ingest now" option: need + key + notice must come first.)

## D-CWE — CWE definitions

Facts: royalty-free including commercial use; copies must reproduce the
notice. Current scope copies NO MITRE text (own summaries + links).

- A: Yes, the own-words-plus-links scope is fine. Consequence: CWE scope
  confirmed; summaries still need D-ORIG for their own license.
- B: No / I want changes: ___. Consequence: scope stays unconfirmed.

## D-ORIG — Original Drobon content license

Facts: NO license exists today (all rights reserved by default). This
covers packs, remediation, lessons, templates, engagements, vectors,
CWE summaries, and planning docs.

- A: License it as: ___ (name the license, e.g. "CC-BY-4.0") for this
  scope: ___ (e.g. "everything" or list asset classes). Consequence: a
  LICENSE file is added and reuse terms exist.
- B: Keep all rights reserved (no reuse by others). Consequence: content
  stays project-internal; distribution stays blocked.
- C: Different licenses per asset class: ___ (list them).

**ANSWER RECORDED 2026-10-17** (owner statement in conversation, verbatim in
`docs/LICENSE_DECISION_RECORD.md` §7): **PROPRIETARY** — "DROBON original
content remains under DROBON control; no redistribution except explicitly
authorized use. Third-party source rights remain separate and must be
verified." This is the proprietary/all-rights-reserved direction (B-style
treatment with explicitly-authorized-use carve-out). **Not yet in effect as a
grant:** grant text unreviewed (PROPRIETARY_LICENSE_DRAFT stays DRAFT — NOT
APPROVED), no LICENSE file installed, ownership evidence outstanding. Third
parties (D-GHSA/D-OSV/D-NVD/D-CWE) are unaffected and stay undecided.

## D-STAGE — production-data stage approval (GATE-1)

- A: I approve stage: ___ naming source(s): ___ , maintainer: ___ ,
  license basis per source: ___ . Consequence: GATE-1 can be satisfied
  for that stage only.
- B: Not approved. Consequence: all ingestion stays blocked.

## D-REVIEW — human review capacity (GATE-3)

- A: Reviewer(s): ___ commit to opening EVERY source URL for batches up
  to ___ records, following the HONESTY checklist. Consequence: GATE-3
  can be satisfied within that capacity.
- B: No commitment. Consequence: all ingestion stays blocked.

## D-PROVIDER — app-side provider design (GATE-4, app workstream)

- A: The app maintainers accept provider design: ___ (link the app-repo
  design: range policy, zero-match semantics, config-lock change,
  consumer contract). Consequence: GATE-4 can be satisfied.
- B: No design accepted. Consequence: ingestion stays blocked (data would
  have no verified consumer).

## D-CADENCE — approval expiry and refresh policy

Facts: no expiry semantics exist; until you set them, any approval is
single-batch and non-extending.

- A: Approvals last: ___ (e.g. "90 days / 5 batches"), corpus refresh
  cadence: ___ . Consequence: dates are enforced from then on.
- B: Keep single-batch approvals. Consequence: every batch needs a fresh
  recorded approval.
