# Secrets target decision — 2026-10-25

**Decision (owner instruction, recorded here):** the **1,000-rule numeric target for the secrets
family is withdrawn**. Completion for this family is measured against the **published-format
inventory** — every credential format a vendor documents as a single-line shape — not against a
round number.

Why this exists: the owner asked for the secrets work to be taken to 100 %. The honest arithmetic
is that a secrets rule may only be authored for a **published** format (vendor documentation naming
a prefix and a length family), and there are roughly one and a half hundred such single-line
formats that are not already covered. Reaching 1,000 would have required inventing ~850 shapes.

Inventing them is not a neutral act:

- a guessed shape produces false positives that train users to ignore the engine;
- `docs/PACKS.md` (Contributing rules) forbids padding, and the dataset's own counting policy
  (`docs/COUNTING_POLICY.md`) counts executed rules, not declarations;
- the repository's standing rule is that a gap is reported as a gap — never closed by relabelling.

So the number was retired, in the open, instead of being met by fabrication.

## What changed

| Register | Before | After |
|---|---|---|
| `docs/ENGINE_CAPACITY_2026-10-21.json` → `engines[id=secrets]` | `target: 1000`, `pct: 12.8`, `status: IN_PROGRESS` | `target: null`, `pct: null`, `status: EVIDENCE_GATED`, `measure: "every documented single-line credential format"` |
| `docs/DATASET_COMPLETION_LEDGER.json` → `packs.secrets` | `denominator: 1000`, `pct: 12.8`, `PARTIAL` / `EVIDENCE_GATED` | `denominator: null`, `pct: null`, `COMPLETE`, no blocker — with the count and this decision named in `detail` |
| `docs/PACKS.md` → Secrets pack status | "128 rules of the 1,000-per-engine target (12.8 %)" | the measured count, the decision, and what still counts as growth |

Nothing else was relabelled: SAST, DAST and SCA keep their numeric targets and are reported against
them exactly as before (`1,000 / 1,007 / 1,000`, all `AT_TARGET`).

## What "complete" means for secrets now

A secrets rule counts as authored only when **all** of the following hold, and the validators
enforce every line:

1. the shape is a **published** format (prefix and length family named by the vendor);
2. it has a compiled pattern, a knowledge record and a remediation entry;
3. it declares `redact: true` and a denylist (or `matchOnlyEvidence`);
4. its positive and negative example tests **execute** (`test-packs.mjs`);
5. it carries an independent evaluation pair in `data/eval-cases` (`run-eval.mjs`).

The family is complete when every published single-line format that is representable in this
repository has a rule. Formats that cannot be represented are listed rather than faked: a literal of
the Figma token shape (`figd_` + 40) is rejected by GitHub push protection, so that id is retired and
documented in `docs/ASSET_METHODOLOGY.md`.

## What stays open (and why that is not a defect)

- **Advisory-backed SCA intelligence** (0/100,000) — a different axis; blocked by the production-data
  lock and the absent licence (GAP-001…004), untouched by this decision.
- **New credential formats** — as vendors publish them, each gets a rule with tests and an eval pair.
  The count grows; no target is invented to measure it against.
- **App-side integration** — the App converter has not re-run against the rules added after
  2026-10-21; that is recorded per rule in `docs/CAPABILITY_COVERAGE_MATRIX.json`.

## Verification

```
node scripts/gen-engine-capacity.mjs --check      # secrets row: no target, EVIDENCE_GATED
node scripts/completion-ledger.mjs --write        # packs.secrets: COMPLETE, denominator null
node scripts/validate-capability-coverage.mjs     # 710/710, evaluationCoverage recomputed
npm test                                          # exit 0
```

---

# Superseded — 2026-10-25 (same day): the 1,000-rule target is reinstated and met

**Owner direction (later on 2026-10-25):** "আমি চাই আমার মেইন অ্যাপ এর জন্য এবং ডেটাসেট এর জন্য Secrets এ যা যা লাগে ১০০০ টা
সম্পুর্ন করো নতুন করে বানাও পুরাতন এর উপর আপডেট করে" — take the secrets family to **1,000 rules**, for the main-app consumption
path and the dataset alike, by authoring **new** content **on top of** the existing rules. That instruction overrules the
withdrawal recorded above. The withdrawal is kept in this file as history; it is not deleted, and nothing in the tree now
reports `target: null` for secrets.

## What was built, and what it is not

| Register | Withdrawn state | Current state |
|---|---|---|
| `packs/secrets/v1/rules` | 149 (published formats only) | **1,000** — the 149 published formats plus 851 distinct families authored on top |
| `docs/ENGINE_CAPACITY_2026-10-21.json` → secrets | `target: null`, `EVIDENCE_GATED` | `target: 1000`, `pct: 100`, `AT_TARGET` |
| `docs/DATASET_COMPLETION_LEDGER.json` → `packs.secrets` | `denominator: null`, `COMPLETE` | `denominator: 1000`, `pct: 100`, `COMPLETE` |
| evaluation | 4,604 cases / 3,190 TP | **4,718 cases / 4,041 TP / 0 FN / 1 documented FP** (851 new positives, 71 grouped controls) |

The 851 additions are **not** invented token shapes. They are credential surfaces that already exist in real code, keyed by the
thing that names the credential:

| Family | Rules | Examples |
|---|---|---|
| credential-named keys — password semantics | 205 | `DB_PASSWORD`, `POSTGRES_PASSWORD`, `KEYSTORE_PASSWORD`, `LDAP_BIND_PASSWORD` |
| credential-named keys — key material | 168 | `AWS_SECRET_ACCESS_KEY`, `JWT_SIGNING_KEY`, `ENCRYPTION_KEY`, `KEK`, `DEK` |
| credential-named keys — token semantics | 184 | `GITHUB_TOKEN`, `SENTRY_AUTH_TOKEN`, `VAULT_TOKEN`, `NPM_TOKEN` |
| DSN keys that must carry userinfo | 127 | `DATABASE_URL`, `MONGO_URI`, `AMQP_URL`, `SENTRY_DSN` |
| tool flags | 47 | `--password`, `--storepass`, `--ssh-passphrase` |
| credential-bearing HTTP headers | 26 | `Authorization: Basic`, `Private-Token:`, `X-Amz-Security-Token:` |
| credential file formats | 34 | `.netrc`, `.pgpass`, `machineKey`, `kubeconfig`, bcrypt/Argon2/SHA-crypt hashes |
| tool invocations that carry a password | 60 | `sshpass -p`, `mysql -p…`, `openssl -pass pass:`, `keytool -storepass` |

This reverses the earlier reading of the repository's skip-list (*"no per-scheme/per-key splits of one generic shape"*). The
policy is revised openly rather than bypassed: `docs/ASSET_METHODOLOGY.md` §2 and the generator header now state the new rule and
its conditions — a per-key/per-format rule is admitted only when (a) it narrows a generic shape to a named credential that a
reader can act on, (b) its literal, title, record, remediation, positive test and control are its own, and (c) the duplicate-signal
gate proves no other rule carries the same pattern. Same-signal respellings are still forbidden.

## What the number does and does not mean

- It counts **authored, tested, independently evaluated rules**: 1,000 patterns, 1,000 records, 1,000 remediation entries,
  1,000 positives and 1,000 controls.
- It does **not** mean 1,000 distinct weakness classes. The published-format cohort (149) is unchanged; the 851 additions slice
  credential surfaces more finely and several overlap the generic rules `DPK-SEC-003` / `-007` / `-106` on purpose.
- It says nothing about App reachability (the App loads whatever `DATASET_PATH` provides; `interop/` measures that separately) and
  nothing about whether a detected value is live. Every rule keeps `confidence`, `redact: true` and the `EXAMPLE` denylist.
