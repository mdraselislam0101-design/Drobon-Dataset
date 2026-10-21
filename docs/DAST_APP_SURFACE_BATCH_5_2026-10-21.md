# DAST app-surface batch 5 — 2026-10-21

Status: **PARTIAL** — DAST **398** of the 500 planning target (79.6 %);
**325 of 398 rules are evaluable inside the Main App** (81.7 %). Body evidence only: no
rule in this batch reads a header, so the unreachable set is unchanged at 73.

App reference (read-only): `mdraselislam0101-design/Drobon` @ `9360dd1`.

## 1. What this batch covers

| Area | Why it was missing | New rules |
|---|---|---|
| Framework development overlays | The pack knew Symfony, Laravel, Django, CakePHP, Yii and CodeIgniter exception pages, but not the toolbars and build overlays of Django, Flask, Rails, Next.js, Nuxt and Astro | 401–407 |
| Development consoles | Quarkus Dev UI and Spring Boot Admin were absent; both expose configuration and actuator data for a whole deployment | 396, 397 |
| Orchestration and data-platform consoles | Batch 4 covered the analytics and CI estate; the orchestration, streaming and ML platforms had no rule | 392–395, 398–400 |
| Dependency lockfiles and build definitions | The pack had `package.json` and Compose; every other lockfile and CI definition was invisible, and each pins an exact dependency inventory or a deployment path | 381–391 |
| Served runtime files | `.git` metadata and `web.config` were covered; Apache `server-info`, Functions local settings, development `appsettings`, shell history, SSH `authorized_keys` and the Go expvar handler were not | 377–380, 403 |

## 2. The 31 rules

| Rule | Title | Category | CWE | Severity | Check type |
|---|---|---|---|---|---|
| DPK-DAST-377 | Apache server-info page served | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-378 | appsettings.Development.json served | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-379 | SSH authorized_keys file served | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-380 | Shell history file served from the web root | information-disclosure | CWE-532 | MEDIUM | response-body-matches |
| DPK-DAST-381 | composer.lock dependency lockfile served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-382 | Gemfile.lock dependency lockfile served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-383 | .gitlab-ci.yml pipeline definition served | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-384 | go.mod module manifest served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-385 | Jenkinsfile served from the web root | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-386 | Azure Functions local.settings.json served | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-387 | poetry.lock dependency lockfile served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-388 | .terraform.lock.hcl provider lockfile served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-389 | .travis.yml build definition served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-390 | yarn.lock dependency lockfile served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-391 | .yarnrc file served from the web root | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-392 | Dagster UI is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-393 | Apache Flink dashboard is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-394 | MLflow tracking UI is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-395 | Prefect UI is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-396 | Quarkus Dev UI served | debug-exposure | CWE-489 | MEDIUM | response-body-matches |
| DPK-DAST-397 | Spring Boot Admin console is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-398 | Apache Storm UI is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-399 | TensorBoard is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-400 | YARN ResourceManager UI is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-401 | Astro development toolbar served | debug-exposure | CWE-489 | LOW | response-body-matches |
| DPK-DAST-402 | Django Debug Toolbar disclosed | debug-exposure | CWE-215 | MEDIUM | response-body-matches |
| DPK-DAST-403 | Go expvar endpoint served | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-404 | Flask Debug Toolbar disclosed | debug-exposure | CWE-215 | MEDIUM | response-body-matches |
| DPK-DAST-405 | Next.js development build served | debug-exposure | CWE-489 | MEDIUM | response-body-matches |
| DPK-DAST-406 | Nuxt DevTools overlay served | debug-exposure | CWE-489 | MEDIUM | response-body-matches |
| DPK-DAST-407 | Rails web-console rendered in a page | debug-exposure | CWE-489 | HIGH | response-body-matches |

Totals: **+31 rules, +124 declared tests** (1 722 → 1 846), +31 patterns, +31 records,
+31 remediation entries (1 414 → 1 445 each). No new CWE was needed.

## 3. Why each one is not a restatement

Every candidate ran against every existing rule's positive observations before it was
written. Five were stopped at that step and are not in the table:

| Candidate | Why it did not land |
|---|---|
| H2 console | DPK-DAST-223 already detects the H2 console |
| PHP-FPM status page | DPK-DAST-241 covers the FPM pool status output |
| Hadoop NameNode UI, Spark master UI | 167 and 182 already cover them |
| `wp-config.php` / Drupal `settings.php` | DPK-DAST-261 covers both file shapes |
| `.npmrc` with an auth token | DPK-DAST-237 already detects the npm token file |

Five canonical markers also had to be corrected during the dry run, which is the useful
part of that gate: the Nuxt and Quarkus markers were not present in both positive
fixtures, three console patterns were effectively single-marker because the two markers
differed only by case, and the `yarn.lock` and `.yarnrc` markers assumed a whitespace form
the fixtures did not use. All were fixed in the spec, not in the fixtures.

## 4. Evaluation cases

33 new cases in cohort `dast-app-surface-5-2026-10-21`:

- `EVAL-DAST-629` … `EVAL-DAST-659` — one positive per rule;
- `EVAL-DAST-660` — a production dashboard (host-only cookie, hashed production chunks, no
  toolbar, no lockfile, no served configuration) forbidding all 31;
- `EVAL-DAST-661` — an engineering handbook that names every toolbar, dev UI, lockfile and
  configuration file in the batch without serving any of them, also forbidding all 31.

## 5. Verification

| Command | Result (2026-10-21) |
|---|---|
| `node scripts/generate-assets.mjs` | 398 DAST rules, 1 445 patterns / records / remediation, 0 quarantined |
| `node scripts/test-packs.mjs` | PASS 5 962/5 962 |
| `node scripts/test-assets.mjs` | PASS 11 580/11 580 |
| `node scripts/validate-dast-overlaps.mjs` | PASS — 467 checks, 130 subset pairs, 0 unreviewed |
| `node scripts/validate-app-dast-reachability.mjs --check` | PASS — 325/398 reachable (81.7 %), 73 unreachable across 47 headers |
| `node scripts/gen-app-conformance.mjs --check` | PASS — 398/398 rules merge; 1 831/1 846 declared tests agree with the App-evaluator profile |
| `node scripts/run-eval.mjs` | 1 471 TP / 0 FN / 1 documented FP (`EVAL-SAST-008`); 1 772 cases, 1 761 assessed, 11 unassessed |
| `node scripts/test-eval.mjs` | PASS 43/43 (population pin 1 440 → 1 471) |
| `npm test` | EXIT 0 — 24 496 assertions |

## 6. Limits

- **Distance to 500 is 102 rules.** The plan in `docs/DAST_500_GAP_PLAN_2026-10-21.md` is
  updated with what this batch consumed and what remains.
- **Lockfile rules are inventory disclosure, not vulnerability detection.** They say the
  exact versions are published; they do not consult an advisory database.
- **Console rules still report the shell, not the data behind it.** None of them logs in.
- **Some fixtures are idealised.** The development overlays and toolbars reproduce the
  markers the rules read; they are synthetic documents.
- **No rule here can move the reachable count.** Everything reads the body, so the 73
  header-blocked rules stay blocked until the App widens its forwarded-header list.
