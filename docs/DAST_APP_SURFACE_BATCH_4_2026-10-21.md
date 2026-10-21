# DAST app-surface batch 4 — 2026-10-21

Status: **PARTIAL** — DAST **367** of the 500 planning target (73.4 %);
**294 of 367 rules are evaluable inside the Main App** (80.1 %). A fourth batch
designed from the App's real response surface: every rule reads the response body or
`Set-Cookie`, and no rule reads a header the App filters out.

App reference (read-only): `mdraselislam0101-design/Drobon` @
`9360dd1abdf940cc1bffd942aab0702703aaaaef`.

## 1. What this batch covers

| Area | Why it was missing | New rules |
|---|---|---|
| Administration and data-platform consoles | The pack knew about twenty-odd consoles (Grafana, Kibana, RabbitMQ, Solr, phpMyAdmin, Argo CD, Keycloak…), but the data-engineering and CI estate was uncovered | 345–365 |
| Framework debug toolbars and error templates | Xdebug, VarDumper, ASP.NET and the Node inspector landed earlier; CakePHP, Yii, CodeIgniter, Jetty, IIS, Phoenix, Sidekiq, Telescope and Horizon had no rule | 368–376 |
| Served deployment artefacts | The pack had `.git` metadata, `package.json`, `web.config`, Compose and kubeconfig; the rest of the build and VCS surface had nothing | 335, 338–342 |
| Browser-resolved navigation | `base` and `meta refresh` were covered only in their plaintext form (271, 275); a **secure** cross-origin target was not | 343, 344 |
| Cookie scope contracts | `Domain` was covered for public suffixes and `__Host-`; an address literal and a trailing dot were not | 366, 367 |

## 2. The 42 rules

| Rule | Title | Category | CWE | Severity | Check type |
|---|---|---|---|---|---|
| DPK-DAST-335 | Apache access log served as a response | information-disclosure | CWE-532 | MEDIUM | response-body-matches |
| DPK-DAST-336 | clientaccesspolicy.xml permits every origin | information-disclosure | CWE-942 | MEDIUM | response-body-matches |
| DPK-DAST-337 | crossdomain.xml permits every origin | information-disclosure | CWE-942 | MEDIUM | response-body-matches |
| DPK-DAST-338 | Dockerfile served from the web root | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-339 | Apache error log served as a response | information-disclosure | CWE-532 | MEDIUM | response-body-matches |
| DPK-DAST-340 | Mercurial .hg/hgrc file served | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-341 | phpunit.xml test configuration served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-342 | Subversion .svn/entries file served | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-343 | Base element points at another origin | content-injection | CWE-1021 | MEDIUM | response-body-matches |
| DPK-DAST-344 | Meta refresh sends the browser to another origin | open-redirect | CWE-601 | MEDIUM | response-body-matches |
| DPK-DAST-345 | Apache Druid console is reachable without authentication | information-disclosure | CWE-200 | HIGH | response-body-matches |
| DPK-DAST-346 | Chronograf console is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-347 | Concourse console is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-348 | Drone CI console is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-349 | Gitea console is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-350 | InfluxDB UI console is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-351 | JupyterHub console is reachable without authentication | information-disclosure | CWE-200 | HIGH | response-body-matches |
| DPK-DAST-352 | Kafdrop console is reachable without authentication | information-disclosure | CWE-200 | HIGH | response-body-matches |
| DPK-DAST-353 | Kiali console is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-354 | Metabase console is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-355 | Nagios Core console is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-356 | Neo4j Browser console is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-357 | OpenSearch Dashboards console is reachable without authentication | information-disclosure | CWE-200 | HIGH | response-body-matches |
| DPK-DAST-358 | phpLDAPadmin console is reachable without authentication | information-disclosure | CWE-200 | HIGH | response-body-matches |
| DPK-DAST-359 | Rancher console is reachable without authentication | information-disclosure | CWE-200 | HIGH | response-body-matches |
| DPK-DAST-360 | Redash console is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-361 | Sentry console is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-362 | Superset console is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-363 | TeamCity console is reachable without authentication | information-disclosure | CWE-200 | HIGH | response-body-matches |
| DPK-DAST-364 | Verdaccio console is reachable without authentication | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-365 | Apache Zeppelin console is reachable without authentication | information-disclosure | CWE-200 | HIGH | response-body-matches |
| DPK-DAST-366 | Set-Cookie Domain is an IP address | cookie-flags | CWE-16 | LOW | response-header-matches |
| DPK-DAST-367 | Set-Cookie Domain ends with a dot | cookie-flags | CWE-16 | LOW | response-header-matches |
| DPK-DAST-368 | CakePHP Debug Kit toolbar disclosed | debug-exposure | CWE-215 | MEDIUM | response-body-matches |
| DPK-DAST-369 | CodeIgniter uncaught-exception page disclosed | debug-exposure | CWE-209 | MEDIUM | response-body-matches |
| DPK-DAST-370 | IIS detailed error page disclosed | debug-exposure | CWE-209 | MEDIUM | response-body-matches |
| DPK-DAST-371 | Jetty default error page disclosed | debug-exposure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-372 | Laravel Horizon dashboard disclosed | debug-exposure | CWE-215 | MEDIUM | response-body-matches |
| DPK-DAST-373 | Laravel Telescope dashboard disclosed | debug-exposure | CWE-215 | HIGH | response-body-matches |
| DPK-DAST-374 | Phoenix LiveDashboard disclosed | debug-exposure | CWE-215 | MEDIUM | response-body-matches |
| DPK-DAST-375 | Sidekiq web dashboard disclosed | debug-exposure | CWE-215 | MEDIUM | response-body-matches |
| DPK-DAST-376 | Yii debugger toolbar disclosed | debug-exposure | CWE-215 | MEDIUM | response-body-matches |

Totals: **+42 rules, +168 declared tests** (1 554 → 1 722), +42 patterns, +42 records,
+42 remediation entries (1 372 → 1 414 each), +1 CWE entry (CWE-1021 → 69).

### Why each one is not a restatement

Every candidate ran against **every existing rule's positive observations** before it was
written. Three were stopped at that step:

| Candidate | Why it did not land |
|---|---|
| HashiCorp Nomad UI | Fired on DPK-DAST-236, which already detects the Nomad shell |
| `meta refresh` to any other origin | Fired on DPK-DAST-275, whose fixture redirects to a plaintext host; the class was narrowed to the secure cross-origin form, which 275 cannot match (`http://` literal) |
| `base` element to any other origin | Same subset problem against DPK-DAST-271; narrowed the same way |

The overlap gate held at **130 subset pairs, 0 unreviewed** (436 checks).

## 3. Honest characterisation of the console family

Twenty-one of the 42 rules (345–365) are console fingerprints. They do not describe a new
weakness class: they name a specific administrative product whose shell is served to an
anonymous caller. That is the same evidence model as the twenty console rules that
preceded them (Grafana, Kibana, RabbitMQ, Solr, phpMyAdmin, Argo CD…), and each is a
distinct product with its own title, so the rules are disjoint by construction rather than
by fixture tuning. The rule text states, per product, what the console exposes and why
that matters; the severity is assigned per product (HIGH where the console itself performs
queries, schedules work or provisions accounts).

## 4. Evaluation cases

44 new cases in cohort `dast-app-surface-4-2026-10-21`:

- `EVAL-DAST-585` … `EVAL-DAST-626` — one positive per rule, anchored on a quote-free,
  backslash-free substring of the fixture (the evaluator compares against the
  JSON-serialised observation, so quoted anchors cannot work);
- `EVAL-DAST-627` — a hardened account page (host-only cookie, no console title, no
  framework template, no artefact, no cross-origin `base` or refresh) forbidding all 42;
- `EVAL-DAST-628` — an operations runbook that *names* every console, template and
  artefact in the batch without serving any of them, also forbidding all 42.

The runbook control is the reason 627 is not enough: it proves the rules read a response
shape, not a product vocabulary. Expectations were authored before the first run; no
pattern was changed to make a case pass and no case was deleted afterwards.

## 5. Verification

| Command | Result (2026-10-21) |
|---|---|
| `node scripts/generate-assets.mjs` | 367 DAST rules, 1 414 patterns / records / remediation, 0 quarantined |
| `node scripts/test-packs.mjs` | PASS 5 838/5 838 |
| `node scripts/test-assets.mjs` | PASS 11 332/11 332 |
| `node scripts/validate-dast-overlaps.mjs` | PASS — 436 checks, 130 subset pairs, 0 unreviewed |
| `node scripts/validate-app-dast-reachability.mjs --check` | PASS — 294/367 reachable (80.1 %), 73 unreachable across 47 headers |
| `node scripts/gen-app-conformance.mjs --check` | PASS — 367/367 rules merge; 1 707/1 722 declared tests agree with the App-evaluator profile |
| `node scripts/run-eval.mjs` | 1 440 TP / 0 FN / 1 documented FP (`EVAL-SAST-008`); 1 739 cases, 1 728 assessed, 11 unassessed |
| `node scripts/test-eval.mjs` | PASS 43/43 (population pin 1 398 → 1 440) |
| `npm test` | EXIT 0 — 24 031 assertions |

## 6. Limits

- **Distance to 500 is 133 rules.** This batch is the largest single tranche since the
  capability-aligned pump, and it still does not close the target; `docs/DAST_500_GAP_PLAN_2026-10-21.md`
  records the family-by-family plan for the remainder.
- **Twenty-one console rules are breadth, not new classes.** They extend coverage of one
  existing family across products; they do not raise the semantic ceiling of the pack.
- **The App surface is unchanged.** 73 rules still read one of 47 headers that the App
  filters out before evaluation. No rule in this batch can reduce that number.
- **Console rules report the shell, not the data.** None of them authenticates, so a
  reachable console proves exposure of the interface, not of the records behind it.
- **Some fixtures are idealised.** The console shells reproduce the title and the marker
  the rule reads; they are synthetic documents, not captured responses.
- **No App code was changed.** The 15 App-evaluator divergences (GAP-041) are untouched.
