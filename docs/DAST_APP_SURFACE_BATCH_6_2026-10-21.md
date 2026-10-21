# DAST app-surface batch 6 — 2026-10-21

Status: **AUTHORING TARGET REACHED, APP SURFACE NOT.** DAST now has **500 rule files**
(the 500-check planning target), but **427 of 500 are evaluable inside the Main App**
(85.4 %). The 73 that the App cannot reach are the same 73 as before this batch: every
rule added here reads the response body or a `Set-Cookie`/`Location` value in the 11-header
allowlist, so this batch adds no new unreachable rules. **500 authored is not 100 % App
coverage** — GAP-048 (the App-side header allowlist) is unchanged and still owns the last 73.

App reference (read-only): `mdraselislam0101-design/Drobon` @ `9360dd1`.

## 1. What this batch covers

| Family | Why it was missing | Rules | Ids |
|---|---|---|---|
| Served configuration and build artefacts | see §3 | 24 | 408–431 |
| Platform consoles reachable without authentication | see §3 | 13 | 432–444 |
| Credential material served in a response | see §3 | 26 | 445–470 |
| Markup trust contracts | see §3 | 7 | 471–477 |
| Personal-data patterns (CWE-359) | see §3 | 22 | 478–499 |
| Cookie hygiene contracts | see §3 | 2 | 500–501 |
| Source and debug data served instead of a rendered page | see §3 | 8 | 502–509 |

## 2. The 102 rules

| Rule | Title | Category | CWE | Severity | Check type |
|---|---|---|---|---|---|
| DPK-DAST-408 | composer.json manifest served from the web root | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-409 | CVS version-control metadata served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-410 | Gemfile dependency manifest served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-411 | Gradle build script served from the web root | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-412 | Helm Chart manifest served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-413 | .htpasswd credential file served from the web root | information-disclosure | CWE-200 | HIGH | response-body-matches |
| DPK-DAST-414 | kubeconfig file served with its client key | credential-exposure | CWE-798 | CRITICAL | response-body-matches |
| DPK-DAST-415 | kustomization manifest served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-416 | Makefile with deployment targets served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-417 | MySQL client configuration served from the web root | credential-exposure | CWE-798 | HIGH | response-body-matches |
| DPK-DAST-418 | Netlify configuration served with redirects | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-419 | .netrc machine credentials served | credential-exposure | CWE-798 | HIGH | response-body-matches |
| DPK-DAST-420 | nginx configuration served from the web root | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-421 | .pgpass database credential file served | credential-exposure | CWE-798 | HIGH | response-body-matches |
| DPK-DAST-422 | php.ini configuration served from the web root | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-423 | Pipfile dependency manifest served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-424 | Maven build file served from the web root | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-425 | Procfile with process types served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-426 | Python requirements file served from the web root | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-427 | Serverless framework definition served | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-428 | Terraform variable file served with values | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-429 | Tomcat server.xml served with its connector and realm | information-disclosure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-430 | Vercel project configuration served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-431 | Java web.xml deployment descriptor served | information-disclosure | CWE-200 | LOW | response-body-matches |
| DPK-DAST-432 | Argo Workflows UI is reachable without authentication | exposed-interface | CWE-306 | HIGH | response-body-matches |
| DPK-DAST-433 | Backstage developer portal is reachable without authentication | exposed-interface | CWE-306 | MEDIUM | response-body-matches |
| DPK-DAST-434 | Consul UI is reachable without authentication | exposed-interface | CWE-306 | HIGH | response-body-matches |
| DPK-DAST-435 | CouchDB Fauxton console is reachable without authentication | exposed-interface | CWE-306 | HIGH | response-body-matches |
| DPK-DAST-436 | Gerrit code review UI is reachable without authentication | exposed-interface | CWE-306 | MEDIUM | response-body-matches |
| DPK-DAST-437 | Grafana is reachable without authentication | exposed-interface | CWE-306 | HIGH | response-body-matches |
| DPK-DAST-438 | Graylog web interface is reachable without authentication | exposed-interface | CWE-306 | HIGH | response-body-matches |
| DPK-DAST-439 | Jaeger query UI is reachable without authentication | exposed-interface | CWE-306 | MEDIUM | response-body-matches |
| DPK-DAST-440 | Kibana is reachable without authentication | exposed-interface | CWE-306 | HIGH | response-body-matches |
| DPK-DAST-441 | Apache NiFi UI is reachable without authentication | exposed-interface | CWE-306 | HIGH | response-body-matches |
| DPK-DAST-442 | Apache Ranger admin UI is reachable without authentication | exposed-interface | CWE-306 | CRITICAL | response-body-matches |
| DPK-DAST-443 | Temporal UI is reachable without authentication | exposed-interface | CWE-306 | HIGH | response-body-matches |
| DPK-DAST-444 | HashiCorp Vault UI is reachable without authentication | exposed-interface | CWE-306 | CRITICAL | response-body-matches |
| DPK-DAST-445 | AMQP credential served in a connection URI | credential-exposure | CWE-798 | HIGH | response-body-matches |
| DPK-DAST-446 | Argon2 password hash served in a response | credential-exposure | CWE-522 | MEDIUM | response-body-matches |
| DPK-DAST-447 | Basic authentication credential served in a response body | credential-exposure | CWE-522 | HIGH | response-body-matches |
| DPK-DAST-448 | bcrypt password hash served in a response | credential-exposure | CWE-522 | MEDIUM | response-body-matches |
| DPK-DAST-449 | ADO.NET connection string carries a password | credential-exposure | CWE-798 | HIGH | response-body-matches |
| DPK-DAST-450 | Django settings serve a database password | credential-exposure | CWE-798 | HIGH | response-body-matches |
| DPK-DAST-451 | FTP credential served in a connection URI | credential-exposure | CWE-798 | MEDIUM | response-body-matches |
| DPK-DAST-452 | JDBC connection properties carry a password in a response | credential-exposure | CWE-798 | HIGH | response-body-matches |
| DPK-DAST-453 | Access token field served in a JSON response | credential-exposure | CWE-522 | MEDIUM | response-body-matches |
| DPK-DAST-454 | API key field served in a JSON response | credential-exposure | CWE-522 | MEDIUM | response-body-matches |
| DPK-DAST-455 | Password field served in a JSON response | credential-exposure | CWE-522 | HIGH | response-body-matches |
| DPK-DAST-456 | Refresh token field served in a JSON response | credential-exposure | CWE-522 | HIGH | response-body-matches |
| DPK-DAST-457 | Secret field served in a JSON response | credential-exposure | CWE-522 | HIGH | response-body-matches |
| DPK-DAST-458 | Session identifier served in a JSON response | credential-exposure | CWE-522 | MEDIUM | response-body-matches |
| DPK-DAST-459 | TOTP seed served in a JSON response | credential-exposure | CWE-522 | HIGH | response-body-matches |
| DPK-DAST-460 | JSON Web Token served in a response body | credential-exposure | CWE-522 | MEDIUM | response-body-matches |
| DPK-DAST-461 | JSON Web Token carried in a cookie | credential-exposure | CWE-522 | MEDIUM | response-header-matches |
| DPK-DAST-462 | LDAP bind credential served in a response | credential-exposure | CWE-798 | MEDIUM | response-body-matches |
| DPK-DAST-463 | MD5 password digest served with its password marker | credential-exposure | CWE-916 | HIGH | response-body-matches |
| DPK-DAST-464 | MongoDB credential served in a connection URI | credential-exposure | CWE-798 | HIGH | response-body-matches |
| DPK-DAST-465 | OAuth client secret served in a response | credential-exposure | CWE-522 | HIGH | response-body-matches |
| DPK-DAST-466 | Java properties file serves a plaintext password | credential-exposure | CWE-798 | MEDIUM | response-body-matches |
| DPK-DAST-467 | Redis credential served in a connection URI | credential-exposure | CWE-798 | HIGH | response-body-matches |
| DPK-DAST-468 | SHA-1 password digest served with its password marker | credential-exposure | CWE-916 | MEDIUM | response-body-matches |
| DPK-DAST-469 | SMTP credential served in a connection URI | credential-exposure | CWE-798 | HIGH | response-body-matches |
| DPK-DAST-470 | YAML password key served with a value | credential-exposure | CWE-798 | MEDIUM | response-body-matches |
| DPK-DAST-471 | Form action is protocol-relative to another host | weak-markup | CWE-319 | MEDIUM | response-body-matches |
| DPK-DAST-472 | Hidden password input ships a value | weak-markup | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-473 | iframe delegates a powerful feature to every origin | weak-markup | CWE-1021 | MEDIUM | response-body-matches |
| DPK-DAST-474 | Sandboxed frame may navigate the top-level page | weak-markup | CWE-1021 | MEDIUM | response-body-matches |
| DPK-DAST-475 | Meta tag sends CSP reports over plaintext HTTP | weak-markup | CWE-319 | LOW | response-body-matches |
| DPK-DAST-476 | Meta tag delivers a wildcard content security policy | weak-markup | CWE-693 | MEDIUM | response-body-matches |
| DPK-DAST-477 | Plugin object loads a data URI document | weak-markup | CWE-79 | MEDIUM | response-body-matches |
| DPK-DAST-478 | Aadhaar number served in a response | privacy-exposure | CWE-359 | HIGH | response-body-matches |
| DPK-DAST-479 | Bangladesh mobile number served in a response | privacy-exposure | CWE-359 | MEDIUM | response-body-matches |
| DPK-DAST-480 | Bangladesh National ID number served in a response | privacy-exposure | CWE-359 | HIGH | response-body-matches |
| DPK-DAST-481 | Bulk email address list served in a response | privacy-exposure | CWE-359 | MEDIUM | response-body-matches |
| DPK-DAST-482 | Bulk phone number list served in a response | privacy-exposure | CWE-359 | MEDIUM | response-body-matches |
| DPK-DAST-483 | Canadian Social Insurance Number served in a response | privacy-exposure | CWE-359 | MEDIUM | response-body-matches |
| DPK-DAST-484 | Payment card number served in a response | privacy-exposure | CWE-359 | HIGH | response-body-matches |
| DPK-DAST-485 | Date of birth column served in a CSV response | privacy-exposure | CWE-359 | MEDIUM | response-body-matches |
| DPK-DAST-486 | Precise coordinates served in a JSON response | privacy-exposure | CWE-359 | MEDIUM | response-body-matches |
| DPK-DAST-487 | International bank account number served in a response | privacy-exposure | CWE-359 | HIGH | response-body-matches |
| DPK-DAST-488 | Bank account and IFSC pair served in a response | privacy-exposure | CWE-359 | HIGH | response-body-matches |
| DPK-DAST-489 | Device IMEI served in a response | privacy-exposure | CWE-359 | LOW | response-body-matches |
| DPK-DAST-490 | Insurance policy number served with its holder record | privacy-exposure | CWE-359 | LOW | response-body-matches |
| DPK-DAST-491 | Passport number field served in a JSON response | privacy-exposure | CWE-359 | MEDIUM | response-body-matches |
| DPK-DAST-492 | Medical record number served in a response | privacy-exposure | CWE-359 | MEDIUM | response-body-matches |
| DPK-DAST-493 | Passport machine-readable zone served in a response | privacy-exposure | CWE-359 | HIGH | response-body-matches |
| DPK-DAST-494 | Salary figure served with its payroll field name | privacy-exposure | CWE-359 | MEDIUM | response-body-matches |
| DPK-DAST-495 | Tax identification number served in a response | privacy-exposure | CWE-359 | MEDIUM | response-body-matches |
| DPK-DAST-496 | UK National Insurance number served in a response | privacy-exposure | CWE-359 | MEDIUM | response-body-matches |
| DPK-DAST-497 | US Social Security number served in a response | privacy-exposure | CWE-359 | HIGH | response-body-matches |
| DPK-DAST-498 | User export with a password column served in a response | privacy-exposure | CWE-359 | CRITICAL | response-body-matches |
| DPK-DAST-499 | Vehicle identification number served in a response | privacy-exposure | CWE-359 | LOW | response-body-matches |
| DPK-DAST-500 | Cookie carries an expired date and a positive Max-Age | cookie-hygiene | CWE-15 | LOW | response-header-matches |
| DPK-DAST-501 | Cookie attribute value contains a semicolon | cookie-hygiene | CWE-15 | LOW | response-header-matches |
| DPK-DAST-502 | HTML comment carries a credential | data-exposure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-503 | Inline script assigns document.domain | weak-markup | CWE-693 | LOW | response-body-matches |
| DPK-DAST-504 | JSONP callback endpoint served | data-exposure | CWE-200 | MEDIUM | response-body-matches |
| DPK-DAST-505 | JSP source served instead of a rendered page | data-exposure | CWE-200 | HIGH | response-body-matches |
| DPK-DAST-506 | Redirect carries a token in the URL fragment | credential-exposure | CWE-598 | MEDIUM | response-header-matches |
| DPK-DAST-507 | Redirect carries a bare token in the query string | credential-exposure | CWE-598 | MEDIUM | response-header-matches |
| DPK-DAST-508 | PHP source served instead of an executed page | data-exposure | CWE-200 | HIGH | response-body-matches |
| DPK-DAST-509 | Server-side include directive served unprocessed | data-exposure | CWE-200 | MEDIUM | response-body-matches |
## 3. Why these questions and not others

**Served configuration and build artefacts (24).** The pack already knew `package.json`,
Compose, `.git`, `web.config`, `.sql` and `Dockerfile`. It did not know the files that pin an
entire dependency tree or a deployment path: `composer.json`, `Gemfile`, `pom.xml`,
`build.gradle`, `requirements.txt`, `Pipfile`, `Makefile`, `Procfile`, Helm `Chart.yaml`,
`kustomization.yaml`, `serverless.yml`, `vercel.json`, `netlify.toml`, `terraform.tfvars`,
nginx/php.ini/my.cnf/Tomcat `server.xml`/`web.xml`, and the credential files `.htpasswd`,
`.pgpass`, `.netrc`, kubeconfig. Each is a distinct file with its own markers; none is a
variant of another.

**Platform consoles (13).** Argo Workflows, Backstage, Consul, CouchDB Fauxton, Gerrit,
Grafana, Graylog, Jaeger, Kibana, NiFi, Ranger, Temporal and Vault expose whole deployments
without authentication. They were absent while 8 neighbouring consoles were covered.

**Credential material in a response (26).** Field-shaped JSON (`password`, `secret`,
`api_key`, `access_token`, `refresh_token`, `totp_seed`, `session_id`), hash shapes (bcrypt,
Argon2, MD5, SHA-1), token shapes (JWT in the body and in a cookie), basic authentication
material, OAuth client secrets, and per-protocol connection URIs (SMTP, Redis, MongoDB,
AMQP, FTP, LDAP, JDBC, ADO.NET, Django, Java properties, YAML).

**Markup trust contracts (7).** Protocol-relative form actions, hidden password inputs that
ship a value, iframe feature delegation to `*`, sandboxed frames that may navigate the top
level, meta-tag CSP reports over plaintext, wildcard meta-tag CSP, and plugin objects loading
`data:` documents.

**Personal-data patterns (22, CWE-359).** This is the family the App side asked for: payment
card numbers, IBAN, Aadhaar, Bangladesh NID and mobile numbers, SSN, Canadian SIN, UK NI
number, passport MRZ and passport fields, MR number, IFSC + account, IMEI, VIN, date of
birth columns, user exports with a password column, salary figures, TIN, policy numbers,
precise coordinates and bulk email/phone lists.

**Cookie hygiene and source exposure (10).** Expired date plus positive `Max-Age`, semicolons
inside cookie attribute values, credentials in HTML comments, `document.domain` assignment,
JSONP callbacks, JSP/PHP source and unprocessed SSI directives, and tokens in `Location`
fragments and query strings.

Two candidates were **dropped at the dry-run stage** rather than ledgered as coverage:
`resp-cookie-invalid-samesite-value` (its evidence is already the question an existing
SameSite rule asks) and `cred-php-config-password` (a strict subset of `resp-php-source`, and
it cross-fired on that rule's fixture).

## 4. Verification (all run on this tree)

| Gate | Result |
|---|---|
| `node scripts/generate-assets.mjs` | 6,143 files written, `quarantined: []` |
| `node scripts/validate-packs.mjs` | PASS — 1,550 files, 0 errors |
| `node scripts/test-packs.mjs` | PASS — 6,370/6,370 |
| `node scripts/test-assets.mjs` | PASS — 12,396/12,396 (linkage 1,547 rule ↔ 1,547 pattern) |
| `node scripts/validate-dast-overlaps.mjs` | PASS — 569 checks; 130 subset pairs (125 expected absence, 5 reviewed) |
| `node scripts/validate-app-dast-reachability.mjs` | 427/500 reachable (85.4 %); 73 unreachable across 47 headers |
| `node scripts/run-eval.mjs` | 1,876 cases / 1,865 assessed; TP 1,573, FN 0, FP 1 (`EVAL-SAST-008`, pre-existing) |
| `node scripts/test-eval.mjs` | PASS — 43/43 |
| `node scripts/test-doc-drift.mjs` | PASS — 120/0 |
| `node scripts/test-current-state.mjs` | PASS — 157/0 |
| `node scripts/validate-capability-coverage.mjs` | PASS — 710/0 |
| `node scripts/gen-app-conformance.mjs --check` | 15/2,152 declared tests diverge from the App evaluator (all on rules ≤ DPK-DAST-190, pre-existing; GAP-041) |
| `node scripts/completion-ledger.mjs` | OK — 21 dimensions: 9 complete, 3 partial, 1 policy-bound, 3 owner-blocked, 5 app-blocked |

Evaluation cohort `dast-app-surface-6-2026-10-21`: **104 cases** (`EVAL-DAST-662`…`765`) —
102 positives, one per new rule, and 2 negative controls in which **all 102 new rule ids are
forbidden**. Expectations were authored before the first run and no expectation was relaxed
afterwards: the first run produced 102 TP, 0 FN, 0 FP.

## 5. What this does *not* buy

- **500 rule files ≠ 500 evaluable rules.** 427/500 (85.4 %) are reachable through the App's
  response surface. The 73 header-blocked rules need the App change in GAP-048; the Dataset
  side cannot move that number by authoring more rules.
- **Reachability is not detection quality.** Every count here is about authored, declared and
  independently evaluated checks against synthetic observations. No request was sent.
- **One documented false positive remains** (`EVAL-SAST-008`), untouched by this batch.
- **Own-work share, licence and capability comparisons are unchanged** by this batch: the
  content is ours, but with no `LICENSE` grant (G6) it stays
  `NOT_ELIGIBLE_NO_LICENSE`, and the paid-tool capability estimates in
  `docs/PAID_TOOL_BENCHMARK.md` do not move because a rule exists.
- **The 9 stale `dast:` cells in `data/asset-cells/.manifest.json`** (header-missing/CSP,
  referrer, XCTO, XFO, response-weak-2, CSP `script-src-attr`/`style-src-attr`, CSP
  `frame-ancestors`/`report-uri`) point at rule files that no longer exist. That condition
  predates this batch and is recorded rather than "fixed" by re-emitting.

## 6. Files

- `data/asset-cells/dast-28.json` — the 102 authored classes (durable copy of the batch spec).
- `data/eval-cases/EVAL-DAST-662.json` … `EVAL-DAST-765.json` — the cohort.
- `packs/dast/v1/rules/DPK-DAST-408.json` … `DPK-DAST-509.json`, with their patterns,
  records and remediation entries.
- `interop/app-dast-reachability.json`, `interop/app-conformance.json`,
  `interop/APP_CONFORMANCE.md`, `docs/CURRENT_INVENTORY.json`,
  `docs/CAPABILITY_COVERAGE_MATRIX.json`, `docs/COVERAGE_MAP.json`,
  `docs/CORPUS_TARGETS.json`, `docs/DATASET_COMPLETION_LEDGER.json`.
