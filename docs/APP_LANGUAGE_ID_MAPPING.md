# APP_LANGUAGE_ID_MAPPING.md — SAST pack reachability in the Main App (generated)

Generated from `data/app-language-catalog.json` + `packs/sast/v1/rules` by
`scripts/validate-app-language-ids.mjs`. Do not edit by hand; edit the catalog and re-run
with `--write`. `npm test` fails when this file or the catalog drifts from the tree.

Pinned App source: `mdraselislam0101-design/Drobon` @ `9360dd1abdf940cc1bffd942aab0702703aaaaef` (`apps/api/src/scans/sast/languages.ts`, verified 2026-10-21).

A pack rule runs only when one of its `languages` ids is a family the App detects.
Everything below is counted from the rule files, not from a previous report.

| Measure | Value |
|---|---|
| SAST rules | 1000 |
| Universal rules (no `languages`, run on every file) | 11 |
| Distinct language ids used by the packs | 115 |
| …resolved directly by the App catalog | 47 |
| …resolved through an alias | 2 |
| …requiring a new App family | 66 |
| Rules that can never fire today (no resolvable id) | 160 |

## Aliases (dataset id → App catalog id)

| Dataset id | App id | Rules |
|---|---|---|
| `gha` | `github-actions` | 8 |
| `shell` | `shell-posix` | 29 |

## Ids that need a new App family (rules that cannot fire today)

| Dataset id | Rules | Severities | Why the App cannot run it |
|---|---|---|---|
| `sshd` | 14 | MEDIUM | sshd_config syntax; no App family and no extension (detected only by filename) |
| `k8s` | 13 | HIGH | Kubernetes manifests; the App parses them as yaml with no k8s family |
| `nginx` | 10 | HIGH/LOW/MEDIUM | nginx.conf directives; no App family and no extension |
| `tcl` | 9 | HIGH/LOW/MEDIUM | Tcl scripts; absent from the App catalog |
| `vba` | 7 | HIGH/LOW/MEDIUM | VBA macros; the App has vbnet but not VBA |
| `properties` | 6 | MEDIUM | Java .properties files; absent from the App catalog |
| `apache` | 5 | LOW/MEDIUM | httpd.conf directives; no App family |
| `basic` | 5 | HIGH/LOW/MEDIUM | BASIC listings; absent from the App catalog |
| `compose` | 5 | HIGH/MEDIUM | docker-compose YAML; parsed as yaml by the App, no compose family |
| `pascal` | 5 | HIGH/LOW/MEDIUM | Pascal sources; absent from the App catalog |
| `ini` | 4 | HIGH/MEDIUM | INI/host config files; absent from the App catalog |
| `postgres` | 4 | HIGH/MEDIUM | postgresql.conf directives; the App sql family is SQL statements, not server config |
| `awk` | 3 | HIGH/LOW/MEDIUM | AWK scripts; absent from the App catalog |
| `bind` | 3 | HIGH/MEDIUM | named.conf directives; no App family |
| `gitlab` | 3 | LOW/MEDIUM | GitLab CI YAML; the App has github-actions only |
| `samba` | 3 | HIGH/MEDIUM | smb.conf directives; no App family |
| `systemd` | 3 | MEDIUM | unit files; no App family |
| `elastic` | 2 | HIGH | Elasticsearch config; no App family |
| `gradle` | 2 | MEDIUM | Gradle scripts; the App has groovy but no gradle family |
| `haproxy` | 2 | HIGH/MEDIUM | haproxy.cfg directives; no App family |
| `nfs` | 2 | HIGH | exports file; no App family |
| `postfix` | 2 | MEDIUM | main.cf directives; no App family |
| `redis` | 2 | HIGH | redis.conf directives; no App family |
| `sudo` | 2 | HIGH | sudoers policy; no App family |
| `vault` | 2 | HIGH/MEDIUM | Vault config; no App family |
| `vsftpd` | 2 | HIGH/MEDIUM | vsftpd.conf directives; no App family |
| `asp` | 1 | MEDIUM | Classic ASP; absent from the App catalog |
| `blade` | 1 | MEDIUM | Laravel Blade templates; the App has html but no blade family |
| `caddy` | 1 | MEDIUM | Caddyfile; no App family |
| `cassandra` | 1 | HIGH | Cassandra config; no App family |
| `cmd` | 1 | HIGH | Windows batch; the App has powershell and bash, not cmd |
| `coldfusion` | 1 | MEDIUM | ColdFusion markup; absent from the App catalog |
| `consul` | 1 | MEDIUM | Consul config; no App family |
| `couchdb` | 1 | HIGH | CouchDB config; no App family |
| `dovecot` | 1 | HIGH | Dovecot config; no App family |
| `ejs` | 1 | MEDIUM | EJS templates; the App has html but no ejs family |
| `grafana` | 1 | MEDIUM | Grafana config; no App family |
| `graylog` | 1 | MEDIUM | Graylog config; no App family |
| `handlebars` | 1 | MEDIUM | Handlebars templates; the App has html but no handlebars family |
| `influx` | 1 | MEDIUM | InfluxDB config; no App family |
| `istio` | 1 | MEDIUM | Istio manifests; parsed as yaml with no istio family |
| `jinja` | 1 | MEDIUM | Jinja templates; the App has html but no jinja family |
| `jmx` | 1 | HIGH | JMX config; no App family |
| `jsp` | 1 | MEDIUM | JSP templates; the App has html but no jsp family |
| `kafka` | 1 | HIGH | Kafka config; no App family |
| `logindefs` | 1 | LOW | login.defs policy; no App family |
| `logrotate` | 1 | MEDIUM | logrotate config; no App family |
| `memcached` | 1 | HIGH | memcached config; no App family |
| `minio` | 1 | MEDIUM | MinIO config; no App family |
| `mongo` | 1 | HIGH | MongoDB config; no App family |
| `mosquitto` | 1 | HIGH | Mosquitto config; no App family |
| `mysql` | 1 | HIGH | my.cnf directives; the App sql family is SQL, not server config |
| `neo4j` | 1 | HIGH | Neo4j config; no App family |
| `openvpn` | 1 | HIGH | OpenVPN config; no App family |
| `pam` | 1 | HIGH | PAM config; no App family |
| `proftpd` | 1 | MEDIUM | proftpd.conf directives; no App family |
| `pug` | 1 | MEDIUM | Pug templates; the App has html but no pug family |
| `rabbitmq` | 1 | HIGH | RabbitMQ config; no App family |
| `rsyslog` | 1 | MEDIUM | rsyslog config; no App family |
| `slapd` | 1 | MEDIUM | slapd.conf directives; no App family |
| `smarty` | 1 | MEDIUM | Smarty templates; the App has html but no smarty family |
| `squid` | 1 | MEDIUM | squid.conf directives; no App family |
| `supervisor` | 1 | MEDIUM | supervisord config; no App family |
| `traefik` | 1 | MEDIUM | Traefik config; no App family |
| `twig` | 1 | MEDIUM | Twig templates; the App has html but no twig family |
| `unbound` | 1 | MEDIUM | unbound.conf directives; no App family |

## What this does and does not mean

- It measures **reachability through the App language gate**, not detection quality.
- An alias is a documentation-level resolution: the App must still accept the dataset id
  (or the pack must be regenerated with the App id) before those rules fire.
- Adding a family to the App catalog is App-repo work; this gate only guarantees that no
  new unreachable id can appear here unnoticed (tracked as GAP-040 in `DROBON_REMAINING_WORK.csv`).
