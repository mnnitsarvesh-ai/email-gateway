# 003: Local docker compose stack (deploy/local)

Owner agent: devops-engineer
Depends on: 001
Status: draft
Branch: feat/003-local-compose-stack
Phase: 0

## User story

Story: _to be written by product-owner_

As a developer or QA agent, I want one command to bring up every dependency of the mail path locally, healthy and seeded, including a real replicating MySQL replica and a stand-in customer mail server, so that integration and swaks e2e tests run against production-like behaviour.

## Acceptance criteria

AC-1 Given a clean machine with Docker and `deploy/local/.env.local` created from `.env.example`, when `docker compose -f deploy/local/compose.yaml --profile mta up -d && deploy/local/scripts/wait-healthy.sh` runs, then the script exits 0 within 300 s and `docker compose ps` shows every long-running service `healthy`.
AC-2 Given a service that cannot become healthy (for example `rabbitmq` stopped), when `wait-healthy.sh` runs, then it exits non-zero after 300 s and prints the unhealthy service's logs.
AC-3 Given the running stack, when `docker compose config` and `docker ps --format '{{.Ports}}'` are inspected, then every published host port is bound to `127.0.0.1` and none to `0.0.0.0`; `postfix-outbound` publishes no port and 10025 is reachable only from the `reinject` network.
AC-4 Given the compose file, when image references are inspected, then every image is pinned by tag and digest (no `latest`).
AC-5 Given `mysql-replica`, when `SHOW REPLICA STATUS\G` is run, then `Replica_IO_Running` and `Replica_SQL_Running` are `Yes` and GTID auto-position is on; a row inserted on the writer appears on the replica within 10 s.
AC-6 Given the replica, when `INSERT` is attempted as `esg_writer` or `esg_reader` and as root, then each fails with a read-only error (`@@read_only = 1`, `@@super_read_only = 1`, `@@server_id = 2`).
AC-7 Given `scripts/replica-lag.sh pause`, when a row is written on the writer, then it does not appear on the replica; after `resume` it appears within 10 s.
AC-8 Given the MySQL users, when privileges are checked, then `esg_writer` can DML on `esg.*` but `CREATE TABLE` fails with access denied, `esg_reader` can only `SELECT`, and `esg_migrator` can run DDL.
AC-9 Given the `migrate` one-shot, when it runs, then it applies `dbmate up` as `esg_migrator` and exits 0 (and exits 0 again if re-run); it applies `db/seeds/local/*.sql` only if present.
AC-10 Given the data-plane env example files, when grepped, then they contain `MYSQL_WRITER_URL` and no `MYSQL_READER_URL`; `MYSQL_READER_URL` appears only in the `api` env example.
AC-11 Given `minio-init`, when it runs, then buckets `esg-mail-local` and `esg-archive-local` exist with versioning enabled, a scoped service key exists, and a conditional `PutObject` with `If-None-Match: *` on an existing key returns 412 (assumes default for NEEDS SARVESH #1: pinned MinIO image).
AC-12 Given `clamav`, when `PING` is sent to port 3310, then it replies `PONG`; after `down` and `up` (volume kept), signatures are not re-downloaded (no freshclam download in logs); no sample corpus is mounted.
AC-13 Given `postfix-inbound` and `postfix-outbound` built from `deploy/docker/postfix`, when started, then `postfix check` exits 0 inside each container, the TLS cert is generated at start (no cert or key file is tracked by git), and the processes run as non-root where the image allows.
AC-14 Given `redis`, `rabbitmq` (management on 15672), `rspamd` (`rspamc stat`), `mailpit-tenant` (`/readyz`) and `mailpit-ext`, when probed, then each healthcheck passes; ClickHouse and OpenSearch are absent from compose.
AC-15 Given `scripts/reset.sh`, when run, then volumes are removed and a following `up.sh` returns to AC-1 state with the replica re-attached.
AC-16 Given the repo, when `git ls-files deploy/local` and gitleaks are run, then no `.env.local`, password or key is tracked and `.env.example` holds placeholders only.

### Open questions for Sarvesh

- The one-line `swaks` image check is covered by AC-1 health only; the swaks behaviour itself is tested in 004 and 012.

## Out of scope

- **Postfix config content** (`main.cf` and `master.cf`) and the Rspamd milter config. Those belong to smtp-infra-engineer in task 004. This task only builds the Postfix image and defines the services that mount `postfix/`.
- **Schema and seed SQL.** Owned by backend-engineer in 005. This task only provides the one-shot runner that applies them.
- RabbitMQ exchanges, queues and bindings. They are declared by `@esg/mq` (008) at service start, not by broker definitions.
- **ClickHouse** is added in a Phase 1 task, together with the first stage events. **OpenSearch** is added in Phase 3, with trace and search. CLAUDE.md lists both in `deploy/local`; they're deferred because nothing uses them in Phase 0.
- kind or k3d, Helm, and service Dockerfiles. Those come in Phase 1.

## Design notes

### Files

```
deploy/local/
  compose.yaml
  .env.example                 placeholders only; real values in deploy/local/.env.local (gitignored)
  mysql/writer.cnf             server_id=1, gtid_mode=ON, enforce_gtid_consistency=ON, binlog_format=ROW,
                               log_replica_updates=ON, default_time_zone='+00:00', character set utf8mb4
  mysql/replica.cnf            server_id=2, gtid settings, read_only=ON, super_read_only=ON, relay_log_recovery=ON
  mysql/init/                  creates users esg_migrator (DDL), esg_writer (DML on esg.*), esg_reader (SELECT on esg.*),
                               esg_repl (REPLICATION SLAVE); passwords from env
  scripts/up.sh  wait-healthy.sh  reset.sh  replica-lag.sh (pause|resume)  postqueue.sh (inbound|outbound)
deploy/docker/postfix/Dockerfile   pinned Debian slim + postfix + postfix-lmdb; entrypoint renders
                                   postfix/<role>/*.tmpl with envsubst, generates a throwaway self-signed TLS
                                   cert at start (never committed), runs `postfix check`, then `postfix start-fg`
```

### Services

Every image is pinned by tag and digest. Every host port binds to **`127.0.0.1` only**, so a laptop never exposes an SMTP relay to the LAN.

| Service | Image | Host port | Health check |
|---|---|---|---|
| `mysql-writer` | `mysql:8.4.x` | 3306 | `mysqladmin ping` |
| `mysql-replica` | `mysql:8.4.x` | 3307 | `SHOW REPLICA STATUS` shows IO and SQL running |
| `mysql-replication-init` | one-shot | — | `CHANGE REPLICATION SOURCE TO … SOURCE_AUTO_POSITION=1, GET_SOURCE_PUBLIC_KEY=1; START REPLICA` |
| `migrate` | one-shot, pinned dbmate | — | `dbmate up` as `esg_migrator` on the writer, then applies `db/seeds/local/*.sql` if present |
| `rabbitmq` | `rabbitmq:4.x-management` | 5672, 15672 | `rabbitmq-diagnostics -q check_port_connectivity` |
| `redis` | `redis:7.4.x` | 6379 | `redis-cli ping` |
| `minio` | pinned last published MinIO image (see NEEDS SARVESH) | 9000, 9001 | `/minio/health/ready` |
| `minio-init` | one-shot `mc` | — | creates `esg-mail-local` and `esg-archive-local` with versioning on, plus a scoped access key for services |
| `clamav` | `clamav/clamav:1.4.x` | 3310 | clamd `PING` → `PONG`; signature volume persisted so freshclam doesn't re-download on every `up` |
| `rspamd` | official `rspamd/rspamd` pinned | 11332 (milter), 11334 (UI, localhost) | `rspamc stat` |
| `postfix-inbound` | `deploy/docker/postfix` | 2525 → 25 | `postfix status` and an SMTP banner check; profile `mta` |
| `postfix-outbound` | `deploy/docker/postfix` | none. Reinjection on 10025 is reachable only on the internal `reinject` network (see 004: published ports arrive from the bridge gateway IP and would be trusted). Connector listener 2587 is added in Phase 3. | same; profile `mta` |
| `swaks` | pinned image with swaks | — | tool container on the default and `reinject` networks, used by 004 and 012 tests; profile `mta` |
| `mailpit-tenant` | `axllent/mailpit` pinned | 8025 UI, 1025 SMTP | `/readyz` |
| `mailpit-ext` | `axllent/mailpit` pinned | 8026 UI | stands in for "the internet" for outbound tests from Phase 3 |

### Notes

- The **replica is real GTID replication**, not a second independent server. `scripts/replica-lag.sh pause` runs `STOP REPLICA SQL_THREAD` and `resume` runs `START REPLICA SQL_THREAD`. qa-engineer uses these to show that replica lag never affects a data-plane decision, and 007 uses them to test `read({ fresh })`.
- **Users and least privilege.** Data-plane env files get only `MYSQL_WRITER_URL` (as `esg_writer`). Only the `api` env file gets `MYSQL_READER_URL` (as `esg_reader`, pointing at the replica). Migrations run as `esg_migrator`. Grants are written so `esg_writer` can't run DDL.
- **Postfix services sit behind compose profile `mta`.** The image builds and starts in this task, but the configs come from 004. After 004 merges, the standard command is `docker compose -f deploy/local/compose.yaml --profile mta up -d`. Update CLAUDE.md "Commands" to match.
- Postfix inbound's LMTP next hop is `ingest-service:24`. That service doesn't exist until Phase 1, so inbound mail **stays deferred in the Postfix queue**. That is the right durable behaviour, and the 012 smoke test asserts it.
- Postfix outbound delivers tenant domains (`tenant-a.test`, `tenant-b.test`) to `mailpit-tenant:1025` and everything else to `mailpit-ext:1025`. The maps are written in 004.
- ClamAV only ever scans EICAR locally. freshclam downloads official signatures, which is allowed. Never mount or download sample corpora.
- `scripts/wait-healthy.sh` polls until every service is `healthy`, or fails after 300 s with the unhealthy services' logs.
- Containers run as non-root where the upstream image allows it.

## Hard rules at risk

- **2 (writer-only data plane).** Separate MySQL users and env vars. The replica DSN only goes into the `api` env.
- **9 (no secrets).** Passwords and keys come only from `deploy/local/.env.local` (gitignored). TLS certs are generated at container start. `.env.example` holds placeholders.
- **10.** Local only. No cloud endpoints.
- **12 (EICAR only).** No sample downloads. ClamAV signatures only.
- **Open relay** (smtp-infra non-negotiable). Ports bind to localhost. Relay restrictions are proven in 004.

## NEEDS SARVESH

1. **MinIO image.** MinIO moved its community edition to source-only distribution in late 2025, so new official images may not be published. Options:
   - (a) pin the last published `minio/minio` image by digest (AGPL, fine for local dev only);
   - (b) switch the local S3 stand-in to another S3-compatible server (for example SeaweedFS or Garage);
   - (c) LocalStack S3.

   *Recommendation:* (a) for now, with the digest pinned. Revisit if it breaks. `@esg/s3` only uses standard S3 APIs, including conditional `If-None-Match` puts, so switching later is cheap. Check that any replacement supports conditional writes.
2. **RabbitMQ topology in local.** One node by default, which is enough for functional tests. A 3-node `ha` profile is added only when chaos tests need node kills (Phase 1). *Recommendation:* approve the single node now and the 3-node profile in Phase 1. This is noted rather than blocking.
