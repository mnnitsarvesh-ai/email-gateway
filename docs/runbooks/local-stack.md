# Runbook: local stack

## Start and stop

```bash
pnpm env:init                                         # once
docker compose up -d --wait                           # infrastructure, including the MySQL replica
pnpm db:migrate                                       # history preflight + apply migrations from the host
pnpm db:partitions -- apply && pnpm db:seed           # partitions ahead + catalog/demo data (idempotent)
docker compose --profile apps up -d --build --wait    # everything, including services
docker compose --profile apps down                    # stop (keep data)
docker compose --profile apps down -v                 # stop and wipe all volumes
```

## Symptoms and fixes

| Symptom                                                                                                                             | Cause                                                                                                                         | Fix                                                                                                                                                                                                                                                  |
| ----------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ports are not available ... address already in use`                                                                                | Another local stack uses a default port                                                                                       | Set the matching `*_HOST_PORT` in `.env`, and update the URL that uses it (e.g. `DATABASE_URL`), then `docker compose up -d`                                                                                                                         |
| `required variable ... is missing a value`                                                                                          | No `.env`                                                                                                                     | `pnpm env:init`                                                                                                                                                                                                                                      |
| MySQL "Access denied" after regenerating `.env`                                                                                     | The data volume was initialised with the old passwords                                                                        | `docker compose down -v` (wipes local data), then start again                                                                                                                                                                                        |
| `mysql-replica` stays `unhealthy`                                                                                                   | Replication is not running yet (the setup has not finished) or has stopped                                                    | `docker compose logs mysql-replica-setup`, then `docker compose run --rm mysql-replica-setup`, which is safe to repeat. See [replication troubleshooting](../database/replication.md#troubleshooting)                                                |
| `mysql-replica-setup` exited 1                                                                                                      | The log names the cause: `Last_IO_Error`/`Last_SQL_Error`, a CLONE error, or a replication password longer than 32 characters | Fix the cause, then `docker compose run --rm mysql-replica-setup`. If the replica diverged or the binlogs it needs were purged, re-seed it (next row)                                                                                                |
| The replica needs a fresh copy (re-seed)                                                                                            | Diverged, too far behind, or a broken volume                                                                                  | `docker compose rm -sf mysql-replica mysql-replica-setup && docker volume rm email-gateway_mysql-replica-data && docker compose up -d --wait`. Only the replica's volume is deleted                                                                  |
| "Access denied" for `gateway_reader` or `gateway_repl` after regenerating `.env`                                                    | The accounts already exist on `mysql-data` with the old passwords; `01-users.sh` never changes a password                     | Either restore the old `.env` values, or set the new ones on the primary (`ALTER USER … IDENTIFIED BY …` as root), then re-seed the replica. `docker compose down -v` also works but wipes all local data                                            |
| `docker compose up -d --wait` exits 1 with `minio-init exited (0)` (or `mysql-replica-setup exited (0)`)                            | Compose v5 treats a one-shot container that has finished as a failure when nothing in the started profiles depends on it      | Harmless with infrastructure only: check `docker compose ps`. With `--profile apps`, the services depend on both one-shots, so `--wait` handles them                                                                                                 |
| `clamav` stays `starting` on first run                                                                                              | freshclam is downloading signatures (~300 MB)                                                                                 | Wait. The health check allows a 10-minute start period, and later starts reuse the `clamav-db` volume                                                                                                                                                |
| RCPT returns `451 4.3.5 Policy service unavailable`                                                                                 | `smtp-adapter` isn't running (expected with infra only)                                                                       | Start the `apps` profile. This tempfail is the intended fail-closed behaviour                                                                                                                                                                        |
| RCPT returns `554 Relay access denied`                                                                                              | Recipient domain not in `POSTFIX_RELAY_DOMAINS`                                                                               | Use a domain from that list (default `gateway.test`)                                                                                                                                                                                                 |
| Rspamd logs `DNS reply returned 'no error' ... likely DNS spoofing`                                                                 | Public DNSBLs refuse queries from shared resolvers                                                                            | Harmless locally. Production uses a dedicated recursive resolver                                                                                                                                                                                     |
| Image build fails with `cannot allocate memory`, or Docker restarts                                                                 | Building every app image in parallel exceeds the Docker VM's memory                                                           | Build one at a time: `for s in db-migrate api smtp-adapter email-worker policy-engine delivery-worker notification-worker archive-worker admin-portal; do docker compose --profile apps build $s; done`, or give Docker more memory                  |
| `/health/ready` returns 503                                                                                                         | A dependency check failed                                                                                                     | The response body names the failing check and its error                                                                                                                                                                                              |
| `db:migrate` / `db-migrate` stops with "retired migration(s): 20261101000000_init"; `db:status` says `_init` is "not found locally" | The schema was created in phase 0, before step 1.1 replaced `_init` with `_baseline`                                          | Once: `pnpm db:reset:local` (schema reset as the migrator, then partitions and seed; not a volume deletion, phase-0 rows are lost). See [Upgrading from the phase-0 init migration](../database/README.md#upgrading-from-the-phase-0-init-migration) |
| `prisma migrate dev` fails with `P1003 Database email_gateway_shadow does not exist` or access denied on the shadow database        | The volume predates the scoped migrator grants, or `SHADOW_DATABASE_URL` is missing from `.env`                               | Add `SHADOW_DATABASE_URL` (see `.env.example`), then re-run the accounts script: `docker compose run --rm mysql-replica-setup` (it re-applies `01-users.sh` on the primary, which creates `<db>_shadow`, grants it and revokes the old global grant) |

## Useful endpoints (default ports)

| What                            | URL                                                             |
| ------------------------------- | --------------------------------------------------------------- |
| API OpenAPI                     | http://localhost:3000/docs                                      |
| Admin portal                    | http://localhost:3001                                           |
| RabbitMQ management             | http://localhost:15672 (user/password from `.env`)              |
| MinIO console                   | http://localhost:9001 (`MINIO_ROOT_USER`/`MINIO_ROOT_PASSWORD`) |
| Grafana (observability profile) | http://localhost:3100 (`admin` / `GRAFANA_ADMIN_PASSWORD`)      |

## Sending a test message

```bash
swaks --server 127.0.0.1:2525 --from sender@example.org --to user@gateway.test
```

Until the ingestion service exists, accepted mail goes to Postfix's `discard` transport after the in-session checks.

## Inspecting state

```bash
docker compose exec mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot email_gateway'
docker compose exec mysql-replica sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -e "SHOW REPLICA STATUS\G"'
docker compose exec rabbitmq rabbitmq-diagnostics list_queues name type messages consumers
docker compose exec redis sh -c 'redis-cli info keyspace'
docker compose logs -f postfix rspamd
```
