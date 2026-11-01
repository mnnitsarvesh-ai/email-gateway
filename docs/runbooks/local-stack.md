# Runbook: local stack

## Start and stop

```bash
pnpm env:init                                         # once
docker compose up -d --wait                           # infrastructure
pnpm db:migrate                                       # apply migrations from the host
docker compose --profile apps up -d --build --wait    # everything, including services
docker compose --profile apps down                    # stop (keep data)
docker compose --profile apps down -v                 # stop and wipe all volumes
```

## Symptoms and fixes

| Symptom                                                             | Cause                                                               | Fix                                                                                                                                                                                                                                 |
| ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ports are not available ... address already in use`                | Another local stack uses a default port                             | Set the matching `*_HOST_PORT` in `.env`, and update the URL that uses it (e.g. `DATABASE_URL`), then `docker compose up -d`                                                                                                        |
| `required variable ... is missing a value`                          | No `.env`                                                           | `pnpm env:init`                                                                                                                                                                                                                     |
| MySQL "Access denied" after regenerating `.env`                     | The data volume was initialised with the old passwords              | `docker compose down -v` (wipes local data), then start again                                                                                                                                                                       |
| `clamav` stays `starting` on first run                              | freshclam is downloading signatures (~300 MB)                       | Wait. The health check allows a 10-minute start period, and later starts reuse the `clamav-db` volume                                                                                                                               |
| RCPT returns `451 4.3.5 Policy service unavailable`                 | `smtp-adapter` isn't running (expected with infra only)             | Start the `apps` profile. This tempfail is the intended fail-closed behaviour                                                                                                                                                       |
| RCPT returns `554 Relay access denied`                              | Recipient domain not in `POSTFIX_RELAY_DOMAINS`                     | Use a domain from that list (default `gateway.test`)                                                                                                                                                                                |
| Rspamd logs `DNS reply returned 'no error' ... likely DNS spoofing` | Public DNSBLs refuse queries from shared resolvers                  | Harmless locally. Production uses a dedicated recursive resolver                                                                                                                                                                    |
| Image build fails with `cannot allocate memory`, or Docker restarts | Building every app image in parallel exceeds the Docker VM's memory | Build one at a time: `for s in db-migrate api smtp-adapter email-worker policy-engine delivery-worker notification-worker archive-worker admin-portal; do docker compose --profile apps build $s; done`, or give Docker more memory |
| `/health/ready` returns 503                                         | A dependency check failed                                           | The response body names the failing check and its error                                                                                                                                                                             |

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
docker compose exec mysql sh -c 'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" email_gateway'
docker compose exec rabbitmq rabbitmq-diagnostics list_queues name type messages consumers
docker compose exec redis sh -c 'redis-cli info keyspace'
docker compose logs -f postfix rspamd
```
