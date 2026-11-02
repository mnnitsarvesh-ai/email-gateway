#!/bin/bash
# Creates the gateway's MySQL accounts. Credentials come from the environment, never from this
# file. Idempotent (CREATE USER IF NOT EXISTS + GRANT only), so it is safe to re-run:
#
#   - On first start of an empty data volume, the mysql image runs it from
#     /docker-entrypoint-initdb.d and it connects over the local socket.
#   - mysql-replica-setup re-runs it with MYSQL_HOST=mysql on every `docker compose up`, which
#     adds accounts introduced later (reader, replication) to an existing volume over TCP.
#
# Accounts:
#   app        DML on the gateway schema (DATABASE_URL, writer)
#   migrator   ALL on the gateway schema (MIGRATION_DATABASE_URL), plus ALL on exactly two
#              throwaway schemas: <db>_shadow (SHADOW_DATABASE_URL, `prisma migrate dev`) and
#              <db>_perf (`pnpm db:perf`). No privileges on *.*, so it cannot touch `mysql.*`.
#   reader     SELECT on the schema + REPLICATION CLIENT (DATABASE_READ_URL; lag probe only)
#   repl       REPLICATION SLAVE + BACKUP_ADMIN (replica I/O thread and CLONE donor access)
#
# Existing passwords are not changed (IF NOT EXISTS). After regenerating .env, see
# docs/runbooks/local-stack.md.
set -euo pipefail

: "${MYSQL_ROOT_PASSWORD:?}" "${MYSQL_DATABASE:?}"
: "${MYSQL_APP_USER:?}" "${MYSQL_APP_PASSWORD:?}"
: "${MYSQL_MIGRATOR_USER:?}" "${MYSQL_MIGRATOR_PASSWORD:?}"
: "${MYSQL_READER_USER:?}" "${MYSQL_READER_PASSWORD:?}"
: "${MYSQL_REPLICATION_USER:?}" "${MYSQL_REPLICATION_PASSWORD:?}"

# Schema names in GRANT ... ON `db`.* treat `_` and `%` as wildcards; escape `_` so the
# throwaway-schema grants match exactly one schema each.
db_literal="${MYSQL_DATABASE//_/\\_}"

if [[ -n "${MYSQL_HOST:-}" ]]; then
  connection=(--protocol=tcp -h "${MYSQL_HOST}" -P "${MYSQL_PORT:-3306}")
else
  connection=(--protocol=socket)
fi

# The password travels in the environment of the mysql client only, never on its command line.
MYSQL_PWD="${MYSQL_ROOT_PASSWORD}" mysql "${connection[@]}" -uroot <<SQL
CREATE USER IF NOT EXISTS '${MYSQL_APP_USER}'@'%' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
GRANT SELECT, INSERT, UPDATE, DELETE ON \`${MYSQL_DATABASE}\`.* TO '${MYSQL_APP_USER}'@'%';

CREATE USER IF NOT EXISTS '${MYSQL_MIGRATOR_USER}'@'%' IDENTIFIED BY '${MYSQL_MIGRATOR_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${MYSQL_DATABASE}\`.* TO '${MYSQL_MIGRATOR_USER}'@'%';
-- Throwaway schemas only (never the mysql system schema): the shadow database that
-- \`prisma migrate dev\` resets and replays (shadowDatabaseUrl), and the perf-test schema.
-- Prisma expects the shadow schema to exist already (it resets it, never creates it).
CREATE DATABASE IF NOT EXISTS \`${MYSQL_DATABASE}_shadow\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON \`${db_literal}\\_shadow\`.* TO '${MYSQL_MIGRATOR_USER}'@'%';
GRANT ALL PRIVILEGES ON \`${db_literal}\\_perf\`.* TO '${MYSQL_MIGRATOR_USER}'@'%';
-- Volumes created before step 1.1 granted DDL + DML on *.* (which reaches mysql.user); remove it.
REVOKE IF EXISTS CREATE, DROP, ALTER, INDEX, REFERENCES, SELECT, INSERT, UPDATE, DELETE ON *.* FROM '${MYSQL_MIGRATOR_USER}'@'%';

-- Reader: read-only on the schema. REPLICATION CLIENT only allows SHOW REPLICA STATUS (lag probe).
CREATE USER IF NOT EXISTS '${MYSQL_READER_USER}'@'%' IDENTIFIED BY '${MYSQL_READER_PASSWORD}';
GRANT SELECT ON \`${MYSQL_DATABASE}\`.* TO '${MYSQL_READER_USER}'@'%';
GRANT REPLICATION CLIENT ON *.* TO '${MYSQL_READER_USER}'@'%';

-- Replication: binlog streaming for the replica, BACKUP_ADMIN for the CLONE donor.
CREATE USER IF NOT EXISTS '${MYSQL_REPLICATION_USER}'@'%' IDENTIFIED BY '${MYSQL_REPLICATION_PASSWORD}';
GRANT REPLICATION SLAVE, BACKUP_ADMIN ON *.* TO '${MYSQL_REPLICATION_USER}'@'%';
FLUSH PRIVILEGES;
SQL
