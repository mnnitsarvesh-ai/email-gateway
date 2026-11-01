#!/bin/bash
# Creates separate runtime (DML-only) and migration (DDL) accounts. Runs once, on first start
# of an empty data volume. Credentials come from the environment, never from this file.
set -euo pipefail

: "${MYSQL_DATABASE:?}" "${MYSQL_APP_USER:?}" "${MYSQL_APP_PASSWORD:?}"
: "${MYSQL_MIGRATOR_USER:?}" "${MYSQL_MIGRATOR_PASSWORD:?}"

mysql --protocol=socket -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL
CREATE USER IF NOT EXISTS '${MYSQL_APP_USER}'@'%' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
GRANT SELECT, INSERT, UPDATE, DELETE ON \`${MYSQL_DATABASE}\`.* TO '${MYSQL_APP_USER}'@'%';

CREATE USER IF NOT EXISTS '${MYSQL_MIGRATOR_USER}'@'%' IDENTIFIED BY '${MYSQL_MIGRATOR_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${MYSQL_DATABASE}\`.* TO '${MYSQL_MIGRATOR_USER}'@'%';
-- Local development only: \`prisma migrate dev\` creates and drops a temporary shadow database.
GRANT CREATE, DROP, ALTER, INDEX, REFERENCES, SELECT, INSERT, UPDATE, DELETE ON *.* TO '${MYSQL_MIGRATOR_USER}'@'%';
FLUSH PRIVILEGES;
SQL
