#!/bin/bash
# Seeds and starts GTID replication from `mysql` (primary) to `mysql-replica`. Runs as the
# one-shot `mysql-replica-setup` Compose service on every `docker compose up`, so it is
# idempotent:
#
#   1. Ensure every account on the primary (01-users.sh over TCP).
#   2. Wait until the replica accepts root connections.
#   3. Replication configured and both threads running  -> exit 0 (nothing to do).
#   4. Configured but not running                        -> START REPLICA; exit 0 if it recovers.
#   5. Otherwise (re)seed: CLONE INSTANCE from the primary (the replica's mysqld exits with error
#      3707 and Docker restarts it on the cloned data), CHANGE REPLICATION SOURCE ... with
#      SOURCE_AUTO_POSITION=1 and SOURCE_SSL=1, START REPLICA, and wait for both threads.
#
# Passwords travel only through the MYSQL_PWD environment variable of the mysql client or SQL on
# stdin; they never appear on a command line or in the output. See docs/database/replication.md.
set -euo pipefail

: "${MYSQL_ROOT_PASSWORD:?}" "${MYSQL_REPLICATION_USER:?}" "${MYSQL_REPLICATION_PASSWORD:?}"
: "${MYSQL_HOST:?}"
PRIMARY_HOST="${MYSQL_HOST}"
REPLICA_HOST="${MYSQL_REPLICA_HOST:-mysql-replica}"
READY_TIMEOUT_S="${REPLICA_READY_TIMEOUT_S:-180}"
THREADS_TIMEOUT_S="${REPLICA_THREADS_TIMEOUT_S:-120}"
USERS_SCRIPT="${USERS_SCRIPT:-/setup/01-users.sh}"

log() { printf '%s [replica-setup] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() {
  log "ERROR: $*"
  exit 1
}

# CHANGE REPLICATION SOURCE TO rejects passwords longer than 32 characters (ERROR 3056).
((${#MYSQL_REPLICATION_PASSWORD} <= 32)) ||
  fail "MYSQL_REPLICATION_PASSWORD is ${#MYSQL_REPLICATION_PASSWORD} characters; MySQL allows at most 32 for replication"

# Runs SQL (from stdin or -e) as root on the replica.
replica_mysql() {
  MYSQL_PWD="${MYSQL_ROOT_PASSWORD}" mysql --protocol=tcp -h "${REPLICA_HOST}" -P 3306 -uroot \
    --batch --connect-timeout=5 "$@"
}
# Same, without column names (for single values).
replica_sql() { replica_mysql --skip-column-names "$@"; }

# Prints one field of SHOW REPLICA STATUS (empty when replication is not configured).
replica_field() {
  replica_mysql -e 'SHOW REPLICA STATUS\G' 2>/dev/null |
    awk -v k="$1" '{
      line = $0; sub(/^ +/, "", line)
      if (line == k ":") { exit }
      if (index(line, k ": ") == 1) { print substr(line, length(k) + 3); exit }
    }'
}

threads_running() {
  [[ "$(replica_field Replica_IO_Running)" == "Yes" && "$(replica_field Replica_SQL_Running)" == "Yes" ]]
}

replication_configured() {
  local n
  n="$(replica_sql -e "SELECT COUNT(*) FROM performance_schema.replication_connection_configuration WHERE CHANNEL_NAME = '' AND HOST <> ''" 2>/dev/null || echo 0)"
  [[ "${n}" -gt 0 ]]
}

wait_for_threads() {
  local timeout="$1" waited=0
  while ((waited < timeout)); do
    if threads_running; then return 0; fi
    sleep 2
    waited=$((waited + 2))
  done
  return 1
}

report_errors() {
  log "Replica_IO_Running=$(replica_field Replica_IO_Running) Replica_SQL_Running=$(replica_field Replica_SQL_Running)"
  log "Last_IO_Error: $(replica_field Last_IO_Error)"
  log "Last_SQL_Error: $(replica_field Last_SQL_Error)"
}

# ---------------------------------------------------------------- 1. accounts on the primary
log "Ensuring accounts on the primary (${PRIMARY_HOST})"
MYSQL_HOST="${PRIMARY_HOST}" bash "${USERS_SCRIPT}"

# ---------------------------------------------------------------- 2. replica reachable
log "Waiting for the replica (${REPLICA_HOST}) to accept connections"
waited=0
until replica_sql -e 'SELECT 1' >/dev/null 2>&1; do
  ((waited < READY_TIMEOUT_S)) || fail "replica not reachable after ${READY_TIMEOUT_S}s"
  sleep 2
  waited=$((waited + 2))
done

# ---------------------------------------------------------------- 3./4. already set up?
if replication_configured; then
  if threads_running; then
    log "Replication already running (Seconds_Behind_Source=$(replica_field Seconds_Behind_Source)); nothing to do"
    exit 0
  fi
  log "Replication configured but not running; trying START REPLICA"
  replica_sql -e 'START REPLICA' || true
  if wait_for_threads 20; then
    log "Replication resumed"
    exit 0
  fi
  report_errors
  log "Replication did not resume; re-seeding the replica from the primary"
  replica_sql -e 'STOP REPLICA; RESET REPLICA ALL' || true
fi

# ---------------------------------------------------------------- 5. seed with CLONE
log "Cloning the primary into the replica; this replaces its data directory and restarts it"
clone_started="$(date +%s)"
set +e
# super_read_only is re-enabled by role.cnf when the replica restarts on the cloned data.
clone_output="$(
  replica_sql 2>&1 <<SQL
SET GLOBAL super_read_only = OFF;
SET GLOBAL clone_valid_donor_list = '${PRIMARY_HOST}:3306';
CLONE INSTANCE FROM '${MYSQL_REPLICATION_USER}'@'${PRIMARY_HOST}':3306
  IDENTIFIED BY '${MYSQL_REPLICATION_PASSWORD}' REQUIRE SSL;
SQL
)"
clone_status=$?
set -e
if ((clone_status != 0)); then
  # The replica's mysqld restarts itself when the clone finishes. Under the supervisor in
  # replica/entrypoint.sh this drops our connection (2013) or returns OK; without one it returns
  # ERROR 3707 and exits, and Docker's restart policy starts it again. Either way the data
  # directory is now the clone; anything else is a real failure.
  if [[ "${clone_output}" =~ ERROR\ (3707|2013) ]]; then
    log "Clone finished; replica is restarting on the cloned data (ERROR ${BASH_REMATCH[1]} is expected)"
  else
    printf '%s\n' "${clone_output}" | sed 's/^/  /' >&2
    fail "CLONE INSTANCE failed"
  fi
else
  log "Clone finished; replica is restarting on the cloned data"
fi

# Wait for the restarted server: it must answer, be a new process (we saw it go down, or its
# uptime is shorter than the time since the clone started) and report the clone as Completed.
saw_down=0
waited=0
while :; do
  ((waited < READY_TIMEOUT_S)) || fail "replica did not come back on the cloned data within ${READY_TIMEOUT_S}s"
  if probe="$(replica_sql -e "SELECT (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME = 'Uptime'), (SELECT STATE FROM performance_schema.clone_status LIMIT 1)" 2>/dev/null)"; then
    read -r uptime state <<<"${probe}"
    elapsed=$(($(date +%s) - clone_started))
    if ((saw_down == 1 || uptime < elapsed)) && [[ "${state}" == "Completed" ]]; then break; fi
  else
    saw_down=1
  fi
  sleep 1
  waited=$((waited + 1))
done
log "Replica is back on the cloned data (clone state ${state})"

log "Configuring GTID auto-positioned replication from ${PRIMARY_HOST}:3306"
replica_sql <<SQL
CHANGE REPLICATION SOURCE TO
  SOURCE_HOST = '${PRIMARY_HOST}',
  SOURCE_PORT = 3306,
  SOURCE_USER = '${MYSQL_REPLICATION_USER}',
  SOURCE_PASSWORD = '${MYSQL_REPLICATION_PASSWORD}',
  SOURCE_AUTO_POSITION = 1,
  SOURCE_SSL = 1,
  SOURCE_CONNECT_RETRY = 10;
START REPLICA;
SQL

if ! wait_for_threads "${THREADS_TIMEOUT_S}"; then
  report_errors
  fail "replication threads not running after ${THREADS_TIMEOUT_S}s"
fi
log "Replication running (Seconds_Behind_Source=$(replica_field Seconds_Behind_Source))"
