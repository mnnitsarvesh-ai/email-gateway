#!/bin/bash
# Entrypoint for mysql-replica: the stock mysql image entrypoint with two changes.
#
# 1. role.cnf sets read_only and super_read_only, which the stock entrypoint's *temporary* init
#    server (first start on an empty volume) also reads, so its root-account setup would fail with
#    ERROR 1290. Only that temporary server is started with both turned off; the real server always
#    runs with role.cnf as written. (CLONE replaces the data directory anyway: the init only has to
#    produce a root account that mysql-replica-setup can log in with.)
#
# 2. The real mysqld runs under a minimal supervisor, as mysqld_safe or systemd would. CLONE
#    INSTANCE restarts the recipient server when it finishes; mysqld does that by exiting with
#    code 16 when it sees MYSQLD_PARENT_PID set to its parent. Restarting inside the container
#    keeps the container running, so `docker compose up --wait` does not see it exit mid-seed.
set -eo pipefail

# The stock entrypoint re-executes *itself* as the mysql user, which would drop the overrides
# below, so switch user here first.
if [ "$(id -u)" = '0' ]; then
  exec gosu mysql "${BASH_SOURCE[0]}" "$@"
fi

# Sourcing defines the entrypoint's functions without running it (it checks _is_sourced).
# shellcheck source=/dev/null
source /usr/local/bin/docker-entrypoint.sh

eval "_upstream_$(declare -f docker_temp_server_start)"
docker_temp_server_start() {
  _upstream_docker_temp_server_start "$@" --read-only=OFF --super-read-only=OFF
}

readonly MYSQLD_RESTART_EXIT_CODE=16

supervise() {
  local pid='' rc
  export MYSQLD_PARENT_PID=$$
  trap '[ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null' TERM INT
  while :; do
    "$@" &
    pid=$!
    rc=0
    wait "$pid" || rc=$?
    # A trapped signal interrupts `wait`; keep waiting until mysqld has really exited.
    while kill -0 "$pid" 2>/dev/null; do
      rc=0
      wait "$pid" || rc=$?
    done
    if [ "$rc" -ne "$MYSQLD_RESTART_EXIT_CODE" ]; then
      exit "$rc"
    fi
    mysql_note "mysqld requested a restart (CLONE finished); starting it again"
  done
}

# _main ends with `exec "$@"` (mysqld). A function named exec takes precedence over the builtin,
# so that last step runs mysqld under the supervisor instead. (_main's only other exec is the
# root -> mysql user switch, which cannot happen here: we already run as mysql.)
exec() {
  unset -f exec
  supervise "$@"
}

_main "$@"
