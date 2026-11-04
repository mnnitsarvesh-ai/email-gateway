#!/bin/sh
# TEST-ONLY 3-node cluster (Compose profile rabbitmq-cluster, step 3.2 §7): writes the shared
# Erlang cookie from RABBITMQ_CLUSTER_ERLANG_COOKIE (never printed) before the image's own
# entrypoint starts the broker. The cookie file must be owned by rabbitmq with mode 400.
set -eu
if [ -z "${RABBITMQ_CLUSTER_ERLANG_COOKIE:-}" ]; then
  echo 'cluster-entrypoint: RABBITMQ_CLUSTER_ERLANG_COOKIE is not set' >&2
  exit 1
fi
cookie=/var/lib/rabbitmq/.erlang.cookie
umask 077
rm -f "$cookie"
printf '%s' "$RABBITMQ_CLUSTER_ERLANG_COOKIE" > "$cookie"
chown rabbitmq:rabbitmq "$cookie"
chmod 400 "$cookie"
unset RABBITMQ_CLUSTER_ERLANG_COOKIE
exec docker-entrypoint.sh rabbitmq-server
