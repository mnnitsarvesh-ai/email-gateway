#!/bin/sh
# Rspamd's UCL config cannot read environment variables, so secrets are rendered at start into
# a tmpfs-backed local.d. Static configuration is copied from the read-only mount.
set -eu

cp /opt/rspamd/local.d/* /etc/rspamd/local.d/

if [ -n "${REDIS_PASSWORD:-}" ]; then
  printf 'servers = "%s";\npassword = "%s";\n' "${REDIS_SERVERS:-redis:6379}" "${REDIS_PASSWORD}" \
    > /etc/rspamd/local.d/redis.conf
else
  printf 'servers = "%s";\n' "${REDIS_SERVERS:-redis:6379}" > /etc/rspamd/local.d/redis.conf
fi
chmod 0600 /etc/rspamd/local.d/redis.conf

exec /usr/bin/rspamd -f
