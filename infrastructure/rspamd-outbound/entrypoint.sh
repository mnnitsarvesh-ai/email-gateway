#!/bin/sh
# rspamd-outbound entrypoint (step 2.2 D12). Rspamd's UCL configuration cannot read environment
# variables, so the static configuration is copied from the read-only mount into a tmpfs-backed
# local.d and the redis-dkim credentials are appended to dkim_signing.conf (mode 0600, readable
# only by the _rspamd user). The password never reaches a file outside the tmpfs.
set -eu

die() {
  echo "rspamd-outbound-entrypoint: $*; refusing to start" >&2
  exit 64
}

: "${REDIS_DKIM_SERVERS:=redis-dkim:6379}"
: "${REDIS_DKIM_READER_USERNAME:=dkim-reader}"
password="${REDIS_DKIM_READER_PASSWORD:-}"

[ -n "$password" ] || die "REDIS_DKIM_READER_PASSWORD is required"
# Values are embedded in a quoted UCL string: allow only characters that need no escaping.
printf '%s' "$password" | grep -Eq '^[A-Za-z0-9._~+/=-]{16,256}$' \
  || die "REDIS_DKIM_READER_PASSWORD must be 16-256 characters of [A-Za-z0-9._~+/=-]"
printf '%s' "$REDIS_DKIM_READER_USERNAME" | grep -Eq '^[A-Za-z0-9._-]{1,64}$' \
  || die "REDIS_DKIM_READER_USERNAME is invalid"
printf '%s' "$REDIS_DKIM_SERVERS" | grep -Eq '^[A-Za-z0-9.-]+:[0-9]{1,5}$' \
  || die "REDIS_DKIM_SERVERS must be host:port"

umask 077
cp /opt/rspamd/local.d/* /etc/rspamd/local.d/
{
  printf '\n# Rendered at container start (redis-dkim, ACL user with HGET only).\n'
  printf 'servers = "%s";\n' "$REDIS_DKIM_SERVERS"
  printf 'username = "%s";\n' "$REDIS_DKIM_READER_USERNAME"
  printf 'password = "%s";\n' "$password"
} >> /etc/rspamd/local.d/dkim_signing.conf
chmod 0600 /etc/rspamd/local.d/dkim_signing.conf
unset password REDIS_DKIM_READER_PASSWORD

# Fail fast on a configuration error instead of running without the signing module.
/usr/bin/rspamadm configtest >/dev/null || die "rspamadm configtest failed"

exec /usr/bin/rspamd -f
