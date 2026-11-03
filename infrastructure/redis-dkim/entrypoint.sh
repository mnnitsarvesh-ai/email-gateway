#!/bin/sh
# redis-dkim entrypoint (step 2.2 D12, ADR-0020): a dedicated Redis holding the DKIM signing keys
# of active, outbound-enabled domains. Renders the ACL file into a tmpfs (mode 0600, passwords
# stored as SHA-256 hashes, never in plaintext), then runs Redis without any persistence: keys
# never touch a disk outside MySQL ciphertext. After a restart the api's publisher refills it
# within one sync interval; until then the reinject-outbound policy defers (fail closed).
#
# Users (exactly the grants of D12):
#   default      off
#   dkim-writer  api DkimSigningPublisher: read/write both hashes, MULTI/EXEC
#   dkim-reader  rspamd-outbound: HGET (+SELECT; Rspamd sends AUTH, then HGET, and SELECT only
#                when a database is configured, see lua_redis.lua / lua_dkim_tools.lua)
#   dkim-probe   smtp-adapter selector probe: read-only on dkim_selectors, never dkim_keys
set -eu

die() {
  echo "redis-dkim-entrypoint: $*; refusing to start" >&2
  exit 64
}

acl_dir=/run/redis-dkim
acl_file=$acl_dir/users.acl

hash_of() {
  printf '%s' "$1" | sha256sum | cut -d' ' -f1
}

check_secret() {
  eval "_value=\${$1:-}"
  [ -n "$_value" ] || die "$1 is required"
  [ "${#_value}" -ge 32 ] || die "$1 must be at least 32 characters"
  case "$_value" in
    *[[:space:]]*) die "$1 must not contain whitespace" ;;
  esac
}

check_secret REDIS_DKIM_WRITER_PASSWORD
check_secret REDIS_DKIM_READER_PASSWORD
check_secret REDIS_DKIM_PROBE_PASSWORD

writer_hash=$(hash_of "$REDIS_DKIM_WRITER_PASSWORD")
reader_hash=$(hash_of "$REDIS_DKIM_READER_PASSWORD")
probe_hash=$(hash_of "$REDIS_DKIM_PROBE_PASSWORD")
unset REDIS_DKIM_WRITER_PASSWORD REDIS_DKIM_READER_PASSWORD REDIS_DKIM_PROBE_PASSWORD

umask 077
mkdir -p "$acl_dir"
cat > "$acl_file" <<EOF
user default off resetpass resetkeys resetchannels -@all
user dkim-writer on #$writer_hash resetchannels ~dkim_selectors ~dkim_keys -@all +ping +hget +hgetall +hkeys +hset +hdel +hexists +multi +exec +del
user dkim-reader on #$reader_hash resetchannels ~dkim_selectors ~dkim_keys -@all +ping +hget +select
user dkim-probe on #$probe_hash resetchannels %R~dkim_selectors -@all +ping +hexists +hget
EOF
chown -R redis:redis "$acl_dir"
chmod 0700 "$acl_dir"
chmod 0600 "$acl_file"

cd /data
exec setpriv --reuid redis --regid redis --clear-groups redis-server \
  --port 6379 \
  --bind 0.0.0.0 \
  --aclfile "$acl_file" \
  --save '' \
  --appendonly no \
  --maxmemory 64mb \
  --maxmemory-policy noeviction
