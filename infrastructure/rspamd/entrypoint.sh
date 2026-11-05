#!/bin/sh
# Inbound Rspamd (milter of the inbound Postfix and post-queue /checkv2 engine of the scan
# pipeline; step 4.1 S11/S12, ADR-0026, ADR-0027; docs/deployment/rspamd.md).
#
# Rspamd's UCL config cannot read the environment, so everything secret or environment-dependent
# is rendered here at start into tmpfs-backed local.d and override.d directories (secrets never
# reach a disk outside tmpfs; controller passwords are stored only as `rspamadm pw` hashes).
# Static configuration is copied from the read-only mount /opt/rspamd. Every input is validated;
# an invalid value stops the container (error messages name the variable, never its value).
set -eu

SRC=/opt/rspamd
LOCAL=/etc/rspamd/local.d
OVERRIDE=/etc/rspamd/override.d

die() {
  echo "rspamd-entrypoint: $*; refusing to start" >&2
  exit 64
}

# read_secret NAME: the value of NAME, or the content of the file named by NAME_FILE.
read_secret() {
  eval "_file=\${$1_FILE:-}"
  if [ -n "$_file" ]; then
    [ -r "$_file" ] || die "$1_FILE does not point at a readable file"
    tr -d '\r\n' <"$_file"
  else
    eval "printf '%s' \"\${$1:-}\""
  fi
}

require_uint() { # NAME VALUE MIN MAX
  case "$2" in
    '' | *[!0-9]*) die "$1 must be a non-negative integer" ;;
  esac
  [ "${#2}" -le 12 ] || die "$1 is out of range"
  [ "$2" -ge "$3" ] && [ "$2" -le "$4" ] || die "$1 must be between $3 and $4"
}

require_score() { # NAME VALUE: positive decimal (at most 2 decimals), 1..1000
  printf '%s' "$2" | grep -Eq '^[0-9]{1,4}(\.[0-9]{1,2})?$' || die "$1 must be a decimal score"
  awk -v v="$2" 'BEGIN { exit !(v >= 1 && v <= 1000) }' || die "$1 must be between 1 and 1000"
}

require_bool() { # NAME VALUE
  case "$2" in
    true | false) ;;
    *) die "$1 must be true or false" ;;
  esac
}

require_hostname() { # NAME VALUE
  printf '%s' "$2" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$' \
    || die "$1 must be a host name"
  [ "${#2}" -le 253 ] || die "$1 is too long"
}

require_password() { # NAME VALUE
  [ "${#2}" -ge 16 ] || die "$1 must be at least 16 characters"
  [ "${#2}" -le 256 ] || die "$1 is too long"
  case "$2" in
    *[![:print:]]*) die "$1 must not contain control characters" ;;
  esac
}

# ucl_list NAME VALUE KIND: comma/space separated list -> UCL array of quoted strings.
# KIND addr: IPv4/IPv6 address with an optional :port; cidr: address or network.
ucl_list() {
  _out=''
  for _item in $(printf '%s' "$2" | tr ',' ' '); do
    case "$3" in
      addr) printf '%s' "$_item" | grep -Eq '^(([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{1,5})?|\[?[0-9A-Fa-f:]+\]?(:[0-9]{1,5})?)$' \
        || die "$1 must be a list of IP addresses" ;;
      cidr) printf '%s' "$_item" | grep -Eq '^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$' || die "$1 must be a list of CIDR networks" ;;
    esac
    _out="${_out:+$_out, }\"$_item\""
  done
  [ -n "$_out" ] || die "$1 must not be empty"
  printf '[%s]' "$_out"
}

ucl_escape() { # VALUE -> UCL double-quoted string body
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# ---------------------------------------------------------------- inputs
REDIS_SERVERS=${REDIS_SERVERS:-redis:6379}
REDIS_PASSWORD=$(read_secret REDIS_PASSWORD)
RSPAMD_REDIS_DB=${RSPAMD_REDIS_DB:-1}
RSPAMD_DNS_SERVERS=${RSPAMD_DNS_SERVERS:-}
RSPAMD_LOCAL_ADDRS=${RSPAMD_LOCAL_ADDRS:-127.0.0.0/8, ::1}
RSPAMD_MAX_MESSAGE_BYTES=${RSPAMD_MAX_MESSAGE_BYTES:-52428800}
RSPAMD_NORMAL_WORKERS=${RSPAMD_NORMAL_WORKERS:-1}
RSPAMD_BAYES_MIN_LEARNS=${RSPAMD_BAYES_MIN_LEARNS:-200}
RSPAMD_RBL_PROFILE=${RSPAMD_RBL_PROFILE:-production}
RSPAMD_SPAMHAUS_DQS_KEY=$(read_secret RSPAMD_SPAMHAUS_DQS_KEY)
RSPAMD_PHISH_FEEDS=${RSPAMD_PHISH_FEEDS:-false}
RSPAMD_BAD_URL_MAP_URL=${RSPAMD_BAD_URL_MAP_URL:-}
RSPAMD_MILTER_REJECT_SCORE=${RSPAMD_MILTER_REJECT_SCORE:-15}
RSPAMD_MILTER_DMARC_REJECT=${RSPAMD_MILTER_DMARC_REJECT:-false}
RSPAMD_AUTHSERV_ID=${RSPAMD_AUTHSERV_ID:-mx.gateway.local}
RSPAMD_ARC_TRUSTED_SEALERS=${RSPAMD_ARC_TRUSTED_SEALERS:-}
CONTROLLER_PASSWORD=$(read_secret RSPAMD_CONTROLLER_PASSWORD)
CONTROLLER_ENABLE_PASSWORD=$(read_secret RSPAMD_CONTROLLER_ENABLE_PASSWORD)

require_uint RSPAMD_REDIS_DB "$RSPAMD_REDIS_DB" 0 15
require_uint RSPAMD_MAX_MESSAGE_BYTES "$RSPAMD_MAX_MESSAGE_BYTES" 1048576 268435456
require_uint RSPAMD_NORMAL_WORKERS "$RSPAMD_NORMAL_WORKERS" 1 64
require_uint RSPAMD_BAYES_MIN_LEARNS "$RSPAMD_BAYES_MIN_LEARNS" 1 1000000
require_score RSPAMD_MILTER_REJECT_SCORE "$RSPAMD_MILTER_REJECT_SCORE"
require_bool RSPAMD_PHISH_FEEDS "$RSPAMD_PHISH_FEEDS"
require_bool RSPAMD_MILTER_DMARC_REJECT "$RSPAMD_MILTER_DMARC_REJECT"
require_hostname RSPAMD_AUTHSERV_ID "$RSPAMD_AUTHSERV_ID"
AUTHSERV_ID=$(printf '%s' "$RSPAMD_AUTHSERV_ID" | tr 'A-Z' 'a-z')
# Trusted ARC sealers (ARC-Seal d=), comma/space separated host names; empty = none trusted.
ARC_TRUSTED_SEALERS=''
for _sealer in $(printf '%s' "$RSPAMD_ARC_TRUSTED_SEALERS" | tr ',' ' '); do
  require_hostname RSPAMD_ARC_TRUSTED_SEALERS "$_sealer"
  ARC_TRUSTED_SEALERS="${ARC_TRUSTED_SEALERS}$(printf '%s' "$_sealer" | tr 'A-Z' 'a-z')
"
done
case "$RSPAMD_RBL_PROFILE" in
  test | production) ;;
  *) die "RSPAMD_RBL_PROFILE must be one of: test production" ;;
esac
if [ -n "$RSPAMD_SPAMHAUS_DQS_KEY" ]; then
  printf '%s' "$RSPAMD_SPAMHAUS_DQS_KEY" | grep -Eq '^[A-Za-z0-9]{8,64}$' \
    || die "RSPAMD_SPAMHAUS_DQS_KEY must be an alphanumeric Spamhaus DQS key"
fi
if [ -n "$RSPAMD_BAD_URL_MAP_URL" ]; then
  printf '%s' "$RSPAMD_BAD_URL_MAP_URL" | grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%/+=&?-]*)?$' \
    || die "RSPAMD_BAD_URL_MAP_URL must be an https URL"
fi
[ -n "$CONTROLLER_PASSWORD" ] || die "RSPAMD_CONTROLLER_PASSWORD is required"
[ -n "$CONTROLLER_ENABLE_PASSWORD" ] || die "RSPAMD_CONTROLLER_ENABLE_PASSWORD is required"
require_password RSPAMD_CONTROLLER_PASSWORD "$CONTROLLER_PASSWORD"
require_password RSPAMD_CONTROLLER_ENABLE_PASSWORD "$CONTROLLER_ENABLE_PASSWORD"
[ "$CONTROLLER_PASSWORD" != "$CONTROLLER_ENABLE_PASSWORD" ] \
  || die "RSPAMD_CONTROLLER_ENABLE_PASSWORD must differ from RSPAMD_CONTROLLER_PASSWORD"
LOCAL_ADDRS=$(ucl_list RSPAMD_LOCAL_ADDRS "$RSPAMD_LOCAL_ADDRS" cidr)
NAMESERVERS=''
[ -z "$RSPAMD_DNS_SERVERS" ] || NAMESERVERS=$(ucl_list RSPAMD_DNS_SERVERS "$RSPAMD_DNS_SERVERS" addr)

# ---------------------------------------------------------------- static files
cp "$SRC"/local.d/* "$LOCAL"/
cp "$SRC"/override.d/* "$OVERRIDE"/

umask 077

# ---------------------------------------------------------------- options.inc
{
  echo '# Rendered by entrypoint.sh (step 4.1 S12).'
  echo 'dns {'
  [ -z "$NAMESERVERS" ] || echo "  nameserver = $NAMESERVERS;"
  echo '  timeout = 2s;'
  echo '  retransmits = 2;'
  echo '}'
  # Only these networks are "local" (no SPF/RBL/hfilter checks); Docker addresses are external.
  echo "local_addrs = $LOCAL_ADDRS;"
  echo 'task_timeout = 15s;'
  echo 'gtube_patterns = "all";'
  echo "max_message = $RSPAMD_MAX_MESSAGE_BYTES;"
} >"$OVERRIDE/options.inc"

# ---------------------------------------------------------------- workers
printf '# Rendered by entrypoint.sh. /checkv2 for the post-queue scan; no auth, internal networks only.\nbind_socket = "*:11333";\ncount = %s;\n' \
  "$RSPAMD_NORMAL_WORKERS" >"$LOCAL/worker-normal.inc"

READ_HASH=$(rspamadm pw -q -p "$CONTROLLER_PASSWORD")
ENABLE_HASH=$(rspamadm pw -q -p "$CONTROLLER_ENABLE_PASSWORD")
case "$READ_HASH$ENABLE_HASH" in
  *'"'* | *'\'*) die "rspamadm pw returned an unexpected hash" ;;
esac
cat >"$OVERRIDE/worker-controller.inc" <<EOF
# Rendered by entrypoint.sh. Read password: email-worker (version, /stat); enable password: api
# (learn, fuzzy add/delete). Stored as hashes only. Loopback (health check) needs no password.
bind_socket = "*:11334";
count = 1;
password = "$READ_HASH";
enable_password = "$ENABLE_HASH";
secure_ip = ["127.0.0.1", "::1"];
static_dir = "\${WWWDIR}";
EOF
unset READ_HASH ENABLE_HASH CONTROLLER_PASSWORD CONTROLLER_ENABLE_PASSWORD

# ---------------------------------------------------------------- redis.conf
# With RSPAMD_DNS_SERVERS set, Rspamd's own resolver (e.g. the test dns-sink) cannot resolve
# Compose service names, so the Redis host is resolved here with the system resolver.
REDIS_TARGET=$REDIS_SERVERS
if [ -n "$NAMESERVERS" ]; then
  _host=${REDIS_SERVERS%:*}
  _port=${REDIS_SERVERS##*:}
  [ "$_host" != "$REDIS_SERVERS" ] || _port=6379
  if ! printf '%s' "$_host" | grep -Eq '^[0-9.]+$'; then
    _addr=''
    for _try in 1 2 3 4 5 6 7 8 9 10; do
      _addr=$(getent ahostsv4 "$_host" | awk 'NR == 1 { print $1 }') || true
      [ -z "$_addr" ] || break
      sleep 1
    done
    [ -n "$_addr" ] || die "REDIS_SERVERS host cannot be resolved"
    REDIS_TARGET="$_addr:$_port"
  fi
fi
{
  echo '# Rendered by entrypoint.sh. Rspamd state (Bayes, fuzzy, reputation, history) in its own DB.'
  echo "servers = \"$(ucl_escape "$REDIS_TARGET")\";"
  [ -z "$REDIS_PASSWORD" ] || echo "password = \"$(ucl_escape "$REDIS_PASSWORD")\";"
  echo "db = \"$RSPAMD_REDIS_DB\";"
} >"$OVERRIDE/redis.conf"
unset REDIS_PASSWORD

# ---------------------------------------------------------------- classifier-bayes.conf
cat >"$LOCAL/classifier-bayes.conf" <<EOF
# Rendered by entrypoint.sh. Explicit learning only (platform administrators, S13): no autolearn,
# so senders cannot train the shared statfiles.
backend = "redis";
new_schema = true;
per_user = false;
min_learns = $RSPAMD_BAYES_MIN_LEARNS;
autolearn = false;
EOF

# ---------------------------------------------------------------- rbl.conf
if [ "$RSPAMD_RBL_PROFILE" = test ]; then
  cat >"$OVERRIDE/rbl.conf" <<'EOF'
# Rendered by entrypoint.sh, profile `test` (local/CI). Replaces every default public RBL with the
# zones of the test dns-sink (scan.test); nothing is queried on the Internet.
url_whitelist = [];
attached_maps = [];
rbls {
  EG_TEST_RBL {
    symbol = "EG_TEST_RBL";
    rbl = "rbl.scan.test";
    checks = ["from"];
    ipv6 = false;
  }
  EG_TEST_DBL {
    symbol = "EG_TEST_DBL";
    rbl = "dbl.scan.test";
    no_ip = true;
    ignore_defaults = true;
    checks = ["urls", "emails", "dkim", "replyto"];
    emails_domainonly = true;
    url_full_hostname = true;
    exclude_users = false;
  }
}
EOF
elif [ -n "$RSPAMD_SPAMHAUS_DQS_KEY" ]; then
  cat >"$LOCAL/rbl.conf" <<EOF
# Rendered by entrypoint.sh, profile \`production\` with a Spamhaus DQS key: Rspamd's default RBL
# set (SURBL, URIBL, mailspike, ...) with Spamhaus queried through DQS (zen, dbl, zrd).
rbls {
  spamhaus {
    rbl = "$RSPAMD_SPAMHAUS_DQS_KEY.zen.dq.spamhaus.net";
  }
  DBL {
    rbl = "$RSPAMD_SPAMHAUS_DQS_KEY.dbl.dq.spamhaus.net";
  }
  SPAMHAUS_ZRD {
    symbol = "SPAMHAUS_ZRD";
    rbl = "$RSPAMD_SPAMHAUS_DQS_KEY.zrd.dq.spamhaus.net";
    no_ip = true;
    ignore_defaults = true;
    checks = ["urls", "emails", "dkim", "helo", "rdns", "replyto"];
    emails_domainonly = true;
    exclude_users = false;
    returncodes_matcher = "luapattern";
    returncodes {
      RBL_SPAMHAUS_ZRD = "127%.0%.2%.%d+";
    }
  }
}
EOF
fi

# ---------------------------------------------------------------- phishing.conf
cat >"$LOCAL/phishing.conf" <<EOF
# Rendered by entrypoint.sh. Link text vs. target checks are always on; the public OpenPhish and
# PhishTank feeds only with RSPAMD_PHISH_FEEDS=true (they need Internet access).
symbol = "PHISHING";
openphish_enabled = $RSPAMD_PHISH_FEEDS;
phishtank_enabled = $RSPAMD_PHISH_FEEDS;
EOF

# ---------------------------------------------------------------- multimap.conf
if [ -n "$RSPAMD_BAD_URL_MAP_URL" ]; then
  BAD_URL_MAP="[\"$RSPAMD_BAD_URL_MAP_URL\", \"$SRC/maps/eg_bad_urls.map\"]"
else
  BAD_URL_MAP="\"$SRC/maps/eg_bad_urls.map\""
fi
cat >"$LOCAL/multimap.conf" <<EOF
# Rendered by entrypoint.sh. Known-bad URL hosts (exact host match; score in groups.conf).
EG_BAD_URL {
  type = "url";
  map = $BAD_URL_MAP;
  symbol = "EG_BAD_URL";
  description = "URL host listed in the gateway's known-bad URL map";
  group = "eg_local";
}
EOF

# ---------------------------------------------------------------- dmarc.conf
{
  echo '# Rendered by entrypoint.sh. No DMARC reports are sent from the gateway.'
  echo 'reporting {'
  echo '  enabled = false;'
  echo '}'
  if [ "$RSPAMD_MILTER_DMARC_REJECT" = true ]; then
    echo '# RSPAMD_MILTER_DMARC_REJECT=true: p=reject failures are rejected at SMTP time (ADR-0027).'
    echo 'actions {'
    echo '  reject = "reject";'
    echo '}'
  fi
} >"$LOCAL/dmarc.conf"

# ---------------------------------------------------------------- arc.conf (trusted sealers)
# Step 4.1 S7 R6 / S12: ARC_ALLOW only means "the chain verifies"; anyone can seal with a key of
# their own domain. Only sealers on RSPAMD_ARC_TRUSTED_SEALERS produce ARC_ALLOW_TRUSTED, the
# only ARC signal the post-queue mapping lets suppress a DMARC failure (and only when the trusted
# sealer is the latest hop). adjust_dmarc stays off so that an ARC chain never lowers the DMARC
# score: the mapping alone decides. Empty list: no map, no ARC_ALLOW_TRUSTED.
if [ -n "$ARC_TRUSTED_SEALERS" ]; then
  {
    echo '# Rendered by entrypoint.sh from RSPAMD_ARC_TRUSTED_SEALERS.'
    printf '%s' "$ARC_TRUSTED_SEALERS"
  } >"$LOCAL/arc_trusted_sealers.map"
  {
    echo '# Rendered by entrypoint.sh from RSPAMD_ARC_TRUSTED_SEALERS (step 4.1 S7 R6).'
    echo "whitelisted_signers_map = \"$LOCAL/arc_trusted_sealers.map\";"
    echo 'adjust_dmarc = false;'
  } >>"$LOCAL/arc.conf"
else
  echo 'adjust_dmarc = false;' >>"$LOCAL/arc.conf"
fi

# ---------------------------------------------------------------- actions.conf
cat >"$OVERRIDE/actions.conf" <<EOF
# Rendered by entrypoint.sh (ADR-0027). The only action is reject (GTUBE and score >=
# RSPAMD_MILTER_REJECT_SCORE); no greylisting, soft reject, subject rewrite or header action.
reject = $RSPAMD_MILTER_REJECT_SCORE;
add_header = null;
rewrite_subject = null;
greylist = null;
EOF

# ---------------------------------------------------------------- milter_headers.conf
cat >"$LOCAL/milter_headers.conf" <<EOF
# Rendered by entrypoint.sh (ADR-0027 decision 3). eg-strip-forged removes every inbound
# X-Spam*, X-Spamd-* and X-Rspamd-* header and every Authentication-Results header carrying our
# authserv-id; authentication-results then adds exactly one with our authserv-id (the MTA-Name
# Postfix announces). No score headers are added.
use = ["eg-strip-forged", "authentication-results"];
remove_upstream_spam_flag = true;
extended_spam_headers = false;
skip_local = false;
skip_authenticated = false;
routines {
  authentication-results {
    header = "Authentication-Results";
    remove = false;
    add_smtp_user = false;
  }
}
custom {
  eg-strip-forged = <<EOD
return function(task, common)
  local authserv = '$AUTHSERV_ID'
  local remove, ours, seen = {}, {}, 0
  for _, h in ipairs(task:get_headers(true) or {}) do
    local name = h.name or ''
    local lname = string.lower(name)
    if lname == 'authentication-results' then
      seen = seen + 1
      local id = tostring(h.decoded or h.value or ''):match('^%s*([^;%s]+)')
      if id and string.lower(id) == authserv then
        table.insert(ours, seen)
      end
    elseif lname:find('^x%-spam') or lname:find('^x%-rspamd%-') then
      remove[name] = 0
    end
  end
  -- The milter protocol path of Rspamd takes one index per header name (0 = every instance):
  -- a single forged header is removed by its index, several forged ones remove every
  -- Authentication-Results header (none of them is trusted downstream; ADR-0027 decision 3).
  if #ours == 1 then
    remove['Authentication-Results'] = ours[1]
  elseif #ours > 1 then
    remove['Authentication-Results'] = 0
  end
  return nil, {}, remove, {}
end
EOD;
}
EOF

exec /usr/bin/rspamd -f
