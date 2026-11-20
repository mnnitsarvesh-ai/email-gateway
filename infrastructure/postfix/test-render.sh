#!/bin/sh
# Rendering check of the inbound Postfix entrypoint (step 8.6 D2.1, ADR-0087): runs the CURRENT
# entrypoint.sh / validate.sh / main.cf / master.cf (mounted read-only over the image's copies)
# with POSTFIX_RENDER_CHECK=true, so nothing is started, and asserts
#   - without a journal intake domain: the step 2.2 relay_domains, empty transport_maps;
#   - with one: the intake domain first in relay_domains, transport_maps routing it to the
#     journal LMTP (:10053) with ${smtp_adapter_host} expanded, smtpd_tls_ask_ccert=yes;
#   - an invalid domain refuses to start (exit 64).
# Usage: infrastructure/postfix/test-render.sh [image]   (default email-gateway/postfix:local;
# build it first with `docker compose build postfix`). No secret is involved.
set -eu

IMAGE=${1:-email-gateway/postfix:local}
DIR=$(cd "$(dirname "$0")" && pwd)

render() {
  docker run --rm \
    -e POSTFIX_RENDER_CHECK=true \
    -e SMTP_ADAPTER_HOST=adapter.internal.test \
    -e POSTFIX_JOURNAL_INTAKE_DOMAIN="$1" \
    -v "$DIR/entrypoint.sh:/usr/local/bin/postfix-entrypoint:ro" \
    -v "$DIR/validate.sh:/usr/local/lib/postfix-entrypoint/validate.sh:ro" \
    -v "$DIR/main.cf:/opt/postfix-src/main.cf:ro" \
    -v "$DIR/master.cf:/opt/postfix-src/master.cf:ro" \
    --entrypoint /bin/sh "$IMAGE" -c \
    'cp /opt/postfix-src/main.cf /opt/postfix-src/master.cf /etc/postfix/ && exec /usr/local/bin/postfix-entrypoint'
}

fail() {
  echo "test-render: $*" >&2
  exit 1
}

expect_line() { # OUTPUT LINE
  printf '%s\n' "$1" | grep -Fxq -- "$2" || fail "missing: $2
--- output ---
$1"
}

without=$(render '') || fail 'rendering without an intake domain failed'
expect_line "$without" 'relay_domains = socketmap:inet:${smtp_adapter_host}:10041:relay_domain'
expect_line "$without" 'transport_maps ='
expect_line "$without" 'smtpd_tls_ask_ccert = no'

with=$(render 'Journal.Gateway.TEST') || fail 'rendering with an intake domain failed'
expect_line "$with" 'relay_domains = journal.gateway.test, socketmap:inet:${smtp_adapter_host}:10041:relay_domain'
expect_line "$with" 'transport_maps = inline:{ journal.gateway.test=lmtp:inet:${smtp_adapter_host}:10053 }'
expect_line "$with" 'transport_maps = inline:{ journal.gateway.test=lmtp:inet:adapter.internal.test:10053 }'
expect_line "$with" 'smtpd_tls_ask_ccert = yes'
# The transport table answers for the intake domain (postmap -q of the expanded table).
expect_line "$with" 'lmtp:inet:adapter.internal.test:10053'

for bad in 'localhost' '192.0.2.1' 'bad domain.test' 'journal.gateway.test;x'; do
  if render "$bad" >/dev/null 2>&1; then fail "accepted an invalid intake domain: $bad"; fi
done

echo 'test-render: ok (without and with POSTFIX_JOURNAL_INTAKE_DOMAIN, invalid values refused)'
