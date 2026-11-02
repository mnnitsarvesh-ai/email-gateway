#!/bin/sh
# Renders the upstream relay settings from the environment, validates and runs Postfix in the
# foreground. Without NOTIFY_RELAY_HOST (CI, fresh checkouts) it accepts and DISCARDS mail, and
# says so loudly; with it, every relay setting is required.
set -eu

: "${POSTFIX_MYNETWORKS:=127.0.0.0/8}"

if [ -z "${NOTIFY_RELAY_HOST:-}" ]; then
  echo "postfix-notify: NOTIFY_RELAY_HOST is not set; transactional mail is accepted and DISCARDED" >&2
  postconf -e "mynetworks=${POSTFIX_MYNETWORKS}" "smtp_sasl_auth_enable=no" \
    "default_transport=discard:no upstream relay configured" \
    "relay_transport=discard:no upstream relay configured"
  postfix check
  exec postfix start-fg
fi

: "${NOTIFY_RELAY_PORT:=587}"
: "${NOTIFY_RELAY_USER:?NOTIFY_RELAY_USER is required}"
: "${NOTIFY_RELAY_PASSWORD:?NOTIFY_RELAY_PASSWORD is required}"
: "${NOTIFY_RELAY_TLS_FINGERPRINT:?NOTIFY_RELAY_TLS_FINGERPRINT (SHA-256 of the upstream certificate) is required}"

install -d -m 0700 /etc/postfix/sasl
umask 077
printf '[%s]:%s %s:%s\n' "$NOTIFY_RELAY_HOST" "$NOTIFY_RELAY_PORT" "$NOTIFY_RELAY_USER" "$NOTIFY_RELAY_PASSWORD" \
  > /etc/postfix/sasl/relay_passwd
umask 022

postconf -e \
  "relayhost=[${NOTIFY_RELAY_HOST}]:${NOTIFY_RELAY_PORT}" \
  "smtp_tls_fingerprint_cert_match=${NOTIFY_RELAY_TLS_FINGERPRINT}" \
  "mynetworks=${POSTFIX_MYNETWORKS}"

newaliases 2>/dev/null || true
postfix check
exec postfix start-fg
