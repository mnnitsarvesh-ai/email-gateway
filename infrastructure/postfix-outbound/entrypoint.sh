#!/bin/sh
# Outbound MTA entrypoint (step 2.2): validates every environment value, renders it into
# main.cf / master.cf / the static transport table, refuses to start on invalid input or
# `postfix check` output, then runs Postfix in the foreground so Docker sees its exit status.
set -eu

. /usr/local/lib/postfix-entrypoint/validate.sh

: "${POSTFIX_OUTBOUND_MYHOSTNAME:=out.gateway.local}"
: "${SMTP_ADAPTER_HOST:=smtp-adapter}"
: "${POSTFIX_REINJECT_NETWORKS:=127.0.0.0/8}"
: "${POSTFIX_BOUNCE_DOMAIN:=bounces.gateway.internal}"
: "${POSTFIX_DELAY_WARNING_TIME:=4h}"
: "${POSTFIX_MESSAGE_SIZE_LIMIT:=52428800}"
: "${POSTFIX_CLIENT_CONNECTION_COUNT_LIMIT:=50}"
: "${POSTFIX_CLIENT_CONNECTION_RATE_LIMIT:=300}"
: "${POSTFIX_CLIENT_MESSAGE_RATE_LIMIT:=2000}"
: "${POSTFIX_CLIENT_RECIPIENT_RATE_LIMIT:=5000}"
: "${POSTFIX_CLIENT_TLS_SESSION_RATE_LIMIT:=300}"
: "${POSTFIX_CLIENT_AUTH_RATE_LIMIT:=30}"
: "${POSTFIX_SMTPD_PROCESS_LIMIT:=100}"
: "${POSTFIX_MINIMAL_BACKOFF_TIME:=300s}"
: "${POSTFIX_MAXIMAL_BACKOFF_TIME:=4000s}"
: "${POSTFIX_QUEUE_RUN_DELAY:=300s}"
: "${POSTFIX_MAXIMAL_QUEUE_LIFETIME:=5d}"
: "${POSTFIX_OUTBOUND_TLS_CERT_PATH:=/etc/ssl/certs/ssl-cert-snakeoil.pem}"
: "${POSTFIX_OUTBOUND_TLS_KEY_PATH:=/etc/ssl/private/ssl-cert-snakeoil.key}"

require_hostname POSTFIX_OUTBOUND_MYHOSTNAME "$POSTFIX_OUTBOUND_MYHOSTNAME"
require_hostname SMTP_ADAPTER_HOST "$SMTP_ADAPTER_HOST"
require_networks POSTFIX_REINJECT_NETWORKS "$POSTFIX_REINJECT_NETWORKS"
require_hostname POSTFIX_BOUNCE_DOMAIN "$POSTFIX_BOUNCE_DOMAIN"
case "$POSTFIX_BOUNCE_DOMAIN" in
  *.*) ;;
  *) die "POSTFIX_BOUNCE_DOMAIN must be a fully qualified domain" ;;
esac
require_time POSTFIX_DELAY_WARNING_TIME "$POSTFIX_DELAY_WARNING_TIME"
require_uint POSTFIX_MESSAGE_SIZE_LIMIT "$POSTFIX_MESSAGE_SIZE_LIMIT" 1048576
require_uint POSTFIX_CLIENT_CONNECTION_COUNT_LIMIT "$POSTFIX_CLIENT_CONNECTION_COUNT_LIMIT" 1
require_uint POSTFIX_CLIENT_CONNECTION_RATE_LIMIT "$POSTFIX_CLIENT_CONNECTION_RATE_LIMIT" 1
require_uint POSTFIX_CLIENT_MESSAGE_RATE_LIMIT "$POSTFIX_CLIENT_MESSAGE_RATE_LIMIT" 1
require_uint POSTFIX_CLIENT_RECIPIENT_RATE_LIMIT "$POSTFIX_CLIENT_RECIPIENT_RATE_LIMIT" 1
require_uint POSTFIX_CLIENT_TLS_SESSION_RATE_LIMIT "$POSTFIX_CLIENT_TLS_SESSION_RATE_LIMIT" 1
require_uint POSTFIX_CLIENT_AUTH_RATE_LIMIT "$POSTFIX_CLIENT_AUTH_RATE_LIMIT" 1
require_uint POSTFIX_SMTPD_PROCESS_LIMIT "$POSTFIX_SMTPD_PROCESS_LIMIT" 1
require_time POSTFIX_MINIMAL_BACKOFF_TIME "$POSTFIX_MINIMAL_BACKOFF_TIME"
require_time POSTFIX_MAXIMAL_BACKOFF_TIME "$POSTFIX_MAXIMAL_BACKOFF_TIME"
require_time POSTFIX_QUEUE_RUN_DELAY "$POSTFIX_QUEUE_RUN_DELAY"
require_time POSTFIX_MAXIMAL_QUEUE_LIFETIME "$POSTFIX_MAXIMAL_QUEUE_LIFETIME"
require_readable POSTFIX_OUTBOUND_TLS_CERT_PATH "$POSTFIX_OUTBOUND_TLS_CERT_PATH"
require_readable POSTFIX_OUTBOUND_TLS_KEY_PATH "$POSTFIX_OUTBOUND_TLS_KEY_PATH"

reinject_networks=$(printf '%s' "$POSTFIX_REINJECT_NETWORKS" | tr ',' ' ' | tr -s ' ')

postconf -e \
  "myhostname=${POSTFIX_OUTBOUND_MYHOSTNAME}" \
  "smtp_adapter_host=${SMTP_ADAPTER_HOST}" \
  "reinject_networks=${reinject_networks}" \
  "gw_bounce_domain=${POSTFIX_BOUNCE_DOMAIN}" \
  "delay_warning_time=${POSTFIX_DELAY_WARNING_TIME}" \
  "message_size_limit=${POSTFIX_MESSAGE_SIZE_LIMIT}" \
  "smtpd_client_connection_count_limit=${POSTFIX_CLIENT_CONNECTION_COUNT_LIMIT}" \
  "smtpd_client_connection_rate_limit=${POSTFIX_CLIENT_CONNECTION_RATE_LIMIT}" \
  "smtpd_client_message_rate_limit=${POSTFIX_CLIENT_MESSAGE_RATE_LIMIT}" \
  "smtpd_client_recipient_rate_limit=${POSTFIX_CLIENT_RECIPIENT_RATE_LIMIT}" \
  "smtpd_client_new_tls_session_rate_limit=${POSTFIX_CLIENT_TLS_SESSION_RATE_LIMIT}" \
  "smtpd_client_auth_rate_limit=${POSTFIX_CLIENT_AUTH_RATE_LIMIT}" \
  "minimal_backoff_time=${POSTFIX_MINIMAL_BACKOFF_TIME}" \
  "maximal_backoff_time=${POSTFIX_MAXIMAL_BACKOFF_TIME}" \
  "queue_run_delay=${POSTFIX_QUEUE_RUN_DELAY}" \
  "maximal_queue_lifetime=${POSTFIX_MAXIMAL_QUEUE_LIFETIME}" \
  "bounce_queue_lifetime=${POSTFIX_MAXIMAL_QUEUE_LIFETIME}" \
  "smtpd_tls_cert_file=${POSTFIX_OUTBOUND_TLS_CERT_PATH}" \
  "smtpd_tls_key_file=${POSTFIX_OUTBOUND_TLS_KEY_PATH}"

# Every smtpd listener carries the same process limit (master.cf maxproc column).
for service in smtp/inet submission/inet 10026/inet 10027/inet; do
  postconf -F "${service}/process_limit=${POSTFIX_SMTPD_PROCESS_LIMIT}"
done

# Bounce notices (postmaster copies of DSNs) go to the bounce handler of smtp-adapter (D13).
printf '%s lmtp:inet:%s:10052\n' "$POSTFIX_BOUNCE_DOMAIN" "$SMTP_ADAPTER_HOST" > /etc/postfix/transport
chmod 0644 /etc/postfix/transport

check_output=$(postfix check 2>&1) || {
  printf '%s\n' "$check_output" >&2
  die "postfix check failed"
}
if [ -n "$check_output" ]; then
  printf '%s\n' "$check_output" >&2
  die "postfix check reported warnings"
fi

exec postfix start-fg
