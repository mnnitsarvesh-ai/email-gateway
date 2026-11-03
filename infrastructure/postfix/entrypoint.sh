#!/bin/sh
# Inbound MX entrypoint (step 2.2): validates every environment value, renders it into main.cf /
# master.cf with postconf, refuses to start on invalid input or `postfix check` errors, then runs
# Postfix in the foreground so Docker sees its exit status.
#
# POSTFIX_RELAY_DOMAINS is no longer read: relay domains come from smtp-adapter (socketmap).
set -eu

. /usr/local/lib/postfix-entrypoint/validate.sh

: "${POSTFIX_MYHOSTNAME:=mx.gateway.local}"
: "${SMTP_ADAPTER_HOST:=smtp-adapter}"
: "${POSTFIX_MESSAGE_SIZE_LIMIT:=52428800}"
: "${POSTFIX_CLIENT_CONNECTION_COUNT_LIMIT:=50}"
: "${POSTFIX_CLIENT_CONNECTION_RATE_LIMIT:=300}"
: "${POSTFIX_CLIENT_MESSAGE_RATE_LIMIT:=2000}"
: "${POSTFIX_CLIENT_RECIPIENT_RATE_LIMIT:=5000}"
: "${POSTFIX_CLIENT_TLS_SESSION_RATE_LIMIT:=300}"
: "${POSTFIX_SMTPD_PROCESS_LIMIT:=100}"
: "${POSTFIX_POSTSCREEN_GREET_ACTION:=ignore}"
: "${POSTFIX_POSTSCREEN_DNSBL_SITES:=}"
: "${POSTFIX_MINIMAL_BACKOFF_TIME:=300s}"
: "${POSTFIX_MAXIMAL_BACKOFF_TIME:=4000s}"
: "${POSTFIX_QUEUE_RUN_DELAY:=300s}"
: "${POSTFIX_MAXIMAL_QUEUE_LIFETIME:=5d}"
: "${POSTFIX_TLS_CERT_PATH:=/etc/ssl/certs/ssl-cert-snakeoil.pem}"
: "${POSTFIX_TLS_KEY_PATH:=/etc/ssl/private/ssl-cert-snakeoil.key}"

require_hostname POSTFIX_MYHOSTNAME "$POSTFIX_MYHOSTNAME"
require_hostname SMTP_ADAPTER_HOST "$SMTP_ADAPTER_HOST"
require_uint POSTFIX_MESSAGE_SIZE_LIMIT "$POSTFIX_MESSAGE_SIZE_LIMIT" 1048576
require_uint POSTFIX_CLIENT_CONNECTION_COUNT_LIMIT "$POSTFIX_CLIENT_CONNECTION_COUNT_LIMIT" 1
require_uint POSTFIX_CLIENT_CONNECTION_RATE_LIMIT "$POSTFIX_CLIENT_CONNECTION_RATE_LIMIT" 1
require_uint POSTFIX_CLIENT_MESSAGE_RATE_LIMIT "$POSTFIX_CLIENT_MESSAGE_RATE_LIMIT" 1
require_uint POSTFIX_CLIENT_RECIPIENT_RATE_LIMIT "$POSTFIX_CLIENT_RECIPIENT_RATE_LIMIT" 1
require_uint POSTFIX_CLIENT_TLS_SESSION_RATE_LIMIT "$POSTFIX_CLIENT_TLS_SESSION_RATE_LIMIT" 1
require_uint POSTFIX_SMTPD_PROCESS_LIMIT "$POSTFIX_SMTPD_PROCESS_LIMIT" 1
require_enum POSTFIX_POSTSCREEN_GREET_ACTION "$POSTFIX_POSTSCREEN_GREET_ACTION" ignore enforce drop
# DNSBL sites: names with optional =filter and *weight (postconf(5) postscreen_dnsbl_sites).
case "$POSTFIX_POSTSCREEN_DNSBL_SITES" in
  *[!A-Za-z0-9.,=*\;:\[\]\ _-]*) die "POSTFIX_POSTSCREEN_DNSBL_SITES contains unsupported characters" ;;
esac
require_time POSTFIX_MINIMAL_BACKOFF_TIME "$POSTFIX_MINIMAL_BACKOFF_TIME"
require_time POSTFIX_MAXIMAL_BACKOFF_TIME "$POSTFIX_MAXIMAL_BACKOFF_TIME"
require_time POSTFIX_QUEUE_RUN_DELAY "$POSTFIX_QUEUE_RUN_DELAY"
require_time POSTFIX_MAXIMAL_QUEUE_LIFETIME "$POSTFIX_MAXIMAL_QUEUE_LIFETIME"
require_readable POSTFIX_TLS_CERT_PATH "$POSTFIX_TLS_CERT_PATH"
require_readable POSTFIX_TLS_KEY_PATH "$POSTFIX_TLS_KEY_PATH"

postconf -e \
  "myhostname=${POSTFIX_MYHOSTNAME}" \
  "smtp_adapter_host=${SMTP_ADAPTER_HOST}" \
  "message_size_limit=${POSTFIX_MESSAGE_SIZE_LIMIT}" \
  "smtpd_client_connection_count_limit=${POSTFIX_CLIENT_CONNECTION_COUNT_LIMIT}" \
  "smtpd_client_connection_rate_limit=${POSTFIX_CLIENT_CONNECTION_RATE_LIMIT}" \
  "smtpd_client_message_rate_limit=${POSTFIX_CLIENT_MESSAGE_RATE_LIMIT}" \
  "smtpd_client_recipient_rate_limit=${POSTFIX_CLIENT_RECIPIENT_RATE_LIMIT}" \
  "smtpd_client_new_tls_session_rate_limit=${POSTFIX_CLIENT_TLS_SESSION_RATE_LIMIT}" \
  "postscreen_greet_action=${POSTFIX_POSTSCREEN_GREET_ACTION}" \
  "postscreen_dnsbl_sites=${POSTFIX_POSTSCREEN_DNSBL_SITES}" \
  "minimal_backoff_time=${POSTFIX_MINIMAL_BACKOFF_TIME}" \
  "maximal_backoff_time=${POSTFIX_MAXIMAL_BACKOFF_TIME}" \
  "queue_run_delay=${POSTFIX_QUEUE_RUN_DELAY}" \
  "maximal_queue_lifetime=${POSTFIX_MAXIMAL_QUEUE_LIFETIME}" \
  "bounce_queue_lifetime=${POSTFIX_MAXIMAL_QUEUE_LIFETIME}" \
  "smtpd_tls_cert_file=${POSTFIX_TLS_CERT_PATH}" \
  "smtpd_tls_key_file=${POSTFIX_TLS_KEY_PATH}"

# postscreen's pregreet test runs even when its result is ignored: it sends a "220-" teaser and
# delays every first contact by postscreen_greet_wait. With action `ignore` (local, CI) that
# costs latency for nothing, so the teaser is disabled and the wait cut to the 1s minimum. With
# `enforce`/`drop` (production) Postfix's defaults apply (teaser = $smtpd_banner, 6s, 2s under
# stress).
if [ "$POSTFIX_POSTSCREEN_GREET_ACTION" = ignore ]; then
  postconf -e "postscreen_greet_banner=" "postscreen_greet_wait=1s"
else
  postconf -X postscreen_greet_banner postscreen_greet_wait
fi

# The smtpd behind postscreen carries the process limit (master.cf maxproc column).
postconf -F "smtpd/pass/process_limit=${POSTFIX_SMTPD_PROCESS_LIMIT}"

# `postfix check` exits non-zero on errors; warnings are printed and treated as errors too, so a
# configuration drift is noticed at start instead of in production traffic.
check_output=$(postfix check 2>&1) || {
  printf '%s\n' "$check_output" >&2
  die "postfix check failed"
}
if [ -n "$check_output" ]; then
  printf '%s\n' "$check_output" >&2
  die "postfix check reported warnings"
fi

exec postfix start-fg
