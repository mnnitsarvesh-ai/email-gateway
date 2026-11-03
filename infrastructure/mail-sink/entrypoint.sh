#!/bin/sh
# mail-sink entrypoint (TEST-ONLY, Compose profile smtp-test; step 2.2 §6, extended in step 2.3
# §6). Renders the sink's identity and mode from the environment, refuses to start on invalid
# input or `postfix check` output, then runs Postfix in the foreground.
#
#   SINK_HOSTNAME           myhostname / banner (default mx.sink.test)
#   SINK_TLS_CERT_PATH      server certificate chain (default: the image's snakeoil certificate)
#   SINK_TLS_KEY_PATH       its private key (default: snakeoil); Postfix reads it as root
#   SINK_MODE               store (default): every *.test domain into Maildirs, never relays
#                           relay: accepts every *.test domain and relays ALL of it to
#                           SINK_RELAY_NEXTHOP instead of storing it (a tenant server that sends
#                           mail back to the gateway MX: loop tests)
#   SINK_RELAY_NEXTHOP      relay mode: next hop, e.g. [172.31.250.10]:25 (required)
#   SINK_RECIPIENT_REWRITE  relay mode: 'from.domain=to.domain,...' envelope recipient domain
#                           rewrites applied before relaying (empty: none)
#
# With no variables set the sink behaves exactly as before step 2.3.
set -eu

die() {
  echo "mail-sink-entrypoint: $*; refusing to start" >&2
  exit 64
}

is_hostname() {
  printf '%s' "$1" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
}

: "${SINK_HOSTNAME:=mx.sink.test}"
: "${SINK_TLS_CERT_PATH:=/etc/ssl/certs/ssl-cert-snakeoil.pem}"
: "${SINK_TLS_KEY_PATH:=/etc/ssl/private/ssl-cert-snakeoil.key}"
: "${SINK_MODE:=store}"
: "${SINK_RELAY_NEXTHOP:=}"
: "${SINK_RECIPIENT_REWRITE:=}"

is_hostname "$SINK_HOSTNAME" || die "SINK_HOSTNAME must be a host name"
for pair in "SINK_TLS_CERT_PATH:$SINK_TLS_CERT_PATH" "SINK_TLS_KEY_PATH:$SINK_TLS_KEY_PATH"; do
  name=${pair%%:*}
  path=${pair#*:}
  case "$path" in
    /*) ;;
    *) die "$name must be an absolute path" ;;
  esac
  [ -r "$path" ] || die "$name does not point at a readable file"
done

postconf -e \
  "myhostname=${SINK_HOSTNAME}" \
  "smtpd_tls_cert_file=${SINK_TLS_CERT_PATH}" \
  "smtpd_tls_key_file=${SINK_TLS_KEY_PATH}"

rewrite_map=/etc/postfix/sink/rewrite.regexp

case "$SINK_MODE" in
  store)
    [ -z "$SINK_RELAY_NEXTHOP" ] || die "SINK_RELAY_NEXTHOP is only valid with SINK_MODE=relay"
    [ -z "$SINK_RECIPIENT_REWRITE" ] || die "SINK_RECIPIENT_REWRITE is only valid with SINK_MODE=relay"
    ;;
  relay)
    # [IPv4]:port, [host]:port or host[:port]; no spaces, no '$'.
    printf '%s' "$SINK_RELAY_NEXTHOP" \
      | grep -Eq '^(\[[A-Za-z0-9.-]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?$' \
      || die "SINK_RELAY_NEXTHOP must look like [172.31.250.10]:25"
    # Accept every *.test domain (relay_domains) and send everything to the next hop. The
    # recipient restrictions (reject_unauth_destination, scripted refusals) are unchanged, so it
    # still relays only for *.test recipients.
    postconf -e \
      "virtual_mailbox_domains=" \
      "virtual_mailbox_maps=" \
      "relay_domains=regexp:/etc/postfix/sink/domains.regexp" \
      "relay_transport=smtp:${SINK_RELAY_NEXTHOP}" \
      "default_transport=smtp:${SINK_RELAY_NEXTHOP}"

    : > "$rewrite_map"
    if [ -n "$SINK_RECIPIENT_REWRITE" ]; then
      for rule in $(printf '%s' "$SINK_RECIPIENT_REWRITE" | tr ',' ' '); do
        from=${rule%%=*}
        to=${rule#*=}
        [ "$from" != "$rule" ] || die "SINK_RECIPIENT_REWRITE entries must be from.domain=to.domain"
        is_hostname "$from" && is_hostname "$to" \
          || die "SINK_RECIPIENT_REWRITE entries must be from.domain=to.domain"
        from_re=$(printf '%s' "$from" | tr 'A-Z' 'a-z' | sed 's/\./\\./g')
        to_lc=$(printf '%s' "$to" | tr 'A-Z' 'a-z')
        printf '/^(.+)@%s$/\t${1}@%s\n' "$from_re" "$to_lc" >> "$rewrite_map"
      done
    fi
    chmod 0644 "$rewrite_map"
    # smtp_generic_maps (one lookup per address in smtp(8), when relaying), not
    # recipient_canonical_maps: cleanup(8) applies canonical maps recursively until the result
    # is stable, so a swap such as a.test=b.test,b.test=a.test (the two-tenant loop test) never
    # converges and the message is refused ("unreasonable ... map nesting"). See
    # docs/deployment/mail-routing.md, deviations.
    postconf -e "smtp_generic_maps=regexp:${rewrite_map}"
    ;;
  *) die "SINK_MODE must be one of: store relay" ;;
esac

check_output=$(postfix check 2>&1) || {
  printf '%s\n' "$check_output" >&2
  die "postfix check failed"
}
if [ -n "$check_output" ]; then
  printf '%s\n' "$check_output" >&2
  die "postfix check reported warnings"
fi

exec postfix start-fg
