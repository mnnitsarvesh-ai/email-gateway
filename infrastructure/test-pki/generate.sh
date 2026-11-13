#!/bin/sh
# test-pki: TEST-ONLY certificate authority for the smtp-test profile (step 2.3 §6).
#
# One-shot and idempotent: creates, only if absent (or expiring within 7 days), a test CA and two
# leaf certificates in the volume mounted at $PKI_DIR (default /pki):
#
#   ca/ca.pem + hash links (openssl rehash)  CApath of postfix-outbound (POSTFIX_OUTBOUND_SMTP_TLS_CAPATH)
#   ca-private/ca.key                         CA key (0600), never mounted by anything else
#   m365/{cert,key}.pem                       SAN mail.protection.outlook.com, *.mail.protection.outlook.com
#   google/{cert,key}.pem                     SAN mx.google.com, aspmx.l.google.com, *.aspmx.l.google.com
#   url-test/{cert,key}.pem                   step 4.3 U19: every url-test corpus name + 203.0.113.10
#                                             (HTTPS of the url-test container; trusted by the URL
#                                             fetchers through URL_FETCH_CA_FILE=/pki/ca/ca.pem)
#   notify-relay-sink/{cert,key}.pem          step 6.2: SAN notify-relay.sink.test + 172.31.250.31
#                                             (STARTTLS of the submission relay notify-relay-sink)
#   webhook-receiver/{cert,key}.pem           step 6.2: SAN hooks.receiver.test, hooks2.receiver.test
#                                             + 203.0.113.20 (HTTPS of webhook-receiver; trusted by
#                                             the webhook-worker through WEBHOOK_EXTRA_CA_PATH)
#
# Idempotent per file: each leaf is created when its directory lacks a valid certificate signed
# by the current CA, so an existing volume gains new leaves without a new CA (and without
# re-issuing the leaves it already has). The containers that read the keys (Postfix of the sinks,
# url-test and webhook-receiver on node:22-alpine) run as root.
#
# The leaves mimic the real providers' certificate names, so postfix-outbound's `secure match=`
# policies for the Microsoft 365 and Google Workspace presets are verified against the same names
# as in production (docs/deployment/mail-routing.md, "Verified Postfix behaviour"). Keys are 0640
# (Postfix reads them as root before dropping privileges). Nothing here is ever committed
# (*.pem / *.key are git-ignored) and the CA is trusted only by the local postfix-outbound.
set -eu

PKI_DIR=${PKI_DIR:-/pki}
DAYS=${TEST_PKI_DAYS:-825}
umask 022

log() { echo "test-pki: $*"; }

valid_for_a_week() {
  [ -s "$1" ] && openssl x509 -in "$1" -noout -checkend 604800 >/dev/null 2>&1
}

install -d -m 0755 "$PKI_DIR/ca"
install -d -m 0700 "$PKI_DIR/ca-private"

ca_cert=$PKI_DIR/ca/ca.pem
ca_key=$PKI_DIR/ca-private/ca.key
regenerate_leaves=no

if valid_for_a_week "$ca_cert" && [ -s "$ca_key" ]; then
  log "CA present: $(openssl x509 -in "$ca_cert" -noout -subject)"
else
  log "creating test CA"
  rm -f "$PKI_DIR"/ca/*
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days "$DAYS" \
    -subj "/O=Email Gateway TEST ONLY/CN=Email Gateway Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -keyout "$ca_key" -out "$ca_cert" 2>/dev/null
  chmod 0600 "$ca_key"
  chmod 0644 "$ca_cert"
  regenerate_leaves=yes
fi

# leaf NAME CN SAN-LIST
leaf() {
  dir=$PKI_DIR/$1
  install -d -m 0755 "$dir"
  # A leaf created with a recorded SAN list (san.txt, since step 4.3) is re-issued when the list
  # changes; leaves without san.txt (m365, google from step 2.3) keep the old rule.
  san_changed=no
  if [ -f "$dir/san.txt" ] && [ "$(cat "$dir/san.txt")" != "$3" ]; then san_changed=yes; fi
  if [ "$regenerate_leaves" = no ] && [ "$san_changed" = no ] && valid_for_a_week "$dir/cert.pem" && [ -s "$dir/key.pem" ] \
    && openssl verify -CAfile "$ca_cert" "$dir/cert.pem" >/dev/null 2>&1; then
    log "$1 leaf present: $(openssl x509 -in "$dir/cert.pem" -noout -ext subjectAltName | tail -n 1 | sed 's/^ *//')"
    return 0
  fi
  log "creating $1 leaf ($3)"
  tmp=$(mktemp -d)
  openssl req -newkey rsa:2048 -nodes -sha256 -subj "/O=Email Gateway TEST ONLY/CN=$2" \
    -keyout "$tmp/key.pem" -out "$tmp/req.csr" 2>/dev/null
  cat > "$tmp/ext.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$3
authorityKeyIdentifier=keyid
EOF
  openssl x509 -req -in "$tmp/req.csr" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
    -CAserial "$PKI_DIR/ca-private/ca.srl" -days "$DAYS" -sha256 -extfile "$tmp/ext.cnf" \
    -out "$tmp/cert.pem" 2>/dev/null
  chmod 0640 "$tmp/key.pem"
  chmod 0644 "$tmp/cert.pem"
  mv "$tmp/key.pem" "$dir/key.pem"
  mv "$tmp/cert.pem" "$dir/cert.pem"
  if [ "${4:-}" = record-san ]; then printf '%s' "$3" > "$dir/san.txt"; fi
  rm -rf "$tmp"
}

leaf m365 mail.protection.outlook.com \
  "DNS:mail.protection.outlook.com,DNS:*.mail.protection.outlook.com"
leaf google mx.google.com \
  "DNS:mx.google.com,DNS:aspmx.l.google.com,DNS:*.aspmx.l.google.com"

# Step 4.3 U19: the url-test web server (TEST-ONLY corpus, all names under .test; the Cyrillic
# homoglyph exаmplebank.test is listed as its A-label xn--exmplebank-0qi.test).
URL_TEST_NAMES="clean-site.test www.clean-site.test short-link.test redirect-chain.test evil-site.test \
phish-login.test collector-site.test examplebank.test examp1ebank.test examplebank-login.test \
xn--exmplebank-0qi.test new-domain.test slow-site.test trickle-site.test huge-site.test \
many-headers.test gzip-bomb.test rdap.test bad-ip-host.test evil-dbl.test malware-dbl.test \
rebind.test url-test"
url_test_san=""
for name in $URL_TEST_NAMES; do url_test_san="${url_test_san:+$url_test_san,}DNS:$name"; done
leaf url-test url-test "$url_test_san,IP:203.0.113.10" record-san

# Step 6.2 §4.5: the authenticated submission relay of postfix-notify's alert path and the
# webhook test receiver (dns-sink zone receiver.test → 203.0.113.20).
leaf notify-relay-sink notify-relay.sink.test \
  "DNS:notify-relay.sink.test,IP:172.31.250.31" record-san
leaf webhook-receiver hooks.receiver.test \
  "DNS:hooks.receiver.test,DNS:hooks2.receiver.test,IP:203.0.113.20" record-san

# Hash links (<subject hash>.0) so OpenSSL finds the CA in a CApath directory.
openssl rehash "$PKI_DIR/ca"
log "done ($(ls "$PKI_DIR/ca" | tr '\n' ' '))"
