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
  if [ "$regenerate_leaves" = no ] && valid_for_a_week "$dir/cert.pem" && [ -s "$dir/key.pem" ] \
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
  rm -rf "$tmp"
}

leaf m365 mail.protection.outlook.com \
  "DNS:mail.protection.outlook.com,DNS:*.mail.protection.outlook.com"
leaf google mx.google.com \
  "DNS:mx.google.com,DNS:aspmx.l.google.com,DNS:*.aspmx.l.google.com"

# Hash links (<subject hash>.0) so OpenSSL finds the CA in a CApath directory.
openssl rehash "$PKI_DIR/ca"
log "done ($(ls "$PKI_DIR/ca" | tr '\n' ' '))"
