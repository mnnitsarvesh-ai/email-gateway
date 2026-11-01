#!/bin/sh
# Applies environment-specific settings, validates the configuration and runs Postfix in the
# foreground as PID 1's child so Docker/Kubernetes see its exit status.
set -eu

: "${POSTFIX_MYHOSTNAME:=mx.gateway.local}"
: "${POSTFIX_RELAY_DOMAINS:=gateway.test}"
# Until the Email Ingestion Service (LMTP) exists, accepted dev mail is discarded after the
# in-session checks. Set POSTFIX_RELAY_TRANSPORT=lmtp:inet:smtp-adapter:24 once it is built.
: "${POSTFIX_RELAY_TRANSPORT:=discard:local development sink}"
: "${POSTFIX_MYNETWORKS:=127.0.0.0/8}"
: "${POSTFIX_POLICY_SERVICE:=inet:smtp-adapter:10040}"
: "${POSTFIX_MILTER:=inet:rspamd:11332}"

postconf -e \
  "myhostname=${POSTFIX_MYHOSTNAME}" \
  "relay_domains=${POSTFIX_RELAY_DOMAINS}" \
  "relay_transport=${POSTFIX_RELAY_TRANSPORT}" \
  "mynetworks=${POSTFIX_MYNETWORKS}" \
  "smtpd_milters=${POSTFIX_MILTER}" \
  "smtpd_recipient_restrictions=reject_non_fqdn_recipient, reject_non_fqdn_sender, reject_unauth_destination, check_policy_service ${POSTFIX_POLICY_SERVICE}"

# Postfix needs the resolver config of the container for DNS lookups.
newaliases 2>/dev/null || true
postfix check
exec postfix start-fg
