# TEST-ONLY mail sink (Compose profile smtp-test). See main.cf; identity, TLS certificate and
# store/relay/submission mode are rendered from the environment by entrypoint.sh (step 2.3;
# submission mode: step 6.2, the authenticated relay notify-relay-sink). sasl2-bin
# (saslpasswd2) and libsasl2-modules (PLAIN/LOGIN) serve only the submission mode; the other
# modes never enable SASL.
FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      postfix ca-certificates ssl-cert sasl2-bin libsasl2-modules \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 2000 sink \
 && useradd -u 2000 -g 2000 -d /var/mail/sink -M -s /usr/sbin/nologin sink \
 && install -d -o sink -g sink -m 0750 /var/mail/sink

COPY main.cf /etc/postfix/main.cf
COPY domains.regexp mailboxes.regexp recipients.regexp /etc/postfix/sink/
COPY smtpd-sasl.conf /etc/postfix/sasl/smtpd.conf
COPY sink-deliver /usr/local/bin/sink-deliver
COPY entrypoint.sh /usr/local/bin/mail-sink-entrypoint
RUN chmod 0644 /etc/postfix/main.cf /etc/postfix/sink/* /etc/postfix/sasl/smtpd.conf \
 && chmod 0755 /usr/local/bin/sink-deliver /usr/local/bin/mail-sink-entrypoint \
 && postconf -F '*/*/chroot = n' \
 && postconf -M 'postlog/unix-dgram=postlog unix-dgram n - n - 1 postlogd' \
 && postconf -M 'sink/unix=sink unix - n n - - pipe flags=DRhu user=sink argv=/usr/local/bin/sink-deliver ${domain} ${user}' \
 && postfix check

EXPOSE 25 587
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 CMD postfix status || exit 1
ENTRYPOINT ["/usr/local/bin/mail-sink-entrypoint"]
