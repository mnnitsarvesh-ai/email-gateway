# Internal smarthost for transactional email (invitations, password reset, verification; later
# the notification service). Services submit to it without credentials on the private network;
# it relays to the upstream submission relay with SASL, pins the upstream certificate by
# fingerprint and never pipelines (the upstream mishandles RFC 2920 PIPELINING).
FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      postfix libsasl2-modules ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY main.cf /etc/postfix/main.cf
COPY entrypoint.sh /usr/local/bin/postfix-notify-entrypoint
RUN chmod 0755 /usr/local/bin/postfix-notify-entrypoint \
 && postconf -F '*/*/chroot = n' \
 && postconf -M 'postlog/unix-dgram=postlog unix-dgram n - n - 1 postlogd'

EXPOSE 25
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 CMD postfix status || exit 1
ENTRYPOINT ["/usr/local/bin/postfix-notify-entrypoint"]
