# Local-development Postfix MX. Production runs Postfix on EC2 ASGs with an EBS spool
# (see docs/architecture/overview.md); main.cf is shared.
FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      postfix ca-certificates ssl-cert \
 && rm -rf /var/lib/apt/lists/*

COPY main.cf /etc/postfix/main.cf
COPY entrypoint.sh /usr/local/bin/postfix-entrypoint
RUN chmod 0755 /usr/local/bin/postfix-entrypoint \
 # Run every service unchrooted inside the container (the container is the isolation boundary).
 && postconf -F '*/*/chroot = n' \
 # postlogd lets Postfix log to stdout without syslog.
 && postconf -M 'postlog/unix-dgram=postlog unix-dgram n - n - 1 postlogd'

EXPOSE 25
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 CMD postfix status || exit 1
ENTRYPOINT ["/usr/local/bin/postfix-entrypoint"]
