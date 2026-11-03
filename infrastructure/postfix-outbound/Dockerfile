# Outbound MTA (step 2.2): submission 587, connector relay 25, reinjection 10026/10027.
# Production runs the same image on its own EC2 Auto Scaling Group with an EBS spool and static
# egress IPs (docs/deployment/smtp-gateway.md).
FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      postfix ca-certificates ssl-cert \
 && rm -rf /var/lib/apt/lists/*

COPY main.cf master.cf /etc/postfix/
COPY validate.sh /usr/local/lib/postfix-entrypoint/validate.sh
COPY entrypoint.sh /usr/local/bin/postfix-outbound-entrypoint
RUN chmod 0644 /etc/postfix/main.cf /etc/postfix/master.cf /usr/local/lib/postfix-entrypoint/validate.sh \
 && chmod 0755 /usr/local/bin/postfix-outbound-entrypoint \
 # The static transport table is rewritten at start; it must exist for the build-time check.
 && : > /etc/postfix/transport \
 && postconf -n >/dev/null

EXPOSE 25 587 10026 10027
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 CMD postfix status || exit 1
ENTRYPOINT ["/usr/local/bin/postfix-outbound-entrypoint"]
