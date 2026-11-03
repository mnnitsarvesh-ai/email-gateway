# Inbound MX (step 2.2). Production runs the same image on an EC2 Auto Scaling Group with an EBS
# spool (docs/deployment/smtp-gateway.md); main.cf and master.cf are shared.
FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      postfix ca-certificates ssl-cert \
 && rm -rf /var/lib/apt/lists/*

COPY main.cf master.cf /etc/postfix/
COPY validate.sh /usr/local/lib/postfix-entrypoint/validate.sh
COPY entrypoint.sh /usr/local/bin/postfix-entrypoint
RUN chmod 0644 /etc/postfix/main.cf /etc/postfix/master.cf /usr/local/lib/postfix-entrypoint/validate.sh \
 && chmod 0755 /usr/local/bin/postfix-entrypoint \
 # Fail the build on a configuration error rather than at container start.
 && postconf -n >/dev/null

EXPOSE 25
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 CMD postfix status || exit 1
ENTRYPOINT ["/usr/local/bin/postfix-entrypoint"]
