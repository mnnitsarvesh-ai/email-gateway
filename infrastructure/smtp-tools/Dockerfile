# TEST-ONLY SMTP client toolbox (Compose profile smtp-test, step 2.2 §6): swaks, Postfix's
# smtp-source/smtp-sink, openssl, dig, nc. Postfix is installed only for those binaries and is
# never configured or started. Step 2.3 §6: socat (the reinject-forwarder service) and the same
# image runs the one-shot test-pki job (openssl).
FROM debian:bookworm-slim

RUN echo 'postfix postfix/main_mailer_type select No configuration' | debconf-set-selections \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      swaks libnet-ssleay-perl libio-socket-ssl-perl libauthen-sasl-perl \
      postfix openssl ca-certificates dnsutils netcat-openbsd socat \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -u 2001 -m -s /bin/sh tools

USER tools
WORKDIR /home/tools
CMD ["sleep", "infinity"]
