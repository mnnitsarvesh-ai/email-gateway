# Runbook: SMTP TLS certificate rotation

For platform operators. Rotating the server certificates of `postfix` (inbound 25) and `postfix-outbound` (587, 25). Configuration: `POSTFIX_TLS_CERT_PATH`/`POSTFIX_TLS_KEY_PATH` and `POSTFIX_OUTBOUND_TLS_CERT_PATH`/`POSTFIX_OUTBOUND_TLS_KEY_PATH` ([deployment](../deployment/smtp-gateway.md#tls-certificates)).

## Detection

- Expiry monitoring (at least 21 days ahead): `echo | openssl s_client -connect <mx host>:25 -starttls smtp 2>/dev/null | openssl x509 -noout -enddate` (and `:587`).
- Senders' logs or TLS-RPT reports with certificate errors; `smtpd_tls_loglevel = 1` logs handshake failures (`SSL_accept error`).

## Impact

Inbound and outbound port 25 are opportunistic: an expired or mismatched certificate is accepted by most MTAs but fails strict senders (MTA-STS/DANE senders defer). Submission 587 requires TLS: tenant servers that verify the certificate stop submitting.

## Procedure

1. Obtain the new certificate (public CA, SAN = every MX / submission name, e.g. `mx1.…`, `mx2.…`, `smtp.…`). ACM cannot export private keys; store the chain (leaf first) and key in Secrets Manager or an encrypted S3 object.
2. Validate before installing:
   ```bash
   openssl x509 -in new-chain.pem -noout -subject -enddate -ext subjectAltName
   diff <(openssl x509 -in new-chain.pem -noout -pubkey) <(openssl pkey -in new.key -pubout)   # must be empty
   ```
3. Install on each instance (one AZ at a time): write the files next to the current ones with a new name (key mode 0600, owner root), then switch the path: update `POSTFIX_TLS_CERT_PATH`/`_KEY_PATH` (or `POSTFIX_OUTBOUND_TLS_*`) and recreate the container — the entrypoint refuses to start on an unreadable file, so a typo is caught before Postfix starts. When the paths stay the same (files replaced in place, e.g. a mounted directory), run `postfix reload` instead: new smtpd processes pick up the new files; sessions in progress keep the old certificate until they end.
4. Locally (Compose): mount the files read-only into the container (for example an override file adding `./certs:/etc/postfix/certs:ro`) and set the variables in `.env`, then `docker compose up -d postfix postfix-outbound`.

## Verification

```bash
echo | openssl s_client -connect <host>:25 -starttls smtp -servername <host> 2>/dev/null | openssl x509 -noout -subject -enddate
echo | openssl s_client -connect <host>:587 -starttls smtp -servername <host> 2>/dev/null | openssl x509 -noout -subject -enddate
docker compose exec postfix postfix check   # prints nothing
```

Check `Protocol version: TLSv1.2` or higher (`openssl s_client -brief`), and that a test submission with a verifying client succeeds.

## Never

- Lower `smtpd_tls_protocols`/`smtpd_tls_mandatory_protocols` below TLSv1.2 or set `smtpd_tls_security_level = none` on 587 to work around a client.
- Put the private key in the repository, an image layer, a Compose file or an environment variable.
- Rotate all instances at once without verifying one first.
