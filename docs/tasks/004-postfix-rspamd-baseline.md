# 004: Postfix inbound and outbound baseline config, Rspamd milter wiring, open-relay proof

Owner agent: smtp-infra-engineer
Depends on: 003
Status: draft
Branch: feat/004-postfix-rspamd-baseline
Phase: 0

**Why this is a separate task.** smtp-infra-engineer owns `postfix/` and the Rspamd milter config. devops-engineer owns the compose stack and the Postfix image (003). Splitting them keeps each agent within its ownership. Without this task, the local stack has an MTA with no proven relay restrictions.

## User story

Story: _to be written by product-owner_

As a platform operator, I want the local inbound and outbound Postfix instances configured to the ADR-020/021/022 mail path, with no open relay, so that every later pipeline task is built and tested against the real MTA behaviour.

## Acceptance criteria

AC-1 Given the rendered inbound and outbound configs, when `postfix check` runs inside each container, then it exits 0 with no warnings.
AC-2 Given inbound on `127.0.0.1:2525`, when swaks sends from `x@ext.test` to `victim@ext-other.test` (external domain), then RCPT returns `554 5.7.1` or `454 4.7.1` (relay denied) and no queue entry exists.
AC-3 Given the same attempt with `MAIL FROM` and `From:` set to `@tenant-a.test`, when sent to an external domain, then the reply is still `554 5.7.1`/`454 4.7.1`; spoofing a tenant sender grants no relay.
AC-4 Given an unknown recipient at `unknown@tenant-a.test`, when sent inbound, then RCPT returns `550 5.1.1` in-session.
AC-5 Given a known recipient (`user@tenant-a.test`, `tenant-b.test`) with the ingest service absent, when sent via swaks, then Postfix returns `250`, `postqueue -j` shows the message deferred with an LMTP connection error to `ingest-service:24`, and it is not delivered or bounced by any other transport.
AC-6 Given a message with header `X-ESG-Tenant: tenant-b` sent to `tenant-a.test`, when queued, then the stored message has no `X-ESG-*` header; likewise an inbound `X-Spam-Status`/`X-Spamd-Result` header is removed by Rspamd `milter_headers`. Recipient routing used only the envelope domain.
AC-7 Given `rspamd` stopped, when swaks sends to a valid recipient, then the reply is `451` or another `4xx` (`milter_default_action = tempfail`) and nothing is queued; after restart, the same send returns `250`.
AC-8 Given the inbound EHLO, when swaks `--tls` is used, then STARTTLS is advertised and the session completes; `Received:` contains the TLS line (`smtpd_tls_received_header`).
AC-9 Given a message over `message_size_limit` (assumes default for NEEDS SARVESH #1: 35 MB), when sent, then it is rejected `552 5.3.4` in-session; one just under the limit gets `250`. EHLO advertises `SIZE` equal to the limit.
AC-10 Given the Rspamd config, when a clean test message is sent, then it is accepted with Rspamd headers added, and `actions.conf` has reject/greylist disabled (a spam-looking GTUBE test message is still `250` in Phase 0).
AC-11 Given `main.cf`, when `postconf` is read, then `enable_long_queue_ids = yes`, `smtputf8_enable = no` (assumes default for NEEDS SARVESH #2), and `smtpd_relay_restrictions` ends in `reject_unauth_destination`.
AC-12 Given a container on the default compose network (not `reinject`), when it connects to `postfix-outbound:10025` and sends mail, then the RCPT is rejected (`554 5.7.1`/`4xx` denied); the host cannot reach 10025 at all (connection refused, not published).
AC-13 Given a `swaks` container on the `reinject` network, when it sends to `user@tenant-a.test` on `10025`, then Postfix accepts and the message arrives in `mailpit-tenant` within 10 s; mail to `user@other.example` arrives in `mailpit-ext`, and no packet leaves for the real internet (default transport is `mailpit-ext`).
AC-14 Given the reinjection listener, when a message with spam- or malware-like content (EICAR via runtime assembly) is sent, then it is not rejected on content and no milter or content filter is invoked.
AC-15 Given `postfix/test/open-relay.sh`, `inbound-basics.sh` and `outbound-basics.sh`, when run with `--profile mta` up, then each exits 0 when all cases pass and non-zero if any case fails (verified by temporarily breaking `reject_unauth_destination` in a test copy).
AC-16 Given the repo, when scanned, then no TLS private key is committed, and `outbound` has `maximal_queue_lifetime = 5d` and `bounce_queue_lifetime = 5d`.

### Open questions for Sarvesh

- NEEDS SARVESH #1 and #2 defaults (35 MB, SMTPUTF8 off) are assumed in AC-9 and AC-11.

## Out of scope

- `policy-adapter` and `check_policy_service`. They arrive in Phase 1 and replace the static maps below.
- Tenant connectors for outbound mail (IP, SMTP AUTH or client cert) and DKIM signing. Both are Phase 3.
- Rspamd reject thresholds. In Phase 0 and Phase 1 the milter adds headers only. Rejects are switched on in Phase 2.
- Production TLS certificates, MTA-STS and DANE. Production Postfix on the EC2 ASG (Phase 2 infra track).

## Design notes

### Files

```
postfix/
  inbound/main.cf.tmpl  master.cf.tmpl  header_checks  relay_domains.local  relay_recipients.local
  outbound/main.cf.tmpl master.cf.tmpl  transport.local
  test/open-relay.sh     test/inbound-basics.sh   test/outbound-basics.sh   test/lib.sh
rspamd/
  local.d/worker-proxy.inc      milter mode on 11332, self_scan
  local.d/actions.conf          Phase 0: reject/greylist disabled, add_header only
  local.d/milter_headers.conf   remove our internal headers on input (see header trust below)
  local.d/options.inc           DNSBL/RBL lookups disabled locally (licensing, see human-tasks)
```

### Inbound Postfix (MX listener)

- `mynetworks = 127.0.0.0/8`.
- `smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination`.
- `smtpd_recipient_restrictions = reject_unlisted_recipient, permit`.
- `relay_domains` and `relay_recipient_maps` come from the static `*.local` lmdb maps for the seeded test domains (`tenant-a.test`, `tenant-b.test`). An unknown recipient gets `550 5.1.1`. The lookup is by **envelope recipient domain**, never by header.
- `relay_transport = lmtp:inet:ingest-service:24`. Set `lmtp_destination_recipient_limit` to a value backend-engineer agrees, so one LMTP transaction doesn't mix tenants. *Recommendation:* 1 for Phase 1, revisited for throughput in Phase 6.
- Milter: `smtpd_milters = inet:rspamd:11332`, `milter_protocol = 6`, **`milter_default_action = tempfail`**, so a Rspamd outage gives `4xx` and never an accept.
- `enable_long_queue_ids = yes`. The queue id feeds ingest dedupe (ADR-021).
- `message_size_limit`: see NEEDS SARVESH. `smtpd_tls_security_level = may`, using the runtime self-signed cert from 003. `smtpd_tls_received_header = yes`.
- **Header trust.** `header_checks` strips any incoming `X-ESG-*` header, and Rspamd `milter_headers` removes inbound `X-Spamd-*`/`X-Spam-*`. That way a sender can't plant a verdict header that a downstream server or the portal might trust.
- Disable `smtputf8_enable` until it has been tested; decide this in Phase 1.

### Outbound Postfix (reinjection)

- Listener `10025` is for `delivery-service` reinjection only. `smtpd_client_restrictions = permit_mynetworks, reject`.
- **Docker NAT trap.** A connection from the host through a published port arrives from the bridge gateway IP, which sits *inside* the compose subnet. So `mynetworks = <compose CIDR>` would trust any process on the laptop. The fix:
  - Put reinjection on a dedicated compose network, `reinject`, with a fixed small subnet.
  - Set `mynetworks` to that subnet **minus its gateway**: list the allowed container IPs or a `/29` that excludes `.1`.
  - **Don't publish 10025 to the host.**
  - The e2e harness reinjects from a `swaks` container attached to `reinject` (agree the details with devops-engineer, who owns `compose.yaml`).
- No content filter or milter on reinjection, so mail isn't scanned twice.
- `transport_maps` (lmdb, `transport.local`): `tenant-a.test` and `tenant-b.test` → `smtp:[mailpit-tenant]:1025`. `default_transport` → `smtp:[mailpit-ext]:1025`. Locally, mail **never** leaves for the real internet. From Phase 1, per-tenant routing comes from `mail_servers` through a socketmap or lookup that smtp-infra-engineer and backend-engineer design together.
- `notify_classes` minimal. `maximal_queue_lifetime = 5d` and `bounce_queue_lifetime = 5d` (ADR-022, tune later).
- Delivery DSN wording must not leak scan details (ADR-022). In Phase 0 there is no scan detail to leak; just note this.

### Tests

These are scripts in `postfix/test/` so qa-engineer can rerun them. Each uses `swaks` against `127.0.0.1` with `--profile mta` up, and asserts SMTP codes. The script exits non-zero if any case fails.

`open-relay.sh`:
- External sender to an external domain on inbound: relay denied (`554 5.7.1` or `454 4.7.1`).
- External sender to an unknown recipient at `tenant-a.test`: `550 5.1.1` in-session.
- Connecting to outbound `10025` from a container on the default network (not `reinject`): rejected. The gateway IP of `reinject` is not in `mynetworks`.
- Inbound with `MAIL FROM` and `From:` set to a tenant domain, sent to an external domain: still denied. Sender spoofing doesn't grant relay.

`inbound-basics.sh`:
- A valid recipient gets `250` from Postfix, and the message sits **deferred** with an LMTP connection error while ingest is absent.
- STARTTLS is offered.
- With Rspamd stopped, the reply is `451`/`4xx`.

`outbound-basics.sh`:
- Reinjection on `10025` to `user@tenant-a.test` reaches `mailpit-tenant`.

`postfix check` runs on the rendered configs inside the container as part of the test.

## Hard rules at risk

- **Open relay (smtp-infra non-negotiable).** `reject_unauth_destination`, a localhost-only `mynetworks`, the listener split, and swaks proof.
- **4 (tenant not from headers).** Relay and recipient decisions use only the envelope recipient domain and the static maps. Internal `X-ESG-*` headers are stripped on input.
- **1 (250 only after persist).** Postfix's own `250` at the SMTP edge is fine, because the message is in the EBS spool. The rule applies to ingest's LMTP `250`. LMTP must not fall back to any other transport when ingest is down. Mail stays deferred.
- **Only in-session components reject.** Outbound reinjection never rejects or bounces on content.
- **9.** No private keys committed. The TLS cert is generated at container start.

## NEEDS SARVESH

1. **Maximum message size** (`message_size_limit`), which is also the hard ceiling for ingest and the scanners. Options: 25 MB, 35 MB or 50 MB. *Recommendation:* 35 MB. That fits Microsoft 365's default receive limit of about 36 MB once MIME overhead is counted, and keeps scanner memory bounded. Per-tenant lower limits can come later.
2. **SMTPUTF8 / EAI (internationalised addresses) support.** *Recommendation:* off in Phase 0–1, decided in Phase 3. Indian-language address uptake is still low, and it touches address normalisation in `domains` and `users`.
