# Mail routing and delivery tracking (step 2.3)

How approved mail leaves the gateway: the reinjection listeners of `postfix-outbound`, the routing per direction, the delivery log that the delivery-worker turns into per-recipient status, the retry schedule, the egress rules, the test profile, and the Postfix 3.7 behaviour this relies on (verified locally, with raw log lines). Design and decision ids (R*n*): [docs/plan/steps/05-routing.md](../plan/steps/05-routing.md). Decision record: [ADR-0021](../architecture/adr/0021-mail-routing-and-delivery-status.md). The step 2.2 mail plane (listeners, relay control, DKIM, bounce notices) is in [smtp-gateway.md](smtp-gateway.md). Customer-facing destination setup: [docs/domains/destination-servers.md](../domains/destination-servers.md). Runbooks: [delivery status log](../runbooks/delivery-status-log.md), [deferred delivery backlog](../runbooks/delivery-deferred-backlog.md), [SMTP queue backlog](../runbooks/smtp-queue-backlog.md).

## Routing paths

```
 delivery-worker ──10026 (reinject-inbound)──▶ postfix-outbound ──transport_maps──▶ tenant destination servers
                 ──10027 (reinject-outbound)─▶ postfix-outbound ──content_filter=smtp: (MX of the recipient domain)──▶ Internet
                                                 │ (10027 only) milter ──▶ rspamd-outbound (DKIM)
                                                 └─ maillog_file /var/log/postfix-outbound/maillog ──read-only──▶ delivery-worker status tailer
 postfix-outbound DSNs and postmaster copies ──transport_maps──▶ sender's tenant destination / LMTP 10052 bounce handler
```

| Direction  | Listener | Envelope sender      | `RCPT … NOTIFY=` | Next hop                                                                                                                                                           | DSN on failure                                                         |
| ---------- | -------- | -------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| `inbound`  | `10026`  | original (external)  | `NEVER`          | `transport_maps`: static bounce-domain entry, then the adapter's `transport` socketmap → the organization's destination servers (`smtp:[h1]:25,[h2]:25`, failover) | none to the sender; a postmaster copy still goes to the bounce handler |
| `internal` | `10026`  | original (`O`'s own) | `FAILURE,DELAY`  | as inbound                                                                                                                                                         | Postfix DSN to the sender, plus the postmaster copy                    |
| `outbound` | `10027`  | original (`O`'s own) | `FAILURE,DELAY`  | `-o content_filter=smtp:` (empty next hop): MX lookup of the recipient domain, **`transport_maps` never consulted**; DKIM-signed by rspamd-outbound                | Postfix DSN to the sender, plus the postmaster copy                    |

- **No cross-tenant shortcut** (R1, R4): a recipient in another tenant's domain is reinjected on 10027 and reaches that tenant through its **public MX** (normally this gateway's inbound MX, so the other tenant gets its full inbound path). Verified (V1).
- DSNs and postmaster copies are new messages without a content filter, so they route through `transport_maps` (the sender's tenant destination; the bounce domain → LMTP 10052), as in step 2.2.
- A tenant domain without an enabled destination (or with only refused hosts) gets `retry:4.4.1 Destination not configured` from the `transport` map. On **10026 this is refused at RCPT** (`450 4.4.1 … Destination not configured`, smtpd's unlisted-recipient check resolves the address through the same map); only mail that was already queued when the destination disappeared is logged by `postfix/error` as `status=deferred (Destination not configured)` (V5).
- Per-destination concurrency and politeness are Postfix's defaults: `smtp_destination_concurrency_limit = 20`, `smtp_destination_rate_delay = 0`. Outbound rate limits per tenant and destination domain are applied by the delivery-worker before 10027 (R11).

## Reinjection session contract (R8, verified)

The delivery-worker speaks plaintext SMTP on the internal network:

```
EHLO delivery.gateway.local                       (DELIVERY_REINJECT_HELO; XFORWARD must be advertised)
XFORWARD NAME=<client name> ADDR=<client ip> HELO=<client helo> PROTO=ESMTP   ([UNAVAILABLE] when unknown)
XFORWARD IDENT=dw1-<32 hex> SOURCE=REMOTE          (the reinjection token)
MAIL FROM:<sender> SIZE=<n> RET=HDRS ENVID=dw1-<32 hex>
RCPT TO:<rcpt> NOTIFY=NEVER|FAILURE,DELAY ORCPT=rfc822;<xtext rcpt>
DATA … X-Gateway-Trace: … + the stored EML …
```

- `postfix-outbound` advertises `250-XFORWARD NAME ADDR PROTO HELO SOURCE PORT IDENT` to clients in `$reinject_networks` (`smtpd_authorized_xforward_hosts`), plus `DSN`, `SMTPUTF8`, `8BITMIME`, `CHUNKING`, `PIPELINING`.
- The token is logged as `orig_queue_id=` on the `client=` line of `postfix/reinject-inbound/smtpd` or `postfix/reinject-outbound/smtpd`, the binding of Postfix's queue id to the reinjection (V4).
- The forwarded `ADDR` does **not** change `permit_mynetworks`: access control uses the real peer (the worker, or the `reinject-forwarder` locally). No fallback needed (V4).
- `ENVID` comes back as `Original-Envelope-Id:` in the sender DSN and in the postmaster copy (V4).
- **The `Received:` header of this hop names the real peer, not the XFORWARD client** (deviation from R8/R10, V4). With `-o smtpd_peername_lookup=no` on both listeners it reads `Received: from delivery.gateway.local (unknown [<worker ip>]) by out.gateway.local (Postfix) with ESMTP id <QID>; <date>`, so no internal host name appears in delivered mail. The original client stays recorded by the inbound MX's own `Received:` (inbound mail) and the submission hop's `Received:` (outbound mail), which the worker never edits.

## Delivery log (R9)

| Item          | Value                                                                                                                                                                                                                                          |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| File          | `maillog_file = /var/log/postfix-outbound/maillog` (written by `postlogd` only)                                                                                                                                                                |
| Compose       | bind mount `${POSTFIX_OUTBOUND_LOG_DIR:-./.local/postfix-outbound-log}` (git-ignored `.local/`); the delivery-worker container mounts the same directory **read-only**; a worker on the host reads `../../.local/postfix-outbound-log/maillog` |
| Permissions   | directory 0755, file 0644 (the entrypoint creates both; after rotation the compressor wrapper restores 0644, see below). Readers never write                                                                                                   |
| `docker logs` | the entrypoint mirrors new lines to stdout with `tail -n0 -F` (follows the name across rotations), so `docker compose logs postfix-outbound` and the step 2.2 stack tests keep working                                                         |
| Format        | `MMM DD HH:MM:SS out postfix/<service>[pid]: <text>`: no year, no microseconds, day zero-padded (`Nov 03`). The parser infers the year from the current UTC date (December/January boundary)                                                   |
| Noise         | the health check (`postfix status`) logs `postfix/postfix-script[…]: the Postfix mail system is running: PID: 1` every 10 s; TLS, `connect from`/`disconnect from` and `cleanup … message-id=` lines are ignored by the parser                 |

### Rotation

`docker compose exec postfix-outbound postfix logrotate` (production: a daily systemd timer or cron job on each postfix-outbound host, `docker exec <container> postfix logrotate`). Verified behaviour (V6):

1. `mv maillog maillog.<YYYYMMDD-HHMMSS>` (same inode, `maillog_file_rotate_suffix = %Y%m%d-%H%M%S`), then `kill -HUP` master (`postfix/master[1]: reload -- version 3.7.11, …` is the last line of the old file), postlogd reopens and **creates a new file with mode 0600**.
2. After one second the compressor runs: `maillog_file_compressor = /usr/local/lib/postfix-entrypoint/maillog-compress` makes the new file 0644 (append-open, never truncating) and then `gzip`s the rotated file, which removes the uncompressed name. Postfix 3.7 has no setting for the file mode; without the wrapper a non-root, read-only reader (the worker container runs as `node`) would get `EACCES` until the next container start.
3. A tailer that **keeps its descriptor open** still reads the rest of the old file after the rename and after the gzip unlink (verified with a probe holding the descriptor: it read the `reload` line from the old inode, saw the path's device/inode change, drained, then switched to the new file at offset 0). It must follow by file identity (device + inode), treat a short `ENOENT`/`EACCES` on the path as "not yet", and drain the old descriptor before switching (R9). A tailer that was **down** across a rotation finds the unread tail only in `maillog.<suffix>.gz`; those signals are then covered by the bounce notices and the stale→`unknown` reconciler (runbook [delivery-status-log.md](../runbooks/delivery-status-log.md)).

Retention: rotated `maillog.*.gz` files are never deleted by Postfix. Keep at least 7 days (`find /var/log/postfix-outbound -name 'maillog.*.gz' -mtime +7 -delete` from the same timer). Size: in the local runs about 1 KB of log per delivered recipient, including the TLS and connection lines (an estimate; measure on real traffic).

### Production status reader (sidecar)

The log lives on each postfix-outbound EC2 instance (outbound ASG, [smtp-gateway.md](smtp-gateway.md#outbound-asg)). Each instance therefore runs **the same delivery-worker image** as a sidecar container with only the log role:

```
DELIVERY_STATUS_LOG_ENABLED=true
DELIVERY_APPROVALS_ENABLED=false
DELIVERY_REINJECTION_ENABLED=false
DELIVERY_STATUS_LOG_PATH=/var/log/postfix-outbound/maillog      # host directory mounted read-only
DELIVERY_STATUS_LOG_SOURCE_ID=<this instance's POSTFIX_OUTBOUND_MYHOSTNAME or instance id>  # unique per host
```

plus the writer `DATABASE_URL`, `GATEWAY_TRACE_*` and the common keys. One reader per source id (`GET_LOCK('dw:postfix-log:<source id>')`), cursor in `stream_cursors`. Reinjection and approval replicas (Kubernetes) run with the log role off. The sidecar's security group needs egress only to MySQL (writer) and the metrics scrape ingress (3040). Drain on scale-in: stop Postfix first, let the sidecar reach the end of the file (`delivery_status_log_lag_seconds` ≈ 0), then stop the sidecar (lifecycle hook, [smtp-gateway.md](smtp-gateway.md#drain-and-instance-refresh)).

## Egress security groups (R3)

Destination host names are checked by rules at write and at map time (no IP literals in private, loopback, link-local, CGNAT, documentation or metadata ranges, no single-label or internal-suffix names, no gateway hosts), but **resolved addresses are not checked** (DNS can change; rebinding). Ports are restricted in the application too (review fix): a custom destination may only use `ROUTING_ALLOWED_DESTINATION_PORTS` (default `25,587,2525`), and the gateway's internal listener and data-service ports (10024–10027, 10040–10042, 10050–10052, 11332–11334, 53, 3306, 3310, 5672, 6379, 9000, 9001, 15672) are refused at write and on every transport answer even if an operator lists them. The network is the second, independent control, and it must cover **every port**, not only 25:

| Security group / rule                     | Allowed                                                                                                                                                                                                                                                                       |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Egress `sg-postfix-outbound` (delivery)   | TCP on the allowed destination ports (25, 587, 2525 by default) to `0.0.0.0/0` and `::/0` **except** the private and special ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `fc00::/7`, `fe80::/10`, the VPC CIDR |
| Egress `sg-postfix-outbound` (internal)   | only the explicit internal next hops: smtp-adapter (10040, 10041, 10042, 10051, 10052), rspamd-outbound (11332), the VPC resolver (53), and for dedicated deployments the customer's private destination ranges (with `ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS=true`)           |
| Ingress `sg-postfix-outbound` 10026/10027 | from `sg-delivery-worker` only                                                                                                                                                                                                                                                |

AWS security groups have no deny rules, and the internal rule above already opens the internal listener ports to the same process that delivers tenant-chosen destinations. So the delivery path must be separated from the internal next hops, for **all ports**:

- Preferred: postfix-outbound delivers through a **dedicated delivery network interface / subnet** whose network ACL denies **all TCP** to the private and special ranges and the VPC CIDR (any port), then allows only the allowed destination ports to `0.0.0.0/0`; the internal next hops (smtp-adapter, rspamd-outbound, the resolver) are reached over a separate interface or via their own subnet routes that the delivery interface cannot use.
- Alternatively an egress firewall (AWS Network Firewall) in front of the NAT/EIP path with a stateful rule set that drops every flow from the postfix-outbound delivery addresses to the private ranges except the explicit internal next-hop address:port pairs, which only the content-filter and LMTP transports use.
- A network ACL that only says "deny 25 to the private ranges" is **not** sufficient: a tenant-controlled name that resolves to a VPC address with a non-25 port would otherwise reach an internal listener (the application port rules above close this too, as defence in depth).

Effect: a destination name that resolves to an internal address (for example a customer entering an internal hostname that resolves to `10.x`) times out (`deferred`, error class `connect`) instead of reaching an internal service. A name that resolves to the gateway's own MX is caught by the trace loop check at ingestion (R10).

### Shared destination servers and TLS policy (R2, review fix)

Postfix looks up `smtp_tls_policy_maps` per next hop (`[host]:port`), with no tenant context, so every tenant that uses the same custom server shares one TLS answer. The api therefore refuses (`422`, reason `destination_tls_conflict`) a custom `host:port` that another organization already uses with a different TLS mode (or, for `verify`, a different `match=` list), and refuses custom servers on a provider preset's hosts (`host_reserved_for_provider`; those carry the preset's fixed policy). A tenant can use another tenant's server only with exactly that server's policy, so it can neither make the answer stricter (denial of delivery) nor weaker (downgrade). Changing the policy of a server shared by several organizations is an operator task. Rows written around the api (direct SQL) that disagree are still answered with the strictest mode, never a weaker one, and the adapter logs `destinations of several organizations disagree on the TLS policy of a shared next hop` with the organization ids.

## Retry schedule (R4)

Postfix owns every retry to a remote server (ADR-0006); both instances render these from the environment:

| Setting                                                                               | Production | Test profile (local `.env`, CI) |
| ------------------------------------------------------------------------------------- | ---------- | ------------------------------- |
| `minimal_backoff_time` (`POSTFIX_MINIMAL_BACKOFF_TIME`)                               | `300s`     | `10s`                           |
| `maximal_backoff_time` (`POSTFIX_MAXIMAL_BACKOFF_TIME`)                               | `4000s`    | `60s`                           |
| `queue_run_delay` (`POSTFIX_QUEUE_RUN_DELAY`)                                         | `300s`     | `10s`                           |
| `maximal_queue_lifetime` = `bounce_queue_lifetime` (`POSTFIX_MAXIMAL_QUEUE_LIFETIME`) | `5d`       | `5d`                            |
| `delay_warning_time` (`POSTFIX_DELAY_WARNING_TIME`, outbound)                         | `4h`       | `4h`                            |
| `smtp_connect_timeout` (`POSTFIX_OUTBOUND_SMTP_CONNECT_TIMEOUT`)                      | `30s`      | `5s`                            |

A deferred message waits at least the minimal backoff; each further failure doubles its wait up to the maximal backoff, rounded up to the next deferred-queue scan (`queue_run_delay`). Production: retries after about **5, 10, 20, 40, 66, 66, … minutes** (roughly 110 attempts in 5 days). Test profile: about 10, 20, 40, 60, 60 … seconds; observed in V5: attempts at 0, +16 s, +36 s, +76 s. After the lifetime the message **expires**: DSN to the sender when NOTIFY includes FAILURE (internal, outbound), none for inbound (`NOTIFY=NEVER`), plus a postmaster copy. `delay_warning_time` sends one delay DSN (NOTIFY=DELAY) and a postmaster delay copy. Nothing in code depends on these values.

## Environment

All keys are in `.env.example`, section `Mail routing and delivery (step 2.3)`, with comments; the table in design §5 lists the defaults and the local values. Infrastructure keys:

| Key                                                                                                                   | Read by                        | Notes                                                                                                                                                                                                                                        |
| --------------------------------------------------------------------------------------------------------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POSTFIX_OUTBOUND_LOG_DIR`                                                                                            | Compose                        | Host directory of the delivery log (`./.local/postfix-outbound-log`). Bind-mounted read-write into postfix-outbound and read-only into the delivery-worker                                                                                   |
| `POSTFIX_OUTBOUND_SMTP_CONNECT_TIMEOUT`                                                                               | postfix-outbound               | Postfix time value (validated). `30s`; test profile `5s`                                                                                                                                                                                     |
| `POSTFIX_OUTBOUND_SMTP_TLS_CAPATH`                                                                                    | postfix-outbound               | Extra hashed CA directory (`smtp_tls_CApath`); empty = not set, the system bundle (`smtp_tls_CAfile`) always applies. Absolute path, safe characters (validated); a missing directory is a warning, not fatal (the test CA may appear later) |
| `POSTFIX_MINIMAL_BACKOFF_TIME`, `…_MAXIMAL_BACKOFF_TIME`, `POSTFIX_QUEUE_RUN_DELAY`                                   | both Postfix instances         | see the retry table                                                                                                                                                                                                                          |
| `REINJECT_INBOUND_HOST_PORT`, `REINJECT_OUTBOUND_HOST_PORT`                                                           | Compose (`reinject-forwarder`) | `2626`, `2627` on 127.0.0.1, smtp-test profile only                                                                                                                                                                                          |
| `RELAY_SINK_RECIPIENT_REWRITE`                                                                                        | Compose (`relay-sink`)         | Test only, empty by default; the loop stack tests set it when they recreate `relay-sink`                                                                                                                                                     |
| `DELIVERY_*`, `ROUTING_MAX_*`, `GATEWAY_TRACE_*`, `INGEST_HEADER_MAX_BYTES`, `POSTFIX_OUTBOUND_MYHOSTNAME`            | delivery-worker                | Compose passes them; the container gets `DELIVERY_REINJECT_HOST=postfix-outbound`, ports `10026`/`10027` and `DELIVERY_STATUS_LOG_PATH=/var/log/postfix-outbound/maillog` (fixed, overriding the host values of the local `.env`)            |
| `ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS`, `ROUTING_DENIED_DESTINATION_SUFFIXES`, `ROUTING_MAX_DESTINATIONS_PER_DOMAIN` | api, smtp-adapter              | destination host rules (R3)                                                                                                                                                                                                                  |
| `DELIVERY_DEV_PASSTHROUGH_ENABLED`                                                                                    | delivery-worker                | **Development only**: delivers mail without scanning or policy; refused unless `APP_ENV` is `local` or `ci`. Compose default `false`; this repository's local `.env` sets `true`                                                             |

Existing `.env` files: append the section from `.env.example` (no secrets in it) and, for the test profile, use the local values of design §5 (`DELIVERY_REINJECT_HOST=127.0.0.1`, ports `2626`/`2627`, `DELIVERY_STATUS_LOG_PATH=../../.local/postfix-outbound-log/maillog`, `POSTFIX_OUTBOUND_SMTP_TLS_CAPATH=/etc/postfix/test-ca/ca`, `POSTFIX_OUTBOUND_SMTP_CONNECT_TIMEOUT=5s`, backoff `10s`/`60s`/`10s`). Recreate both Postfix containers afterwards.

## Test profile (`smtp-test`, never deployed)

| Service              | Address (`mailtest`) | Role                                                                                                                                                                                                               |
| -------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `postfix` (default)  | `172.31.250.10`      | the gateway MX, also reachable as `gw-mx.sink.test` (cross-tenant and loop tests); no configuration change                                                                                                         |
| `mail-sink`          | `172.31.250.25`      | unchanged: every `*.test` domain into Maildirs, scripted `hard-bounce@`/`soft-bounce@`/`policy-block@`                                                                                                             |
| `sink-m365`          | `172.31.250.26`      | `*.mail.protection.outlook.com`, test-CA certificate with SAN `mail.protection.outlook.com`, `*.mail.protection.outlook.com`                                                                                       |
| `sink-google`        | `172.31.250.27`      | `aspmx.l`, `alt2`–`alt4.aspmx.l.google.com`, SAN `mx.google.com`, `aspmx.l.google.com`, `*.aspmx.l.google.com`                                                                                                     |
| `sink-google-alt`    | `172.31.250.28`      | `alt1.aspmx.l.google.com` (failover target), same certificate                                                                                                                                                      |
| `relay-sink`         | `172.31.250.29`      | `relay.sink.test`: `SINK_MODE=relay`, relays everything (also its own DSNs) to `[172.31.250.10]:25`, recipient domains rewritten by `RELAY_SINK_RECIPIENT_REWRITE`                                                 |
| `reinject-forwarder` | `172.31.250.30`      | `socat`: `127.0.0.1:2626` → `postfix-outbound:10026`, `127.0.0.1:2627` → `postfix-outbound:10027`, for a delivery-worker on the host                                                                               |
| `test-pki`           | none (one-shot)      | `infrastructure/test-pki/generate.sh` in volume `test-pki`: CA in `ca/` (hashed), CA key in `ca-private/` (0600), leaves in `m365/` and `google/` (key 0640); created only if absent or expiring within 7 days     |
| `dns-sink`           | `172.31.250.53`      | zones `sink.test` (+ `gw-mx`, `relay`, `*.gwtenant` → MX `gw-mx`), `mail.protection.outlook.com` (apex and `*` → .26), `aspmx.l.google.com` (apex, `alt2`–`alt4` → .27, `alt1` → .28); REFUSED for everything else |

- Dynamic addresses on `mailtest` come from `172.31.250.128/25` only (`ip_range`), gateway `172.31.250.1`, so a dynamic container can never take a fixed address. **Existing local stacks** created before step 2.3 must recreate the network once: `docker compose --profile smtp-test rm -sf postfix postfix-outbound smtp-tools mail-sink dns-sink`, `docker network rm email-gateway_mailtest`, then `docker compose --profile smtp-test up -d --wait`. If Compose recreated the network by itself, it reconnects running containers **without** their fixed addresses: `docker compose --profile smtp-test up -d --force-recreate --no-deps <every mailtest service>`.
- `postfix-outbound` mounts the `test-pki` volume read-only at `/etc/postfix/test-ca` and uses `POSTFIX_OUTBOUND_SMTP_TLS_CAPATH=/etc/postfix/test-ca/ca` (local `.env`); it depends on `test-pki` only when the profile is active (`required: false`). The test CA is trusted by nothing else.
- Images: build one at a time (`docker compose build postfix-outbound`, `docker compose --profile smtp-test build mail-sink`, `docker compose --profile smtp-test build smtp-tools`); the sinks, `test-pki` and `reinject-forwarder` reuse the `mail-sink` and `smtp-tools` images (`pull_policy: never`, no own build).
- `mail-sink` image environment: `SINK_HOSTNAME`, `SINK_TLS_CERT_PATH`/`SINK_TLS_KEY_PATH` (default snakeoil), `SINK_MODE=store|relay`, `SINK_RELAY_NEXTHOP`, `SINK_RECIPIENT_REWRITE` (`from.domain=to.domain,…`); with nothing set it behaves as in step 2.2. Store mode refuses relay settings.

## Verified Postfix behaviour

Run on 2026-11-03 on the local stack (Postfix 3.7.11, Debian bookworm), smtp-adapter on the host, fixtures created with SQL on the writer and removed afterwards. Sessions were sent with a raw SMTP client through `reinject-forwarder` (so the client is `172.31.250.30`) or injected inside postfix-outbound with `sendmail` and temporary static `texthash` maps (V2, V3; restored by recreating the container). Addresses are test fixtures; queue ids are exactly as Postfix printed them.

| #   | Question                                                   | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| --- | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| V1  | 10027 with `content_filter=smtp:` ignores `transport_maps` | **Pass.** Recipient `user@it-wp2-e13b06-t.sink.test`: active tenant domain of another organization with an enabled `inbound_destination` `alt1.aspmx.l.google.com`; delivered to its MX `relay=mx.sink.test[172.31.250.25]:25`, not to the destination. A `*.gwtenant.sink.test` recipient went to `gw-mx.sink.test[172.31.250.10]:25` and was ingested by the gateway MX for that tenant (LMTP 10050). No fallback needed                                                                                                                                                                                                                                 |
| V2  | next-hop list failover; TLS policy per next hop            | **Pass.** `smtp:[aspmx.l.google.com]:25,[alt1.aspmx.l.google.com]:25` with `sink-google` stopped: `connect to aspmx.l.google.com[172.31.250.27]:25: Connection timed out`, then delivered by alt1. **`smtp_tls_policy_maps` is looked up for each next hop**: alt1's own entry decided every time (`secure match=wrong.example` → `Server certificate not verified`; `encrypt` → `Trusted TLS`; `secure match=nexthop:…` → `Verified TLS`). The api does not need to force one TLS mode per domain                                                                                                                                                         |
| V3  | `secure match=` with the test-CA sinks                     | **Pass, design values unchanged.** Microsoft 365 host `contoso-test.mail.protection.outlook.com`: `nexthop`, `mail.protection.outlook.com`, `.mail.protection.outlook.com` and the preset list each verify alone. Google `aspmx.l` and `alt1.aspmx.l`: `nexthop`, `mx.google.com`, `.aspmx.l.google.com` (also for `aspmx.l` itself, matched through the certificate's `*.aspmx.l.google.com`) and the preset list verify. Wrong names (`mx.google.com` for M365, `mail.protection.outlook.com` for Google) fail: `server certificate verification failed for …: num=62:hostname mismatch`, `dsn=4.7.5, status=deferred (Server certificate not verified)` |
| V4  | XFORWARD `IDENT`, `ADDR`, `Received:`, `ENVID`             | **Pass with one deviation.** `orig_queue_id=dw1-…` (and `orig_client=` when NAME/ADDR were sent) is on the `client=` line of `postfix/reinject-inbound/smtpd` and `postfix/reinject-outbound/smtpd`. `ADDR=203.0.113.7` did not affect `permit_mynetworks` (RCPT `250 2.1.5`). `ENVID` is echoed as `Original-Envelope-Id:` in the sender DSN and in the postmaster copy. **Deviation:** the `Received:` header names the real peer, not the XFORWARD client (see [session contract](#reinjection-session-contract-r8-verified)); `smtpd_peername_lookup=no` added on both listeners                                                                       |
| V5  | `maillog_file` timestamp and every line type               | **Pass with format notes** (next section): no year, no microseconds. **Expiry is one message-level qmgr line** (`from=<…>, status=expired, returned to sender`), not a per-recipient `to=<…>, status=expired` line. Connection failures log `relay=none`. `NOTIFY=NEVER` recipients still produce a postmaster copy (`postmaster non-delivery notification` / `postmaster delay notification`) but no sender notification                                                                                                                                                                                                                                  |
| V6  | `postfix logrotate` and a tailer                           | **Pass after a fix.** Rename + HUP + gzip as described [above](#rotation); postlogd re-creates the file with mode 0600, fixed with the `maillog-compress` wrapper (verified: a `nobody` reader can read the new file). `tail -F` mirror and new lines in the new file verified                                                                                                                                                                                                                                                                                                                                                                             |
| V7  | reinjection reachability                                   | **Pass.** `docker compose port postfix-outbound 10026/10027`: no port (only 25 and 587 published). From the host only `127.0.0.1:2626/2627` (`reinject-forwarder`) answer; `127.0.0.1:10026/10027` are closed. Inside Docker, `smtp-tools` and `postfix` reach `postfix-outbound:10026/10027` directly (`220 out.gateway.local ESMTP`): locally `POSTFIX_REINJECT_NETWORKS` is every private range, as in step 2.2; production restricts it to the delivery-worker subnet plus the security group                                                                                                                                                          |

Other observations:

- A paused container (`docker pause`) accepts the TCP connection in the kernel and never greets: `conversation with … timed out while receiving the initial server greeting` after `smtp_helo_timeout` (300 s), `dsn=4.4.2`. A stopped container gives `No route to host` (about 3 s, ARP) or `Connection timed out` (the 5 s connect timeout).
- `recipient_canonical_maps` with a swap (`a=b,b=a`) never converges: cleanup logs `warning: …: unreasonable recipient_canonical_maps map nesting for user@a-loop.test -- message not accepted, try again later` and the recipient is not rewritten. `relay-sink` therefore uses `smtp_generic_maps` (one lookup, in the SMTP client); verified: the gateway MX received `RCPT TO:<user@b-loop.test>` for mail sent to `user@a-loop.test`.
- `postsuper -r <QID>` on a deferred 10027 message: the queue file before had `content_filter: smtp:` and `named_attribute: log_ident=dw1-…` (`postcat -e`); after `pickup` it has a **new queue id** and **no content filter record** (`log_ident` is kept but not logged again):
  ```
  Nov 03 06:49:14 out postfix/postsuper[980]: 4jJfLW444tzw53: requeued
  Nov 03 06:50:03 out postfix/pickup[253]: 4jJfMb5dpKzw88: uid=100 from=<alice@it-wp2-8a36b3-out.sink.test> orig_id=4jJfLW444tzw53
  ```
  So requeued outbound mail would route through `transport_maps` (cross-tenant shortcut) and lose its binding. Operators must never requeue reinjected mail (runbooks); the parser may treat `orig_id=` as a re-binding of the old queue id's reinjection.
- A `smtp_tls_CApath` that does not exist does not disable the TLS client: opportunistic delivery still logged `Untrusted TLS connection established` and `status=sent` (only verification against that directory fails). That is why a missing `POSTFIX_OUTBOUND_SMTP_TLS_CAPATH` directory is a start-up warning, not a refusal.
- `orig_to=` never appeared on the reinjection listeners (`no_address_mappings`); an `ORCPT` that differs from the envelope recipient is carried only in DSNs, not logged.
- The step 2.2 stack suites passed with the new configuration (adapter on the host): 17 files passed, 1 skipped (apps profile off), 147 tests passed, 10 skipped. No 2.2 test depended on 10027 using `transport_maps` or on the old 30s/120s/30s backoff.

## Delivery log line reference

Every line type the status tailer handles (R9 table), as Postfix 3.7.11 printed it in the runs above. `4jJ…` are long queue ids (`enable_long_queue_ids = yes`). The client name is `unknown` since `smtpd_peername_lookup=no` (the first sample was captured before that change).

**Binding** (`client=` with the token; only from the reinjection listeners' syslog names):

```
Nov 03 06:22:00 out postfix/reinject-outbound/smtpd[694]: 4jJdlD6Cp2zrsd: client=email-gateway-reinject-forwarder-1.email-gateway_mailtest[172.31.250.30], orig_queue_id=dw1-c0722beaeab545ec8914353368ec6afb, orig_client=mail.example.org[203.0.113.7]
Nov 03 06:24:03 out postfix/reinject-inbound/smtpd[290]: 4jJdnb6VPDzs5m: client=unknown[172.31.250.30], orig_queue_id=dw1-89290587de5847d890bc0688ef786d21, orig_client=mail.example.org[203.0.113.9]
Nov 03 06:24:03 out postfix/reinject-outbound/smtpd[282]: 4jJdnb56vBzs5S: client=unknown[172.31.250.30], orig_queue_id=dw1-124412a52ae34e32aa06b9cf0eeb48b1, orig_client=unknown
Nov 03 06:25:07 out postfix/reinject-outbound/smtpd[234]: 4jJdpq5F5kzBLhX: client=unknown[172.31.250.30], orig_queue_id=dw1-35989ee0182e44c3aff447469f299f30
```

The third line was sent with `NAME=[UNAVAILABLE] ADDR=[UNAVAILABLE] HELO=[UNAVAILABLE]` (`orig_client=unknown`), the fourth with `IDENT` and `SOURCE` only (no `orig_client=`).

**The binding is a correlation, not proof of queueing** (review fix): smtpd writes the `client=` line when it opens the queue file at the first accepted RCPT, before DATA. If the session then fails before the final dot is accepted (worker crash, S3 stream error, a DATA or end-of-data 4xx, shutdown), Postfix discards that queue id and never logs it again. The tailer therefore only sets `delivery_reinjections.queue_id`; a recipient is tied to the queue file (`email_deliveries.outbound_queue_id`) by the worker's `250` commit, by qmgr `queue active` when its `nrcpt` equals the group's waiting recipients, or by a result line naming the address. A later session of the same row (same token) **rebinds** the token to its new queue id while the row is `pending`/`in_progress`; a `queued` row's binding never changes. The reconciler moves an expired lease to `queued` only on evidence that the file exists (qmgr `queue active` or a result line), otherwise it releases the row once the log has passed the session, clearing the stale binding. Lines of queue ids that never appeared on a binding line of the stream (submissions, connector mail, DSNs, bounce notices) are ignored after one lookup and never retried.

**Queue file accepted** (qmgr, first and every later scan of the message; also for DSNs `from=<>` and postmaster copies `from=<double-bounce@out.gateway.local>`, which are not bound and are ignored):

```
Nov 03 06:22:00 out postfix/qmgr[212]: 4jJdlD6Cp2zrsd: from=<alice@it-wp2-e13b06-out.sink.test>, size=466, nrcpt=2 (queue active)
Nov 03 06:24:03 out postfix/qmgr[266]: 4jJdnb5qBvzs5Z: from=<>, size=3295, nrcpt=1 (queue active)
Nov 03 06:24:03 out postfix/qmgr[266]: 4jJdnb5qlPzs5c: from=<double-bounce@out.gateway.local>, size=2887, nrcpt=1 (queue active)
```

**Sent** (one line per recipient; several recipients of one connection share the remote `queued as`):

```
Nov 03 06:22:01 out postfix/smtp[698]: 4jJdlD6Cp2zrsd: to=<user@it-wp2-e13b06-t.sink.test>, relay=mx.sink.test[172.31.250.25]:25, delay=0.16, delays=0.09/0.05/0.02/0.01, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 05221156A60)
Nov 03 06:22:04 out postfix/smtp[697]: 4jJdlD6Cp2zrsd: to=<bob@it-wp2-e13b06-g.gwtenant.sink.test>, relay=gw-mx.sink.test[172.31.250.10]:25, delay=3.9, delays=0.09/0.02/0.02/3.8, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 4jJdlF03jCzBLL7)
Nov 03 06:31:24 out postfix/smtp[238]: 4jJdxB42pbzs5Q: to=<user@it-wp2-e13b06-t.sink.test>, relay=alt1.aspmx.l.google.com[172.31.250.28]:25, delay=46, delays=46/0.01/0.03/0.01, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as DEF16156A86)
Nov 03 06:38:59 out postfix/smtp[1587]: 4jJf6j4YqHzBYty: to=<v@v2.test>, relay=alt1.aspmx.l.google.com[172.31.250.28]:25, delay=6, delays=0.01/0.94/5/0, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 933E61E895)
Nov 03 06:42:09 out postfix/smtp[283]: 4jJfBS741Qzs54: to=<Mixed.Case@orcpt-e13b06.sink.test>, relay=mx.sink.test[172.31.250.25]:25, delay=0.07, delays=0.06/0/0.01/0, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 0DDA214FBDA)
```

The third line is a recovery after `No route to host`; the fourth a failover to the second next hop. Postfix keeps the address case as given (match case-insensitively).

**Deferred** (remote 4xx; connection refused, no route, connect timeout and greeting timeout log `relay=none` or the host; TLS verification failure; the retry transport):

```
Nov 03 06:25:07 out postfix/smtp[238]: 4jJdpq5F5kzBLhX: to=<soft-bounce@ext-e13b06.sink.test>, relay=mx.sink.test[172.31.250.25]:25, delay=0.11, delays=0.08/0.02/0.01/0, dsn=4.2.1, status=deferred (host mx.sink.test[172.31.250.25] said: 450 4.2.1 <soft-bounce@ext-e13b06.sink.test>: Recipient address rejected: Mailbox busy (in reply to RCPT TO command))
Nov 03 06:25:07 out postfix/smtp[238]: connect to mx.sink.test[172.31.250.25]:2526: Connection refused
Nov 03 06:25:07 out postfix/smtp[238]: 4jJdpq6K4yzBLhZ: to=<user@it-wp2-e13b06-refused.sink.test>, relay=none, delay=0.01, delays=0.01/0/0/0, dsn=4.4.1, status=deferred (connect to mx.sink.test[172.31.250.25]:2526: Connection refused)
Nov 03 06:30:41 out postfix/smtp[238]: connect to alt1.aspmx.l.google.com[172.31.250.28]:25: No route to host
Nov 03 06:30:41 out postfix/smtp[238]: 4jJdxB42pbzs5Q: to=<user@it-wp2-e13b06-t.sink.test>, relay=none, delay=3.1, delays=0.02/0.02/3.1/0, dsn=4.4.1, status=deferred (connect to alt1.aspmx.l.google.com[172.31.250.28]:25: No route to host)
Nov 03 06:38:43 out postfix/smtp[1482]: connect to aspmx.l.google.com[172.31.250.27]:25: Connection timed out
Nov 03 06:30:07 out postfix/smtp[238]: 4jJdpq6t8lzBLhc: to=<user@it-wp2-e13b06-m365.test>, relay=contoso-e13b06.mail.protection.outlook.com[172.31.250.26]:25, delay=300, delays=0.01/0/300/0, dsn=4.4.2, status=deferred (conversation with contoso-e13b06.mail.protection.outlook.com[172.31.250.26] timed out while receiving the initial server greeting)
Nov 03 06:36:25 out postfix/smtp[946]: server certificate verification failed for contoso-test.mail.protection.outlook.com[172.31.250.26]:25: num=62:hostname mismatch
Nov 03 06:36:25 out postfix/smtp[946]: 4jJf3r68sxzBLhX: to=<v@v3m.test>, relay=contoso-test.mail.protection.outlook.com[172.31.250.26]:25, delay=0.65, delays=0.01/0.64/0.01/0, dsn=4.7.5, status=deferred (Server certificate not verified)
Nov 03 06:38:43 out postfix/smtp[1482]: 4jJf6P5wmjz60cD: to=<v@v2.test>, relay=alt1.aspmx.l.google.com[172.31.250.28]:25, delay=5.6, delays=0.01/0.64/5/0, dsn=4.7.5, status=deferred (Server certificate not verified)
Nov 03 06:30:54 out postfix/error[255]: 4jJdxB4cnGzsFw: to=<user@it-wp2-e13b06-refused.sink.test>, relay=none, delay=16, delays=16/0.02/0/0, dsn=4.4.1, status=deferred (Destination not configured)
```

Notes for the parser: the separate `connect to …` lines carry no queue id (ignore them; the `to=` line repeats the reason). A connection-level failure is a remote attempt even with `relay=none` (count it when the text starts with `connect to` or `conversation with`); the `postfix/error` line is not (no remote attempt, class `no_destination`). With a next-hop list, the `to=` line names the **last** host tried and its reason.

**Bounced** (remote 5xx):

```
Nov 03 06:24:03 out postfix/smtp[286]: 4jJdnb56vBzs5S: to=<hard-bounce@ext-e13b06.sink.test>, relay=mx.sink.test[172.31.250.25]:25, delay=0.11, delays=0.06/0.02/0.02/0.01, dsn=5.1.1, status=bounced (host mx.sink.test[172.31.250.25] said: 550 5.1.1 <hard-bounce@ext-e13b06.sink.test>: Recipient address rejected: User unknown (in reply to RCPT TO command))
```

**Expired** (message level, qmgr; applies to every recipient of the queue file that is not yet final; the last per-recipient `deferred` line of the same scan precedes it):

```
Nov 03 06:26:23 out postfix/smtp[256]: 4jJdpq6K4yzBLhZ: to=<user@it-wp2-e13b06-refused.sink.test>, relay=none, delay=76, delays=76/0.02/0.01/0, dsn=4.4.1, status=deferred (connect to mx.sink.test[172.31.250.25]:2526: Connection refused)
Nov 03 06:26:23 out postfix/qmgr[212]: 4jJdpq6K4yzBLhZ: from=<ext@example.org>, status=expired, returned to sender
Nov 03 06:26:23 out postfix/qmgr[212]: 4jJdpq5F5kzBLhX: from=<alice@it-wp2-e13b06-out.sink.test>, status=expired, returned to sender
```

(captured with a temporary `POSTFIX_MAXIMAL_QUEUE_LIFETIME=1m`, `POSTFIX_DELAY_WARNING_TIME=15s` container; those tiny values also make the bounce daemon log `warning: [built-in]: zero result in delay template conversion …`, which never happens with production values.)

**DSN generated** (bounce daemon; `sender …` = to the original envelope sender, `postmaster …` = the copy for the bounce handler):

```
Nov 03 06:24:03 out postfix/bounce[287]: 4jJdnb56vBzs5S: sender non-delivery notification: 4jJdnb5qBvzs5Z
Nov 03 06:24:03 out postfix/bounce[287]: 4jJdnb56vBzs5S: postmaster non-delivery notification: 4jJdnb5qlPzs5c
Nov 03 06:25:23 out postfix/bounce[239]: 4jJdpq5F5kzBLhX: sender delay notification: 4jJdq71pPzzBLhY
Nov 03 06:25:23 out postfix/bounce[239]: 4jJdpq6K4yzBLhZ: postmaster delay notification: 4jJdq71TRHzxsM
Nov 03 06:26:23 out postfix/bounce[239]: 4jJdpq5F5kzBLhX: sender non-delivery notification: 4jJdrH47Xmzw7V
```

For a `NOTIFY=NEVER` recipient there is **no** `sender …` line, only the `postmaster …` line, and cleanup logs an orphan `message-id=` line for the discarded sender notice (`Nov 03 06:24:03 out postfix/cleanup[288]: 4jJdnb68Syzw59: message-id=<4jJdnb68Syzw59@out.gateway.local>`, never followed by a qmgr line).

**Removed** (queue file gone; also from an operator's `postsuper -d`):

```
Nov 03 06:22:04 out postfix/qmgr[212]: 4jJdlD6Cp2zrsd: removed
Nov 03 06:31:26 out postfix/postsuper[298]: 4jJdxB4cnGzsFw: removed
```

**Refusals at reinjection** (no queue id; the worker sees them as RCPT replies, they are not delivery-log signals):

```
Nov 03 06:25:08 out postfix/reinject-inbound/smtpd[240]: NOQUEUE: reject: RCPT from unknown[172.31.250.30]: 450 4.4.1 <user@it-wp2-e13b06-nodest.sink.test>: Recipient address rejected: Destination not configured; from=<ext@example.org> to=<user@it-wp2-e13b06-nodest.sink.test> proto=ESMTP helo=<delivery.gateway.local>
```

**Ignored** (examples): `postfix/lmtp[…]: …: to=<bounce-notices@bounces.gateway.internal>, relay=host.docker.internal[…]:10052, …, status=sent (250 2.0.0 Ok)` (postmaster copy to the bounce handler, unbound queue id), `Verified|Trusted|Untrusted TLS connection established to …`, `postfix/master[1]: reload -- version 3.7.11, configuration /etc/postfix`, `postfix/postfix-script[…]: the Postfix mail system is running: PID: 1`, `… disconnect from unknown[172.31.250.30] ehlo=1 xforward=2 mail=1 rcpt=2 data=1 quit=1 commands=8`.

## Deviations from the design (WP2)

| Decision                                  | Design                                                                     | Implemented                                                                                                                                                                                                                                                                                                                      |
| ----------------------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R8/R10 `Received:` of the reinjection hop | shows the original client through XFORWARD                                 | Postfix 3.7 writes the real peer into `Received:` (XFORWARD only reaches the log and the queue file). Added `-o smtpd_peername_lookup=no` on 10026/10027 so the header reads `from delivery.gateway.local (unknown [<worker ip>])` and never carries internal host names. The worker's address stays visible                     |
| R9 `expired` line                         | per recipient: `to=<a>, relay=none, …, status=expired, returned to sender` | message level: `QID: from=<sender>, status=expired, returned to sender` (qmgr). The parser applies it to every non-final recipient of the bound queue file                                                                                                                                                                       |
| R9 `no_destination`                       | `postfix/(error\|retry)` deferred line                                     | on 10026 the reinjection itself gets `450 4.4.1 … Destination not configured` at RCPT; the `postfix/error` line only appears for mail queued before the destination disappeared                                                                                                                                                  |
| R9 log file permissions                   | file mode 0644                                                             | as designed, plus `maillog_file_compressor = maillog-compress` because postlogd re-creates the file with 0600 after `postfix logrotate`                                                                                                                                                                                          |
| §6 relay-sink rewrite                     | `recipient_canonical_maps`                                                 | `smtp_generic_maps` (canonical maps are applied recursively; a two-way swap is refused). Generic maps also rewrite matching header addresses, which the loop tests do not depend on                                                                                                                                              |
| §6 `mailtest` network                     | fixed subnet                                                               | plus `gateway: 172.31.250.1` and `ip_range: 172.31.250.128/25` (dynamic addresses can never collide with the fixed ones)                                                                                                                                                                                                         |
| §6 test-pki keys                          | 0640, readable by the sinks' postfix                                       | 0640 owned by root: Postfix reads TLS keys as root before dropping privileges                                                                                                                                                                                                                                                    |
| V3 / R2 seed values                       | WP2 corrects the preset `tls_verify_names` if needed                       | no correction: `nexthop:mail.protection.outlook.com:.mail.protection.outlook.com` and `nexthop:mx.google.com:.aspmx.l.google.com` verify. Not verifiable locally: `*.mx.microsoft` hosts (their real certificate names are unknown here; with `nexthop` in the list they verify if Microsoft's certificate covers the host name) |
