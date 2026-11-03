# Runbook: deferred delivery backlog

For platform operators. Approved mail waits instead of being delivered: deliveries stay `deferred` (or reinjections stay `pending`) and postfix-outbound's deferred queue grows. This runbook classifies the backlog by error class, handles a destination outage and gateway rate limiting, and explains how to retry safely. Background: [mail routing and delivery tracking](../deployment/mail-routing.md), design [step 2.3](../plan/steps/05-routing.md) R4/R8/R9.2/R11. For queues that grow before delivery (ingestion, DKIM, disk), see [smtp-queue-backlog.md](smtp-queue-backlog.md).

Two retry loops exist, and only one of them talks to remote servers:

| Where                         | What waits                                                                                                                        | Who retries                                                                                                                                 |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| delivery-worker (own hop)     | `delivery_reinjections` rows `pending` with `next_attempt_at` in the future: rate limited, reinjection 4xx, postfix-outbound down | the worker, exponential `DELIVERY_REINJECT_RETRY_BASE_SECONDS` … `_MAX_SECONDS`, until `DELIVERY_REINJECT_MAX_AGE_SECONDS` (then `expired`) |
| postfix-outbound (remote hop) | queue files in `deferred/` after a 4xx, timeout, refused connection, TLS failure, no destination                                  | Postfix only: about 5, 10, 20, 40, 66, 66 … minutes, `expired` after 5 days (`maximal_queue_lifetime`)                                      |

## Detection

- Deferred deliveries by error class (reader; bounded time range so partitions prune):

  ```sql
  SELECT direction, last_error_class, COUNT(*) AS deliveries, MIN(status_changed_at) AS oldest
    FROM email_deliveries
   WHERE status = 'deferred' AND received_at >= NOW() - INTERVAL 6 DAY
   GROUP BY direction, last_error_class ORDER BY deliveries DESC;
  ```

  The same per tenant: add `organization_id`; per destination: group by `destination_key` (`tenant:<domainId>` for inbound/internal, `mx:<recipient domain>` for outbound). The API shows the same per message (`GET /messages/{id}/deliveries`) and tenant-wide (`GET /deliveries?status=deferred`).

- Worker side: `SELECT listener, last_error_class, COUNT(*), MIN(next_attempt_at) FROM delivery_reinjections WHERE status = 'pending' AND received_at >= NOW() - INTERVAL 6 DAY GROUP BY 1, 2;` and the metrics `delivery_reinjections_total{outcome="retry|rate_limited"}`, `delivery_rate_limited_total{scope}`.
- Postfix side: `docker compose exec postfix-outbound postqueue -j | jq -r '.recipients[].delay_reason' | sed -E 's/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/IP/g' | sort | uniq -c | sort -rn | head` and the delivery log (`grep 'status=deferred' /var/log/postfix-outbound/maillog | tail`).

## Error classes (R9.2) and what to do

| Class                                                    | Typical Postfix text                                                                                      | Meaning / action                                                                                                                                                                                                                                 |
| -------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `connect`                                                | `connect to h[ip]:25: Connection refused`, `No route to host`, `Connection timed out`                     | The destination (or its network) is down or blocks the gateway's egress IPs. Destination outage, below                                                                                                                                           |
| `timeout`                                                | `conversation with h[ip] timed out while receiving the initial server greeting`, `lost connection with …` | The server accepts TCP but does not answer (overloaded, tarpitting, a firewall that half-opens). As a destination outage                                                                                                                         |
| `dns`                                                    | `Host or domain name not found. Name service error for name=… type=MX: Host not found, try again`         | Recipient domain without working DNS, or the gateway's resolver failing. If many unrelated domains: check the VPC resolver first                                                                                                                 |
| `tls`                                                    | `Server certificate not verified`, `TLS is required, but was not offered by host …`                       | A `verify`/`required` destination presents a certificate that does not match the verify names (`hostname mismatch`) or offers no STARTTLS. Tenant configuration; see the customer guide [destination servers](../domains/destination-servers.md) |
| `remote_4xx`                                             | `host h[ip] said: 450 4.2.1 … (in reply to RCPT TO command)`, `421 … too many connections`                | The remote server asks to retry later (greylisting, mailbox busy, throttling). Usually nothing to do; Postfix's backoff handles it. Many 421/451 from one provider: reputation or rate, see below                                                |
| `no_destination`                                         | `status=deferred (Destination not configured)`                                                            | The tenant domain has no enabled destination server (deleted while mail was queued). Ask the tenant to configure one (`PUT /api/v1/domains/{id}/destinations`); mail expires after 5 days otherwise                                              |
| `gateway_rate_limited`, `gateway_rate_limit_unavailable` | (worker, before 10027)                                                                                    | Outbound rate limits per tenant / tenant × domain / destination domain, or Redis unavailable (fail closed). Rate limited, below                                                                                                                  |
| `gateway_hold`                                           | (worker)                                                                                                  | Inbound mail of a suspended domain or organization is held until it is active again or the max age                                                                                                                                               |
| `reinjection_4xx`, `reinjection_error`                   | (worker) `450 4.3.5 … Policy service unavailable`, connection refused to 10026/10027                      | postfix-outbound or smtp-adapter (policy, socketmap) unavailable: [smtp-policy-service-down.md](smtp-policy-service-down.md), [smtp-gateway-restart.md](smtp-gateway-restart.md)                                                                 |

## Recovery

### Destination outage (one tenant's servers, or one Internet domain)

1. Confirm it is one destination: the backlog shares one `destination_key` / one host in `delay_reason`.
2. Inbound/internal (`tenant:<domainId>`): the tenant's own server. Nothing to fix on the gateway; Postfix retries with backoff and fails over to the next server of the list (lower priority) on every attempt. Inform the tenant (their status page shows `deferred`, class `connect`/`timeout`). If they add or fix a server, the new route is used at the next attempt after the adapter cache expires (`SMTP_DOMAIN_CACHE_TTL_SECONDS`; the api's `domain.routing.changed.v1` event invalidates it sooner).
3. Outbound (`mx:<domain>`): a remote provider outage or a block of the gateway's egress IPs. Check the remote replies for block lists or reputation texts; follow [smtp-tenant-reputation.md](smtp-tenant-reputation.md) if a tenant's mail causes it.
4. A destination that resolves to an internal address (egress denied by the network ACL) times out forever: the tenant must change the host name.

### Rate limited (outbound)

1. `delivery_rate_limited_total{scope}` tells which limit: `tenant`, `tenant_domain` or `destination` (gateway-wide per destination domain).
2. Expected after a burst: the worker releases the group to the next minute window; nothing is lost. Check that the tenant's limits (`organization_limits` keys `outbound_recipients_per_minute`, `outbound_recipients_per_domain_per_minute`) match their plan.
3. `gateway_rate_limit_unavailable` = Redis errors: fix Redis ([smtp-policy-service-down.md](smtp-policy-service-down.md) for the shared Redis); the worker defers until it can count (fail closed).

### Flushing safely

Once the cause is fixed, Postfix retries by itself within `maximal_backoff_time` (about an hour in production). To retry earlier:

- One destination: `docker compose exec postfix-outbound postqueue -s <recipient domain>` (outbound) or flush the affected queue ids: `postqueue -j | jq -r 'select(.recipients[].delay_reason | test("<host>")) | .queue_id' | xargs -n1 postqueue -i`.
- Everything deferred: `postqueue -f`, only after the cause is fixed and if the remote side can take the burst (a provider that throttled you will throttle again).
- Worker side: pending reinjections are retried at `next_attempt_at`; restarting the worker does not speed this up. Do not edit `next_attempt_at` for rate-limited rows (it would only be released into the same limit).

Each flush produces new `status=…` lines; the delivery status follows from the log as usual (duplicates are ignored).

## Verification

- The `deferred` count by class shrinks; `delivered` transitions rise (`delivery_status_transitions_total{status="delivered"}`).
- `postqueue -j | wc -l` back to normal.

## Never

- `postsuper -d` on deferred mail (it is accepted mail; the deliveries end `unknown`) or deleting spool files.
- `postsuper -r` on postfix-outbound (verified, [mail-routing.md](../deployment/mail-routing.md#verified-postfix-behaviour)): the message gets a **new queue id** (`pickup[…]: <new>: … orig_id=<old>`) and **loses its `content_filter: smtp:` record**, so requeued 10027 mail would route through `transport_maps` (a cross-tenant shortcut) and its deliveries lose their queue-id binding (`unknown`). Use `postqueue -f`/`-s`/`-i` instead.
- Raise `maximal_queue_lifetime` during an incident without a decision: it changes when senders get their DSN.
- Point a tenant domain's destination at a gateway host to "drain" it (refused by the api; written directly it defers as `no_destination`).
- Change `DELIVERY_REINJECT_MAX_AGE_SECONDS` downwards during a backlog: rows past the new age become `expired` at once.
