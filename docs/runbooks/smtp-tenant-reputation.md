# Runbook: tenant sending reputation (bounce ratio, suppressions, deferrals)

Step 2.2 (D13) records **counters only**: what a tenant submitted, what the gateway relayed, how much bounced. Nothing reads them automatically yet. No API endpoint, scheduled job or tenant throttle uses them. The Alertmanager rules and Grafana panels belong to step 10.3, and automatic throttling of a tenant is out of scope (design §10). This page gives operators the queries and thresholds to use until then.

## Where the numbers come from

| Event (`event` label) | Recorded by                                                                                     | Unit          |
| --------------------- | ----------------------------------------------------------------------------------------------- | ------------- |
| `submitted`           | outbound policy (`submission` / `relay`) when a recipient passes                                | RCPT          |
| `relayed`             | outbound policy (`reinject-outbound`, 10027) when a recipient passes on its way to the Internet | RCPT          |
| `suppressed`          | outbound policy, recipient refused by `delivery_suppressions`                                   | RCPT          |
| `rate_limited`        | outbound policy, per-tenant per-minute or per-day limit hit                                     | RCPT          |
| `bounced_hard`        | bounce handler, `Action: failed` with a 5.x.x (or missing) status, newly recorded               | DSN recipient |
| `bounced_soft`        | bounce handler, `Action: failed` after transient errors (queue lifetime expired)                | DSN recipient |
| `delayed`             | bounce handler, delay warning (`delay_warning_time`, 4 h)                                       | DSN recipient |

The bounce handler counts a notice only when the undelivered message carries a valid outbound `X-Gateway-Trace` for the sender's organization. The trace is added when the gateway reinjects a message on 10027 for delivery. Failures of the gateway's own ingestion hop, such as the From check, a loop, or an adapter, S3 or database outage, are therefore **not** tenant bounces (§12.7 of the step design).

Each event is counted in two places:

- Prometheus: `smtp_tenant_mail_events_total{organization_id, event}`, scraped from every smtp-adapter instance (job `smtp-adapter`). Use `increase()` or `rate()`, which handle restarts. The cardinality is one series per organization and event.
- Redis: the hash `rep:{organizationId}:{yyyymmdd}` (UTC day, TTL 40 days). Use it for an ad-hoc look at one tenant: `redis-cli HGETALL rep:<organizationId>:<yyyymmdd>` on the shared Redis. It is never exposed to tenants.

`smtp_reputation_errors_total` counts failed recordings. Recording never fails mail, so a non-zero rate means the counters undercount.

## Queries

Hard-bounce ratio per organization over 24 hours, for organizations with enough volume to judge:

```promql
(
  sum by (organization_id) (increase(smtp_tenant_mail_events_total{event="bounced_hard"}[24h]))
/
  sum by (organization_id) (increase(smtp_tenant_mail_events_total{event="relayed"}[24h]))
)
and on (organization_id)
  sum by (organization_id) (increase(smtp_tenant_mail_events_total{event="relayed"}[24h])) >= 100
```

Suppression hit ratio (a tenant keeps sending to addresses that already bounced or were blocked):

```promql
sum by (organization_id) (increase(smtp_tenant_mail_events_total{event="suppressed"}[24h]))
/
clamp_min(sum by (organization_id) (increase(smtp_tenant_mail_events_total{event="submitted"}[24h])), 1)
```

Delay ratio (remote sites deferring a tenant's mail, often greylisting or reputation blocks):

```promql
sum by (organization_id) (increase(smtp_tenant_mail_events_total{event="delayed"}[24h]))
/
clamp_min(sum by (organization_id) (increase(smtp_tenant_mail_events_total{event="relayed"}[24h])), 1)
```

Tenants hitting their own limits (sustained, not a single burst):

```promql
sum by (organization_id) (rate(smtp_tenant_mail_events_total{event="rate_limited"}[15m])) > 0
```

## Recommended thresholds

These are starting values for SaaS tenants. Tune them once real traffic exists; mailbox providers start blocking at about a 2 to 5 % bounce ratio.

| Signal                       | Warning               | Critical    | Minimum volume       |
| ---------------------------- | --------------------- | ----------- | -------------------- |
| Hard-bounce ratio (24 h)     | > 2 %                 | > 5 %       | ≥ 100 relayed / 24 h |
| Suppression hit ratio (24 h) | > 5 %                 | > 15 %      | ≥ 100 submitted      |
| Delay ratio (24 h)           | > 10 %                | > 25 %      | ≥ 100 relayed        |
| `rate_limited`               | > 0 for 15 min        | > 0 for 2 h | none                 |
| Record errors                | > 0 for 10 min (page) | (none)      | none                 |

Complaint (feedback-loop) rates are not collected: there is no FBL or ARF intake yet.

## What to do

1. Identify the organization (`organization_id`) and check the recent `bounce_events` (writer or reader): `SELECT bounce_type, enhanced_status, reporting_mta, COUNT(*) FROM bounce_events WHERE organization_id = ? AND occurred_at > NOW() - INTERVAL 1 DAY GROUP BY 1, 2, 3;`.
2. Mostly `5.1.1` (unknown users): the tenant is mailing a stale list. The hard-bounce suppressions already stop repeats for `SUPPRESSION_HARD_BOUNCE_DAYS`. Contact the tenant.
3. Mostly `5.7.x` from a few providers: the mail is being blocked for reputation or content. Check the DKIM signing (runbook [smtp-dkim-signing.md](smtp-dkim-signing.md)) and the tenant's SPF/DMARC, then contact the tenant.
4. If the volume is abusive, lower the tenant's `outbound_recipients_per_minute` / `outbound_recipients_per_day` limits (organization limits API) or suspend its connectors. There is no automatic throttling.
