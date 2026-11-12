# notification-worker

Notification Service. **Step 5.2** ([design](../../docs/plan/steps/16-policy-engine.md) P15, P24, P25; runbook [policy-notifications](../../docs/runbooks/policy-notifications.md)) gives it its first job: the **policy notices** requested by the policy-engine — ALERT actions (to the organization's policy administrators) and sender non-delivery notices of rejected outbound/internal mail. **Step 5.3** ([design](../../docs/plan/steps/17-quarantine.md) Q16, Q20) adds the **quarantine notices** (`mail.quarantine.notification_requested.v1` on the same queue and ledger): per-user digests, approval requests and decisions, blocked releases, rate-bounded admin alerts and sender notices of rejected outbound/internal entries (`src/notifications/quarantine-notification.handler.ts`, `quarantine-reads.ts`, `quarantine-templates.ts`; metric `notification_quarantine_messages_total{kind,result}`; Message-ID `<quarantine-notice.<eventId>@<From domain>>`). Webhooks, DLP incident notifications and a preference center are step 6.2.

## Run and test

```bash
pnpm --filter @email-gateway/notification-worker dev               # reads ../../.env, port 3050
pnpm --filter @email-gateway/notification-worker test              # unit (config, templates, mailer, handler, wiring)
pnpm --filter @email-gateway/notification-worker test:integration  # real MySQL writer + RabbitMQ (throwaway vhost) + in-process SMTP sink
```

## What it does

| Piece                                                                                                                                                                                                                                                                                    | File                                                                        |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Consumer of `email.notifications` (`mail.policy.notification_requested.v1`), ledger `notification-worker.policy`, `processOnceHandler` with `NOTIFICATION_DB_TX_TIMEOUT_MS`, retry/dead-letter per topology v9 (hold, 8 attempts, 5 s–1 min, 24 h), consumer progress for the reconciler | `src/notifications/notifications.module.ts`                                 |
| Handler: writer reads (organization-checked, echo-checked), recipient resolution, template, send, metrics                                                                                                                                                                                | `src/notifications/policy-notification.handler.ts`, `notification-reads.ts` |
| Fixed plain-text templates, deterministic `Message-ID: <policy-notice.<eventId>@<From domain>>`                                                                                                                                                                                          | `src/notifications/templates.ts`                                            |
| nodemailer over the `NOTIFY_SMTP_*` relay (the api's transport options; plaintext only when APP_ENV is local or ci), Bcc only                                                                                                                                                            | `src/notifications/mailer.ts`                                               |
| `notification_policy_messages_total{kind, result}` (`sent`, `no_recipients`, `disabled`, `failed`), `notification_send_duration_seconds`                                                                                                                                                 | `src/notifications/notification-metrics.ts`                                 |

**Recipients (P25).** `policy_alert`: active, non-deleted, email-verified users of the event's organization holding `policy:publish` through a role (≤ `NOTIFICATION_MAX_RECIPIENTS`, sorted by user id); none → `no_recipients`. `sender_non_delivery`: the message's `envelope_from` from the writer row of the event's organization, only when its domain is an active domain of that organization (never an external address); else `no_recipients`. An event naming a message that is not the organization's is dead-lettered (`message_not_found`) without a send. `alerts.enabled` is evaluated by the policy-engine (a disabled ALERT is recorded there and never requested).

**Privacy.** A notice carries the organization name, the message public id, its received time, direction, the disposition, the decisive policy name and rule id and a portal link (`PORTAL_PUBLIC_URL/messages/<id>`); the sender notice adds the Internet-Message-ID and the recipient count. Never a subject, body, file name, URL of the message or any other address; database text is reduced to printable, bounded single-line text.

**Delivery semantics.** At least once: the SMTP submission runs inside the idempotency transaction before the ledger commits, so a crash between them can send a notice twice (same Message-ID). An SMTP failure is thrown and retried by the topology, then dead-lettered. Without `NOTIFY_SMTP_HOST` nothing is sent (`disabled`).

## Configuration

`DATABASE_URL`, `RABBITMQ_NOTIFICATION_URL` (`eg-notification`: read `email.notifications`, write retry and dead-letter copies), `NOTIFY_SMTP_HOST` / `_PORT` / `_SECURE` / `_USER` / `_PASSWORD` / `_CA_PATH` / `_FROM`, `NOTIFICATION_PREFETCH` (4, 1–32), `NOTIFICATION_DB_TX_TIMEOUT_MS` (120 000, 120 000–600 000), `NOTIFICATION_MAX_RECIPIENTS` (50, 1–500), `PORTAL_PUBLIC_URL` (https in staging/production). Readiness: `mysql`, `rabbitmq`. Locally the relay is `postfix-notify`, which discards mail unless `NOTIFY_RELAY_HOST` is set; Compose maps `NOTIFY_SMTP_HOST: ${NOTIFICATION_SMTP_HOST:-postfix-notify}` so a test can point the worker at a mail sink.
