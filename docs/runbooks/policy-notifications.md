# Policy notifications (step 5.2)

The notification-worker sends the notices the policy-engine requests ([design](../plan/steps/16-policy-engine.md) P15, P25; [README](../../apps/notification-worker/README.md)): **policy alerts** (ALERT action) to the organization's policy administrators and **sender non-delivery notices** when an outbound/internal message is rejected. They are _requested_ by 5.2, never part of the mail decision: a lost or late notice never changes a disposition.

## Flow

1. The policy-engine evaluates a round and, in the same commit, writes `mail.policy.notification_requested.v1` to `message_outbox` (`kind = policy_alert` when an ALERT applies and the tenant setting `alerts.enabled` is on; `kind = sender_non_delivery` for a REJECT of outbound/internal mail with the notice on).
2. The event-relay publishes it to `email.policy` (`org.<id>.mail.policy.notification_requested.v1`), bound to the work queue `email.notifications`.
3. The notification-worker (`eg-notification`) consumes it with the ledger `notification-worker.policy`, resolves the recipients on the writer, renders a fixed plain-text notice and submits it to the relay (`NOTIFY_SMTP_*`).

## Recipients and privacy

- `policy_alert`: active, non-deleted, email-verified users of the organization holding `policy:publish` through a role, sorted by id, at most `NOTIFICATION_MAX_RECIPIENTS` (default 50). One message, recipients as Bcc (they do not see each other).
- `sender_non_delivery`: the message's envelope sender, only when its domain is an **active domain of the organization**; an external or null sender gets nothing (`no_recipients`).
- The text holds the organization name, message public id, received time, direction, disposition, decisive policy name and rule id, a portal link, and for the sender notice the Internet-Message-ID and recipient count. Never the subject, body, file names, URLs or other addresses.

## At-least-once semantics

The SMTP submission happens inside the idempotency transaction before the ledger row commits. A duplicate event (relay replay, redelivery) is absorbed by the ledger. A crash after the relay accepted the notice but before the commit sends it again on redelivery with the **same `Message-ID`** (`<policy-notice.<eventId>@<From domain>>`), so mail clients can de-duplicate.

## Failures

| Symptom                                                                                          | Meaning and action                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `notification_policy_messages_total{result="failed"}` rising, alert `PolicyNotificationFailures` | The relay refused or was unreachable. The event is retried (hold, 8 attempts, 5 s–1 min, 24 h), then dead-lettered to `dead-letter.email.notifications`. Check the relay (`postfix-notify` logs, `NOTIFY_SMTP_*`), then replay from the dead-letter view (`POST /api/v1/platform/dead-letters/replay`, platform operators; [rabbitmq-messaging](rabbitmq-messaging.md)). |
| `result="disabled"`                                                                              | `NOTIFY_SMTP_HOST` is not set: nothing is sent. Set the relay and restart; already-handled events are not re-sent.                                                                                                                                                                                                                                                       |
| `result="no_recipients"`                                                                         | No verified policy administrator (alert) or the sender is not in an active domain of the organization (notice). Expected; no action.                                                                                                                                                                                                                                     |
| Dead letter with reason `message_not_found`                                                      | The event names a message that is not the organization's (or was purged). Investigate as a defect; never replay blindly.                                                                                                                                                                                                                                                 |
| Readiness `rabbitmq` failing                                                                     | Broker user or URL wrong (`RABBITMQ_NOTIFICATION_URL`); events wait in `email.notifications`.                                                                                                                                                                                                                                                                            |

## Local stack

- `postfix-notify` **discards** mail unless `NOTIFY_RELAY_HOST` is set (no outbound mail leaves a laptop). To see notices locally, point the worker at a sink: Compose maps `NOTIFY_SMTP_HOST: ${NOTIFICATION_SMTP_HOST:-postfix-notify}`, so `NOTIFICATION_SMTP_HOST=mail-sink docker compose up -d notification-worker` (the stack suite does this for its run and restores it afterwards).
- Plaintext SMTP (`NOTIFY_SMTP_SECURE=none`) is accepted only when `APP_ENV` is `local` or `ci`.
- Metrics: `GET http://localhost:3050/metrics` (`notification_policy_messages_total`, `notification_send_duration_seconds`).
