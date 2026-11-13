import type { Prisma } from '@email-gateway/database';
import {
  EventTypes,
  type NotificationAlertRequestedV1,
  notificationAlertRequestedV1,
} from '@email-gateway/event-contracts';
import {
  type AlertKind,
  alertWindow,
  type Severity,
  webhookEventId,
} from '@email-gateway/webhooks';

/**
 * Security alert requests (step 6.2 N2): throttle windows in `notification_alert_windows`
 * (unique `(organization_id, kind, scope_key, window_start)`) and, for the **first** event of a
 * window only, one `notification.alert_requested.v1` outbox row (`aggregate_type =
 * 'organization'`, deterministic event id `webhookEventId(sourceEventId, 'alert:<kind>')`).
 * Runs inside the producing transaction (the fanout's ledger transaction, or the delivery
 * recorder's CAS transaction), so a redelivered source never counts twice.
 */

export interface AlertRequestInput {
  organizationId: bigint;
  kind: AlertKind;
  severity: Severity;
  /** `-` (threat), the domain public id (DNS) or the subscription public id (webhook disabled). */
  scopeKey: string;
  /** The event time the window is computed from (the source `occurredAt`). */
  occurredAt: Date;
  throttleMinutes: number;
  /** Envelope id of the source event (or the delivery public id of an auto-disable). */
  sourceEventId: string;
  correlationId: string;
  refs: NotificationAlertRequestedV1['refs'];
  now: Date;
}

export type AlertRequestResult =
  { result: 'requested'; eventId: string } | { result: 'throttled'; eventId: null };

export async function requestAlert(
  tx: Prisma.TransactionClient,
  input: AlertRequestInput,
): Promise<AlertRequestResult> {
  const window = alertWindow(input.occurredAt, input.throttleMinutes);
  const affected = await tx.$executeRaw`
    INSERT INTO notification_alert_windows
      (organization_id, kind, scope_key, window_start, event_count, first_source_event_id,
       created_at, updated_at)
    VALUES (${input.organizationId}, ${input.kind}, ${input.scopeKey}, ${window.from}, 1,
            ${input.sourceEventId}, NOW(3), NOW(3))
    ON DUPLICATE KEY UPDATE event_count = event_count + 1, updated_at = NOW(3)`;
  // MySQL: 1 = inserted (first event of the window), 2 = an existing window was counted.
  if (affected !== 1) return { result: 'throttled', eventId: null };

  const previousStart = new Date(window.from.getTime() - input.throttleMinutes * 60_000);
  const previous = await tx.$queryRaw<Array<{ event_count: number | bigint }>>`
    SELECT event_count FROM notification_alert_windows
    WHERE organization_id = ${input.organizationId} AND kind = ${input.kind}
      AND scope_key = ${input.scopeKey} AND window_start = ${previousStart}`;
  const suppressedBefore = Math.max(0, Number(previous[0]?.event_count ?? 0) - 1);
  const eventId = webhookEventId(input.sourceEventId, `alert:${input.kind}`);
  const payload = notificationAlertRequestedV1.parse({
    kind: input.kind,
    severity: input.severity,
    refs: input.refs,
    window: { from: window.from.toISOString(), to: window.to.toISOString() },
    counts: { suppressedBefore },
    requestedAt: input.now.toISOString(),
  });
  await tx.messageOutbox.create({
    data: {
      eventId,
      organizationId: input.organizationId,
      eventType: EventTypes.NotificationAlertRequested,
      aggregateType: 'organization',
      aggregateId: input.organizationId.toString(),
      correlationId: input.correlationId,
      payload,
    },
    select: { id: true },
  });
  await tx.$executeRaw`
    UPDATE notification_alert_windows SET alert_event_id = ${eventId}
    WHERE organization_id = ${input.organizationId} AND kind = ${input.kind}
      AND scope_key = ${input.scopeKey} AND window_start = ${window.from}`;
  return { result: 'requested', eventId };
}
