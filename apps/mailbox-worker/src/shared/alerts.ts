import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import {
  EventTypes,
  notificationAlertRequestedV1,
  type NotificationAlertRequestedV1,
} from '@email-gateway/event-contracts';

/** The throttle window `{ from, to }` containing `at` (the webhook-worker's N2 rule). */
export function alertWindow(at: Date, minutes: number): { from: Date; to: Date } {
  const size = minutes * 60_000;
  const from = new Date(Math.floor(at.getTime() / size) * size);
  return { from, to: new Date(from.getTime() + size) };
}

export interface AlertRequest {
  organizationId: bigint;
  kind: NotificationAlertRequestedV1['kind'];
  /** `notification_alert_windows.scope_key` (≤ 64): a public id or a fixed scope name. */
  scopeKey: string;
  windowMinutes: number;
  severity: NotificationAlertRequestedV1['severity'];
  refs: NotificationAlertRequestedV1['refs'];
  correlationId: string;
  now: Date;
}

/**
 * A throttled `notification.alert_requested.v1` (step 6.2 N2, as the health role's
 * `api_mode_unhealthy`): counts the event in its `notification_alert_windows` row (organization,
 * kind, scope, window) and, for the first event of the window only, writes the outbox row
 * (aggregate `organization`) in the caller's transaction. True when the alert was requested.
 * Content-free: refs are public ids only.
 */
export async function requestThrottledAlert(
  tx: Prisma.TransactionClient,
  input: AlertRequest,
): Promise<boolean> {
  const window = alertWindow(input.now, input.windowMinutes);
  const sourceEventId = uuidv7(input.now.getTime());
  const scope = input.scopeKey.slice(0, 64);
  const affected = await tx.$executeRaw`
    INSERT INTO notification_alert_windows
      (organization_id, kind, scope_key, window_start, event_count, first_source_event_id,
       created_at, updated_at)
    VALUES (${input.organizationId}, ${input.kind}, ${scope}, ${window.from}, 1,
            ${sourceEventId}, NOW(3), NOW(3))
    ON DUPLICATE KEY UPDATE event_count = event_count + 1, updated_at = NOW(3)`;
  // MySQL: 1 = inserted (first event of the window), 2 = an existing window was counted.
  if (affected !== 1) return false;
  const previous = await tx.$queryRaw<Array<{ event_count: number | bigint }>>`
    SELECT event_count FROM notification_alert_windows
    WHERE organization_id = ${input.organizationId} AND kind = ${input.kind}
      AND scope_key = ${scope}
      AND window_start = ${new Date(window.from.getTime() - input.windowMinutes * 60_000)}`;
  const suppressedBefore = Math.max(0, Number(previous[0]?.event_count ?? 0) - 1);
  const eventId = uuidv7(input.now.getTime());
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
      correlationId: input.correlationId.slice(0, 128),
      payload,
    },
    select: { id: true },
  });
  await tx.$executeRaw`
    UPDATE notification_alert_windows SET alert_event_id = ${eventId}
    WHERE organization_id = ${input.organizationId} AND kind = ${input.kind}
      AND scope_key = ${scope} AND window_start = ${window.from}`;
  return true;
}
