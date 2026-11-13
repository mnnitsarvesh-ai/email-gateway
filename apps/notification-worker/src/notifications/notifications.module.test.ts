import { NonRetryableError } from '@email-gateway/common';
import { type EventEnvelope, EventTypes } from '@email-gateway/event-contracts';
import { describe, expect, it, vi } from 'vitest';
import {
  dispatchNotification,
  NOTIFICATION_EVENT_TYPES,
  type NotificationPayload,
} from './notifications.module';

const tx = {} as never;
const envelope = (eventType: string) =>
  ({
    eventId: '0190f0f0-0000-7000-8000-00000000e401',
    eventType,
    occurredAt: '2026-11-13T09:00:00.000Z',
    correlationId: 'corr-12345678',
    organizationId: '7',
    payload: {},
  }) as unknown as EventEnvelope<NotificationPayload>;

describe('dispatchNotification (email.notifications, dispatch by event type)', () => {
  const handlers = () => ({
    policy: { handle: vi.fn(() => Promise.resolve('sent' as const)) },
    quarantine: { handle: vi.fn(() => Promise.resolve('sent' as const)) },
    alert: { handle: vi.fn(() => Promise.resolve('sent' as const)) },
  });

  it('consumes the three event types of the queue', () => {
    expect([...NOTIFICATION_EVENT_TYPES]).toEqual([
      'mail.policy.notification_requested.v1',
      'mail.quarantine.notification_requested.v1',
      'notification.alert_requested.v1',
    ]);
  });

  it.each([
    [EventTypes.PolicyNotificationRequested, 'policy'],
    [EventTypes.QuarantineNotificationRequested, 'quarantine'],
    [EventTypes.NotificationAlertRequested, 'alert'],
  ] as const)('%s → the %s handler only', async (type, target) => {
    const h = handlers();
    const e = envelope(type);
    await dispatchNotification(h, e, tx);
    for (const [name, handler] of Object.entries(h)) {
      if (name === target) expect(handler.handle).toHaveBeenCalledWith(e, tx);
      else expect(handler.handle).not.toHaveBeenCalled();
    }
  });

  it('dead-letters an unexpected event type', async () => {
    await expect(
      dispatchNotification(handlers(), envelope('mail.message.received.v1'), tx),
    ).rejects.toBeInstanceOf(NonRetryableError);
  });
});
