import { NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { encodeCursor } from '../../../http/pagination';
import type {
  DeliveriesRepository,
  DeliveryEventRow,
  DeliveryMessageRow,
  DeliveryRow,
  RecipientRow,
} from '../repositories/deliveries.repository';
import { DeliveriesService } from './deliveries.service';

const scope = systemScope(3n);
const receivedAt = new Date('2026-11-03T08:00:00.000Z');
const message: DeliveryMessageRow = {
  id: 100n,
  publicId: '0195f3c1-7a2b-7c3d-8e4f-000000000100',
  receivedAt,
  direction: 'outbound',
  status: 'delivered',
  statusReason: 'delivery_partial',
};

const recipient = (id: bigint, rcptSeq: number, address: string): RecipientRow => ({
  id,
  receivedAt,
  rcptSeq,
  address,
  direction: 'outbound',
});

const delivery = (
  id: bigint,
  recipientId: bigint,
  overrides: Partial<DeliveryRow> = {},
): DeliveryRow => ({
  id,
  receivedAt,
  messageId: 100n,
  recipientId,
  deliverySeq: 0,
  direction: null,
  status: 'delivered',
  attemptCount: 1,
  lastAttemptAt: receivedAt,
  deliveredAt: receivedAt,
  remoteHost: 'mx.example',
  finalSmtpCode: 250,
  enhancedStatus: '2.0.0',
  finalSmtpResponse: '250 2.0.0 Ok',
  lastErrorClass: null,
  failureReason: null,
  dsnQueueId: null,
  statusChangedAt: receivedAt,
  ...overrides,
});

const event = (
  id: bigint,
  deliveryId: bigint,
  toStatus: DeliveryEventRow['toStatus'],
): DeliveryEventRow => ({
  id,
  deliveryId,
  source: 'postfix_log',
  fromStatus: 'queued',
  toStatus,
  applied: true,
  occurredAt: receivedAt,
  queueId: 'QID1',
  smtpCode: 250,
  enhancedStatus: '2.0.0',
  remoteHost: 'mx.example',
  errorClass: null,
  detail: null,
});

function harness(found: DeliveryMessageRow | null = message) {
  const recipients = [recipient(1n, 0, 'a@x.test'), recipient(2n, 1, 'b@y.test')];
  const repository = {
    findMessage: vi.fn(() => Promise.resolve(found)),
    deliveriesOf: vi.fn(() =>
      Promise.resolve([
        delivery(12n, 2n, { status: 'bounced', dsnQueueId: 'DSN1', direction: 'outbound' }),
        delivery(11n, 1n),
        delivery(99n, 999n),
      ]),
    ),
    recipientsOf: vi.fn((_s: unknown, _m: unknown, rcptSeq?: number) =>
      Promise.resolve(recipients.filter((r) => rcptSeq === undefined || r.rcptSeq === rcptSeq)),
    ),
    eventsOf: vi.fn(() =>
      Promise.resolve([
        event(5n, 11n, 'delivered'),
        event(6n, 12n, 'bounced'),
        event(7n, 12n, 'bounced'),
      ]),
    ),
    list: vi.fn(() => Promise.resolve([delivery(12n, 2n), delivery(11n, 1n), delivery(10n, 1n)])),
    recipientsByIds: vi.fn(() => Promise.resolve(recipients)),
    messagePublicIds: vi.fn(() => Promise.resolve(new Map([[100n, message.publicId]]))),
  };
  return {
    service: new DeliveriesService(repository as unknown as DeliveriesRepository),
    repository,
  };
}

describe('DeliveriesService', () => {
  it('returns every delivery of the message by rcptSeq, without internal ids', async () => {
    const h = harness();
    const view = await h.service.forMessage(scope, message.publicId);
    expect(view.message).toEqual({
      id: message.publicId,
      direction: 'outbound',
      status: 'delivered',
      statusReason: 'delivery_partial',
      receivedAt: receivedAt.toISOString(),
    });
    expect(
      view.deliveries.map((d) => [d.rcptSeq, d.recipient, d.status, d.dsnGenerated, d.direction]),
    ).toEqual([
      [0, 'a@x.test', 'delivered', false, 'outbound'],
      [1, 'b@y.test', 'bounced', true, 'outbound'],
    ]);
    expect(JSON.stringify(view)).not.toMatch(/"id":"?1[12]\b|recipientId|deliveryId/);
  });

  it('404 for a message that is not the organization’s', async () => {
    const h = harness(null);
    await expect(h.service.forMessage(scope, message.publicId)).rejects.toBeInstanceOf(
      NotFoundException,
    );
    await expect(h.service.events(scope, message.publicId, { limit: 25 })).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });

  it('pages the audit trail oldest first and filters by rcptSeq', async () => {
    const h = harness();
    const page = await h.service.events(scope, message.publicId, { limit: 2 });
    expect(page.data.map((e) => [e.rcptSeq, e.toStatus])).toEqual([
      [0, 'delivered'],
      [1, 'bounced'],
    ]);
    expect(page.nextCursor).toBe(encodeCursor(6n));
    expect(h.repository.eventsOf).toHaveBeenCalledWith(scope, message, { take: 3 });

    await h.service.events(scope, message.publicId, {
      limit: 2,
      rcptSeq: 1,
      cursor: encodeCursor(6n),
    });
    expect(h.repository.eventsOf).toHaveBeenLastCalledWith(scope, message, {
      take: 3,
      afterId: 6n,
      deliveryIds: [12n],
    });
    h.repository.eventsOf.mockClear();
    const none = await h.service.events(scope, message.publicId, { limit: 2, rcptSeq: 9 });
    expect(none).toEqual({ data: [], nextCursor: null });
    expect(h.repository.eventsOf).not.toHaveBeenCalled();
  });

  it('lists deliveries in a range with a keyset cursor', async () => {
    const h = harness();
    const page = await h.service.list(scope, {
      from: '2026-11-03T00:00:00Z',
      to: '2026-11-03T12:00:00Z',
      status: 'delivered',
      direction: 'outbound',
      limit: 2,
    });
    expect(page.data.map((d) => [d.messageId, d.rcptSeq, d.recipient])).toEqual([
      [message.publicId, 1, 'b@y.test'],
      [message.publicId, 0, 'a@x.test'],
    ]);
    expect(page.nextCursor).not.toBeNull();
    expect(h.repository.list).toHaveBeenCalledWith(
      scope,
      {
        from: new Date('2026-11-03T00:00:00Z'),
        to: new Date('2026-11-03T12:00:00Z'),
        status: 'delivered',
        direction: 'outbound',
      },
      { take: 3 },
    );
    await h.service.list(scope, { limit: 2, cursor: page.nextCursor! });
    expect(h.repository.list).toHaveBeenLastCalledWith(scope, expect.anything(), {
      take: 3,
      after: { receivedAt, id: 11n },
    });
  });
});
