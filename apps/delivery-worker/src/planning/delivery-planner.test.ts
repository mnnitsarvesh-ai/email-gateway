import { MetricsService, NonRetryableError } from '@email-gateway/common';
import type { DeliveryApprovedV1, EventEnvelope } from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import { describe, expect, it, vi } from 'vitest';
import { DeliveryMetrics } from '../metrics/delivery-metrics';
import { DeliveryPlanner } from './delivery-planner';

const planner = () =>
  new DeliveryPlanner({
    logger: createLogger({ service: 't', level: 'silent' }),
    metrics: new DeliveryMetrics(new MetricsService({ service: 't' })),
    config: {
      DELIVERY_BATCH_MAX_RECIPIENTS: 100,
      DELIVERY_REINJECT_RETRY_BASE_SECONDS: 30,
      DELIVERY_REINJECT_RETRY_MAX_SECONDS: 900,
    },
    recorderTimeoutMs: 15_000,
  });

const approval = (
  overrides: Partial<DeliveryApprovedV1> = {},
  organizationId = '7',
): EventEnvelope<DeliveryApprovedV1> => ({
  eventId: '0190f0f0-0000-7000-8000-000000000001',
  eventType: 'mail.delivery.approved.v1',
  occurredAt: '2026-11-03T12:00:00.000Z',
  correlationId: 'corr-12345678',
  organizationId,
  payload: {
    messageId: '100',
    receivedAt: '2026-11-03T11:00:00.000Z',
    deliverySeq: 0,
    source: 'policy',
    emlS3Key: 'org/7/eml/x.eml',
    recipients: [{ recipientId: '500', rcptSeq: 0 }],
    approvedAt: '2026-11-03T12:00:00.000Z',
    ...overrides,
  },
});

/** The approval's outbox row (provenance): by default the one the gateway wrote for `approval()`. */
const issued = (payload: unknown = approval().payload) => ({ payload });

const tx = (message: unknown, recipients: unknown[] = [], outbox: unknown = issued()) => ({
  messageOutbox: { findFirst: vi.fn(() => Promise.resolve(outbox)) },
  emailMessage: { findFirst: vi.fn(() => Promise.resolve(message)) },
  emailRecipient: { findMany: vi.fn(() => Promise.resolve(recipients)) },
});

describe('DeliveryPlanner approval provenance (review round 1)', () => {
  it('dead-letters an approval without an outbox row (forged on the broker) before planning anything', async () => {
    const t = tx({ id: 100n, direction: 'outbound' }, [], null);
    const error = await planner()
      .plan(approval(), t as never)
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(NonRetryableError);
    expect((error as NonRetryableError).code).toBe('approval_not_issued');
    expect(t.messageOutbox.findFirst).toHaveBeenCalledWith({
      where: {
        eventId: approval().eventId,
        eventType: 'mail.delivery.approved.v1',
        organizationId: 7n,
        createdAt: { gte: new Date(Date.parse('2026-11-03T11:00:00.000Z') - 5 * 60_000) },
      },
      select: { payload: true },
    });
    expect(t.emailRecipient.findMany).not.toHaveBeenCalled();
  });

  it('dead-letters a real event id carrying another payload (approval_mismatch)', async () => {
    const t = tx({ id: 100n, direction: 'outbound' }, [], issued());
    for (const forged of [
      approval({ recipients: [{ recipientId: '501', rcptSeq: 0 }] }),
      approval({ messageId: '101' }),
      approval({ deliverySeq: 1 }),
    ]) {
      const error = await planner()
        .plan(forged, t as never)
        .catch((e: unknown) => e);
      expect((error as NonRetryableError).code).toBe('approval_mismatch');
    }
    const stored = tx({ id: 100n, direction: 'outbound' }, [], issued({ not: 'an approval' }));
    const error = await planner()
      .plan(approval(), stored as never)
      .catch((e: unknown) => e);
    expect((error as NonRetryableError).code).toBe('approval_mismatch');
    expect(t.emailRecipient.findMany).not.toHaveBeenCalled();
  });

  it('acknowledges an approval of a message that no longer exists as rejected, without a provenance lookup', async () => {
    const t = tx(null, [], null);
    expect(await planner().plan(approval(), t as never)).toMatchObject({
      status: 'rejected',
      reason: 'message_not_found',
    });
    expect(t.messageOutbox.findFirst).not.toHaveBeenCalled();
  });

  it('plans an approval whose outbox row matches (a replay keeps the event id and payload)', async () => {
    // Passes provenance and reaches the recipient lookup (none known here).
    const t = tx({ id: 100n, direction: 'outbound' }, []);
    expect(await planner().plan(approval(), t as never)).toMatchObject({
      status: 'rejected',
      reason: 'no_known_recipients',
    });
    expect(t.messageOutbox.findFirst).toHaveBeenCalled();
    expect(t.emailRecipient.findMany).toHaveBeenCalled();
  });
});

describe('DeliveryPlanner (R7) trust checks', () => {
  it('rejects an EML key outside the organization prefix before reading anything', async () => {
    const t = tx({ id: 100n, direction: 'outbound' });
    for (const key of ['org/8/eml/x.eml', 'org/77/eml/x.eml']) {
      expect(await planner().plan(approval({ emlS3Key: key }), t as never)).toMatchObject({
        status: 'rejected',
        reason: 'eml_key_prefix',
      });
    }
    expect(t.emailMessage.findFirst).not.toHaveBeenCalled();
  });

  it('loads the message with the envelope organization and rejects a foreign message', async () => {
    const foreign = approval({ emlS3Key: 'org/9/eml/x.eml' }, '9');
    const t = tx(null, [], issued(foreign.payload));
    const result = await planner().plan(foreign, t as never);
    expect(result).toMatchObject({ status: 'rejected', reason: 'message_not_found' });
    expect(t.emailMessage.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 100n, receivedAt: new Date('2026-11-03T11:00:00.000Z'), organizationId: 9n },
      }),
    );
  });

  it('skips recipient ids that are unknown for the message and organization', async () => {
    const t = tx({ id: 100n, direction: 'outbound' }, []);
    const result = await planner().plan(approval(), t as never);
    expect(result).toMatchObject({
      status: 'rejected',
      reason: 'no_known_recipients',
      unknownRecipients: 1,
    });
    expect(t.emailRecipient.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: { in: [500n] },
          receivedAt: new Date('2026-11-03T11:00:00.000Z'),
          messageId: 100n,
          organizationId: 7n,
        },
      }),
    );
  });
});
