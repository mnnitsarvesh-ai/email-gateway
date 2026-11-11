import { MetricsService, NonRetryableError } from '@email-gateway/common';
import type { DeliveryApprovedV1, EventEnvelope } from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import {
  lockLifecycle,
  transitionMessage,
  type LifecycleSnapshot,
} from '@email-gateway/message-lifecycle';
import type * as Lifecycle from '@email-gateway/message-lifecycle';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DeliveryMetrics } from '../metrics/delivery-metrics';
import { approvalObjectLabel, DeliveryPlanner } from './delivery-planner';

vi.mock('@email-gateway/message-lifecycle', async (original) => ({
  ...(await original<typeof Lifecycle>()),
  lockLifecycle: vi.fn(),
  transitionMessage: vi.fn(),
}));
const lock = vi.mocked(lockLifecycle);
const transition = vi.mocked(transitionMessage);
beforeEach(() => {
  lock.mockReset();
  transition.mockReset();
});

const planner = (metrics = new DeliveryMetrics(new MetricsService({ service: 't' }))) =>
  new DeliveryPlanner({
    logger: createLogger({ service: 't', level: 'silent' }),
    metrics,
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

describe('DeliveryPlanner lifecycle rule (step 3.3 L8.4)', () => {
  const snapshot = (state: LifecycleSnapshot['state'], round = 0): LifecycleSnapshot => ({
    state,
    version: 3,
    round,
    statusChangedAt: new Date('2026-11-03T11:30:00.000Z'),
    statusReason: null,
    direction: 'outbound',
    emlObjectKey: 'org/7/eml/x.eml',
  });
  /** Reaches the lifecycle check; every recipient already has a delivery (a duplicate). */
  const planningTx = (event = approval()) => ({
    ...tx(
      { id: 100n, direction: 'outbound' },
      [{ id: 500n, rcptSeq: 0, address: 'a@ext.test', direction: 'outbound' }],
      issued(event.payload),
    ),
    emailDelivery: { findMany: vi.fn(() => Promise.resolve([{ recipientId: 500n }])) },
  });

  it('moves an approved message of the approval round to delivery_pending, then plans', async () => {
    lock.mockResolvedValue(snapshot('approved'));
    transition.mockResolvedValue({
      result: 'applied',
      from: 'approved',
      to: 'delivery_pending',
      version: 4,
      round: 0,
      historyId: 1n,
      stateEventId: '0190f0f0-0000-7000-8000-0000000000bb',
      snapshot: snapshot('delivery_pending'),
    });
    const t = planningTx();
    const event = approval();
    expect(await planner().plan(event, t as never)).toMatchObject({ status: 'duplicate' });
    expect(lock).toHaveBeenCalledWith(t, {
      id: 100n,
      receivedAt: new Date('2026-11-03T11:00:00.000Z'),
      organizationId: 7n,
    });
    expect(transition.mock.calls[0]![1]).toMatchObject({
      to: 'delivery_pending',
      reason: 'delivery_planned',
      actor: { role: 'delivery', service: 'delivery-worker', type: 'system' },
      transitionKey: `evt:${event.eventId}:delivery_pending`,
      causationEventId: event.eventId,
      correlationId: event.correlationId,
      expectedRound: 0,
      expectedFrom: ['approved'],
    });
    expect(t.emailDelivery.findMany).toHaveBeenCalled();
  });

  it('plans a later chunk while delivery_pending or delivery_retry of the same round, without a transition', async () => {
    for (const state of ['delivery_pending', 'delivery_retry'] as const) {
      lock.mockResolvedValueOnce(snapshot(state, 2));
      const event = approval({ lifecycleRound: 2 });
      const t = planningTx(event);
      expect(await planner().plan(event, t as never)).toMatchObject({ status: 'duplicate' });
      expect(t.emailDelivery.findMany).toHaveBeenCalled();
    }
    expect(transition).not.toHaveBeenCalled();
  });

  it('rejects approvals of another round or of a message that is not approved (lifecycle_state)', async () => {
    const service = new MetricsService({ service: 't' });
    const metrics = new DeliveryMetrics(service);
    const cases: [LifecycleSnapshot | null, number | undefined][] = [
      [snapshot('approved', 1), 0], // an older round's approval after a release
      [snapshot('approved', 1), undefined], // absent = round 0
      [snapshot('approved', 0), 1], // a future round (forged or a bug)
      [snapshot('delivery_pending', 1), 0],
      [snapshot('persisted'), 0],
      [snapshot('quarantined'), 0],
      [snapshot('delivered'), 0],
      [snapshot('expired'), 0],
      [null, 0], // locked row gone or another organization
    ];
    for (const [snap, round] of cases) {
      lock.mockResolvedValueOnce(snap);
      const event = approval(round === undefined ? {} : { lifecycleRound: round });
      const t = planningTx(event);
      expect(await planner(metrics).plan(event, t as never)).toMatchObject({
        status: 'rejected',
        reason: 'lifecycle_state',
        deliveries: 0,
      });
      expect(t.emailDelivery.findMany).not.toHaveBeenCalled();
    }
    expect(transition).not.toHaveBeenCalled();
    expect(await service.metrics()).toContain(
      `delivery_approvals_rejected_total{reason="lifecycle_state",service="t"} ${cases.length}`,
    );
  });

  it('does not plan when the transition is refused under the lock', async () => {
    lock.mockResolvedValue(snapshot('approved'));
    transition.mockResolvedValue({
      result: 'duplicate',
      why: 'transition_key',
      snapshot: snapshot('approved'),
    });
    const t = planningTx();
    expect(await planner().plan(approval(), t as never)).toMatchObject({
      status: 'rejected',
      reason: 'lifecycle_state',
    });
    expect(t.emailDelivery.findMany).not.toHaveBeenCalled();
  });
});

describe('approvalObjectLabel (delivery_approvals_total{object}, step 4.3 U20, step 5.2 P14)', () => {
  it('labels rewritten copies, policy copies and originals by the organization prefix', () => {
    expect(approvalObjectLabel('org/7/rewrite/2026/11/03/100/r0-ab.eml', 7n)).toBe('rewritten');
    expect(approvalObjectLabel('org/7/policy/2026/11/03/100/r0-cd.eml', 7n)).toBe('policy_copy');
    expect(approvalObjectLabel('org/7/eml/2026/11/03/x.eml', 7n)).toBe('original');
    // Another organization's prefix (the planner refuses such keys) or a look-alike segment.
    expect(approvalObjectLabel('org/8/policy/2026/11/03/100/r0-cd.eml', 7n)).toBe('original');
    expect(approvalObjectLabel('org/70/policy/x.eml', 7n)).toBe('original');
    expect(approvalObjectLabel('org/7/policyx/x.eml', 7n)).toBe('original');
  });
});
