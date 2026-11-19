/**
 * The step 8.4 webhook types through the real fanout against the MySQL writer (D16, §10.4):
 * `security.incident.created.v1`, `security.incident.updated.v1`, `ato.account.risk.updated.v1`
 * and `ato.response.completed.v1` envelopes handled by `FanoutService` (no broker needed: the
 * service is driven directly, as the consumer would) for an organization with subscriptions to
 * the four public types. Each yields one stored public event (strict schema, payload guard: no
 * address, IP or name) and one pending delivery; `minSeverity` filters apply; the account kind of
 * a response is read on the writer and echo-checked; another organization's subscription is never
 * matched; a redelivery is a duplicate (ledger).
 */
import { MetricsService, uuidv7 } from '@email-gateway/common';
import {
  type EventEnvelope,
  EventTypes,
  EXAMPLE_EVENT_PAYLOADS,
} from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import { parseStoredEnvelope } from '@email-gateway/webhooks';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FanoutReads } from '../src/fanout/facts';
import { FanoutService, PendingCounts } from '../src/fanout/fanout.service';
import { SubscriptionIndex } from '../src/fanout/subscription-index';
import { WebhookMetrics } from '../src/metrics/webhook-metrics';
import { Fixtures } from './support/fixtures';

const fx = new Fixtures();
const logger = createLogger({ service: 'webhook-worker-it', level: 'silent' });
const CONSUMER = `it-ato-fanout-${fx.suffix}`;
let service: FanoutService;
let org: { id: bigint; publicId: string };
let other: { id: bigint; publicId: string };
let account: { id: bigint; publicId: string };
const TYPES = [
  'security.incident.created',
  'security.incident.updated',
  'ato.account.risk_changed',
  'ato.response.completed',
];

function envelope(
  eventType: string,
  organizationId: bigint,
  overrides: Record<string, unknown> = {},
): EventEnvelope<unknown> {
  return {
    eventId: fx.track(uuidv7()),
    eventType,
    occurredAt: new Date().toISOString(),
    correlationId: `it-${fx.suffix}`,
    organizationId: organizationId.toString(),
    payload: { ...(EXAMPLE_EVENT_PAYLOADS as Record<string, object>)[eventType], ...overrides },
  };
}

beforeAll(async () => {
  org = await fx.organization('ato');
  other = await fx.organization('ato-other');
  const row = await fx.prisma.atoAccount.create({
    data: {
      organizationId: org.id,
      kind: 'smtp_connector',
      subjectHash: randomBytes(32).toString('hex'),
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    },
    select: { id: true, publicId: true },
  });
  account = row;
  await fx.subscription(org.id, { url: 'https://hooks.receiver.test/ato', eventTypes: TYPES });
  await fx.subscription(org.id, {
    url: 'https://hooks.receiver.test/high',
    eventTypes: ['security.incident.created'],
    filters: { minSeverity: 'high' },
  });
  await fx.subscription(other.id, { url: 'https://hooks.receiver.test/other', eventTypes: TYPES });
  const metrics = new WebhookMetrics(new MetricsService({ service: 'webhook-worker-it' }));
  const sink = () => undefined;
  service = new FanoutService({
    prisma: fx.prisma,
    index: new SubscriptionIndex(fx.prisma, 0, sink, logger),
    reads: new FanoutReads(sink),
    pending: new PendingCounts(10_000),
    metrics,
    logger,
    txTimeoutMs: 30_000,
    consumer: CONSUMER,
  });
});

afterAll(async () => {
  await fx.prisma.messageIdempotency.deleteMany({ where: { consumer: CONSUMER } });
  await fx.prisma.atoAccount.deleteMany({ where: { organizationId: { in: fx.organizationIds } } });
  await fx.cleanup();
});

const storedOf = async (sourceEventId: string) =>
  fx.prisma.webhookEvent.findMany({ where: { organizationId: org.id, sourceEventId } });

describe('ATO and incident webhooks (D16)', () => {
  it('each source event yields its public event and a delivery per matching subscription of the organization only', async () => {
    const cases: Array<[string, string, Record<string, unknown>]> = [
      [EventTypes.SecurityIncidentCreated, 'security.incident.created', { severity: 'critical' }],
      [EventTypes.SecurityIncidentUpdated, 'security.incident.updated', {}],
      [EventTypes.AtoAccountRiskUpdated, 'ato.account.risk_changed', {}],
      [
        EventTypes.AtoResponseCompleted,
        'ato.response.completed',
        { accountPublicId: account.publicId },
      ],
    ];
    for (const [source, type, overrides] of cases) {
      const e = envelope(source, org.id, overrides);
      await expect(service.handle(e)).resolves.toBe('handled');
      const stored = await storedOf(e.eventId);
      expect(stored, type).toHaveLength(1);
      expect(stored[0]!.eventType).toBe(type);
      const env = parseStoredEnvelope(stored[0]!.payloadJson);
      expect(env.type).toBe(type);
      expect(env.organizationId).toBe(org.publicId);
      const json = JSON.stringify(env.data);
      expect(json).not.toMatch(/@|\b\d{1,3}(\.\d{1,3}){3}\b/);
      const deliveries = await fx.prisma.webhookDelivery.findMany({ where: { eventId: env.id } });
      expect(deliveries.every((d) => d.organizationId === org.id)).toBe(true);
      expect(deliveries.length, type).toBe(type === 'security.incident.created' ? 2 : 1);
      if (type === 'ato.response.completed') {
        expect((env.data as { account: { kind: string } }).account.kind).toBe('smtp_connector');
      }
      expect(await service.handle(e)).toBe('duplicate');
    }
    expect(await fx.prisma.webhookEvent.count({ where: { organizationId: other.id } })).toBe(0);
  });

  it('minSeverity: a medium incident reaches only the unfiltered subscription', async () => {
    const e = envelope(EventTypes.SecurityIncidentCreated, org.id, { severity: 'medium' });
    await service.handle(e);
    const [stored] = await storedOf(e.eventId);
    expect(stored!.severity).toBe('medium');
    expect(await fx.prisma.webhookDelivery.count({ where: { eventId: stored!.eventId } })).toBe(1);
  });

  it('a response of an account of another organization is refused (echo-checked read)', async () => {
    const e = envelope(EventTypes.AtoResponseCompleted, other.id, {
      accountPublicId: account.publicId,
    });
    await expect(service.handle(e)).rejects.toThrow();
    expect(await fx.prisma.webhookEvent.count({ where: { organizationId: other.id } })).toBe(0);
  });
});
