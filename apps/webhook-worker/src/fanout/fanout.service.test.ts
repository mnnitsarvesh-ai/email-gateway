import { NonRetryableError } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { EventTypes, notificationAlertRequestedV1 } from '@email-gateway/event-contracts';
import {
  NOTIFICATION_SETTINGS_DEFAULTS,
  type ResolvedNotificationSettings,
  webhookEventId,
} from '@email-gateway/webhooks';
import { describe, expect, it } from 'vitest';
import { InconsistentReadError } from '../shared/errors';
import {
  fakeFacts,
  ORG_ID,
  ORG_PUBLIC_ID,
  type SeenSql,
  silentLogger,
  sourceEvent,
  sqlOf,
  testMetrics,
} from '../worker.test-support';
import type { FactsSource } from './builders';
import type { FanoutReads } from './facts';
import { FanoutService, PendingCounts } from './fanout.service';
import type {
  IndexedSubscription,
  OrganizationIndex,
  SubscriptionIndex,
} from './subscription-index';

const SUB = (overrides: Partial<IndexedSubscription> = {}): IndexedSubscription => ({
  id: 501n,
  publicId: '01890a5d-ac96-774b-bcce-b3020990b501',
  eventTypes: ['email.received'],
  filters: null,
  createdAt: new Date('2026-10-01T00:00:00.000Z'),
  ...overrides,
});

function orgIndex(overrides: Partial<OrganizationIndex> = {}): OrganizationIndex {
  return {
    organizationId: ORG_ID,
    publicId: ORG_PUBLIC_ID,
    organizationActive: true,
    webhooksEnabled: true,
    subscriptions: [SUB()],
    settings: structuredClone(NOTIFICATION_SETTINGS_DEFAULTS),
    settingsInvalid: false,
    ...overrides,
  };
}

interface Harness {
  service: FanoutService;
  statements: SeenSql[];
  outbox: Array<Record<string, unknown>>;
  transactions: number;
  indexCalls: bigint[];
  metrics: ReturnType<typeof testMetrics>;
}

function harness(
  options: {
    index?: OrganizationIndex | null;
    facts?: FactsSource;
    ledger?: Set<string>;
    windowInsert?: number;
    pendingCount?: number;
    maxPending?: number;
  } = {},
): Harness {
  const statements: SeenSql[] = [];
  const outbox: Array<Record<string, unknown>> = [];
  const ledger = options.ledger ?? new Set<string>();
  const h = { statements, outbox, transactions: 0, indexCalls: [] as bigint[] } as Harness;
  const tx = {
    messageIdempotency: {
      create: ({ data }: { data: { consumer: string; eventId: string } }) => {
        const key = `${data.consumer}|${data.eventId}`;
        if (ledger.has(key)) {
          return Promise.reject(
            new Prisma.PrismaClientKnownRequestError('duplicate', {
              code: 'P2002',
              clientVersion: 'test',
            }),
          );
        }
        ledger.add(key);
        return Promise.resolve({});
      },
    },
    $executeRaw: (first: unknown, ...rest: unknown[]) => {
      const s = sqlOf(first, rest);
      statements.push(s);
      if (s.text.startsWith('INSERT INTO notification_alert_windows')) {
        return Promise.resolve(options.windowInsert ?? 1);
      }
      return Promise.resolve(1);
    },
    $queryRaw: (first: unknown, ...rest: unknown[]) => {
      const s = sqlOf(first, rest);
      statements.push(s);
      if (s.text.includes('COUNT(*)')) return Promise.resolve([{ n: options.pendingCount ?? 0 }]);
      return Promise.resolve([]);
    },
    messageOutbox: {
      create: ({ data }: { data: Record<string, unknown> }) => {
        outbox.push(data);
        return Promise.resolve({ id: 1n });
      },
    },
  };
  const prisma = {
    $transaction: (fn: (t: typeof tx) => Promise<unknown>) => {
      h.transactions += 1;
      return fn(tx);
    },
  };
  const facts = options.facts ?? fakeFacts();
  const reads = {
    message: (_tx: unknown, key: never) => facts.message(key),
    scanReasonCodes: (_tx: unknown, key: never, id: never) => facts.scanReasonCodes(key, id),
    executionLog: (_tx: unknown, key: never, round: never) => facts.executionLog(key, round),
    quarantineEntries: (_tx: unknown, k: never, r: never, o: never) =>
      facts.quarantineEntries(k, r, o),
    release: (_tx: unknown, k: never, s: never) => facts.release(k, s),
    recipientOutcomes: (_tx: unknown, k: never) => facts.recipientOutcomes(k),
    sandboxSubmission: (_tx: unknown, k: never, id: never) => facts.sandboxSubmission(k, id),
    domain: (_tx: unknown, o: never, id: never, p: never) => facts.domain(o, id, p),
  } as unknown as FanoutReads;
  const index = {
    get: (organizationId: bigint) => {
      h.indexCalls.push(organizationId);
      return Promise.resolve(options.index === undefined ? orgIndex() : options.index);
    },
  } as unknown as SubscriptionIndex;
  h.metrics = testMetrics();
  h.service = new FanoutService({
    prisma: prisma as never,
    index,
    reads,
    pending: new PendingCounts(options.maxPending ?? 1000),
    metrics: h.metrics.metrics,
    logger: silentLogger,
    txTimeoutMs: 120_000,
    now: () => new Date('2026-11-01T10:15:40.000Z'),
  });
  return h;
}

const inserts = (h: Harness, table: string) =>
  h.statements.filter((s) => s.text.startsWith(`INSERT INTO ${table}`));

const counter = async (h: Harness, name: string): Promise<string> =>
  (await h.metrics.registry.metrics())
    .split('\n')
    .filter((l) => l.startsWith(name))
    .join('\n');

describe('FanoutService (W1, W3, W5, N2)', () => {
  it('acks without a transaction or ledger row when nothing matches and no alert is due', async () => {
    const h = harness({
      index: orgIndex({ subscriptions: [SUB({ eventTypes: ['email.scanned'] })] }),
    });
    await expect(h.service.handle(sourceEvent(EventTypes.MessageReceived))).resolves.toBe(
      'handled',
    );
    expect(h.transactions).toBe(0);
    expect(await counter(h, 'webhook_fanout_events_total')).toContain('result="noop"');
  });

  it('skips organizations without the webhooks feature (alerts still apply)', async () => {
    const h = harness({ index: orgIndex({ webhooksEnabled: false }) });
    await h.service.handle(sourceEvent(EventTypes.MessageReceived));
    expect(h.transactions).toBe(0);
  });

  it('skips organizations that are not active (suspended, pending deletion, deleted)', async () => {
    const h = harness({ index: orgIndex({ organizationActive: false }) });
    await h.service.handle(sourceEvent(EventTypes.MessageReceived));
    expect(h.transactions).toBe(0);
  });

  it('never delivers an event to a subscription created after it occurred', async () => {
    const h = harness({
      index: orgIndex({
        subscriptions: [SUB({ createdAt: new Date('2026-11-01T10:15:33.000Z') })],
      }),
    });
    await h.service.handle(sourceEvent(EventTypes.MessageReceived));
    expect(h.transactions).toBe(0);
  });

  it('only asks the index of the envelope organization', async () => {
    const h = harness();
    await h.service.handle(sourceEvent(EventTypes.MessageReceived, {}, { organizationId: '777' }));
    expect(h.indexCalls).toEqual([777n]);
  });

  it('projects a matching event: one event row and one pending delivery in the ledger transaction', async () => {
    const h = harness();
    const event = sourceEvent(EventTypes.MessageReceived);
    await expect(h.service.handle(event)).resolves.toBe('handled');
    expect(h.transactions).toBe(1);
    const [row] = inserts(h, 'webhook_events');
    const eventId = webhookEventId(event.eventId, 'email.received', '');
    expect(row?.values).toContain(eventId);
    expect(row?.values).toContain(ORG_ID);
    expect(row?.values).toContain('mail.message.received.v1');
    const json = row?.values.find((v) => typeof v === 'string' && v.startsWith('{')) as string;
    expect(JSON.parse(json)).toMatchObject({
      id: eventId,
      type: 'email.received',
      version: 1,
      occurredAt: '2026-11-01T10:15:32.000Z',
      organizationId: ORG_PUBLIC_ID,
    });
    const [delivery] = inserts(h, 'webhook_deliveries');
    expect(delivery?.values).toEqual(
      expect.arrayContaining([501n, ORG_ID, eventId, 'email.received', 'pending']),
    );
    expect(await counter(h, 'webhook_deliveries_created_total')).toContain(
      'type="email.received",trigger="event"',
    );
    expect(await counter(h, 'webhook_fanout_events_total')).toContain('result="projected"');
  });

  it('a redelivered event hits the ledger (duplicate) and writes nothing', async () => {
    const ledger = new Set<string>();
    const first = harness({ ledger });
    await first.service.handle(sourceEvent(EventTypes.MessageReceived));
    const again = harness({ ledger });
    await expect(again.service.handle(sourceEvent(EventTypes.MessageReceived))).resolves.toBe(
      'duplicate',
    );
    expect(inserts(again, 'webhook_events')).toHaveLength(0);
  });

  it('applies filters after the reads (a domain filter that does not match → no row)', async () => {
    const h = harness({
      index: orgIndex({
        subscriptions: [SUB({ filters: { domainIds: ['01890a5d-ac96-774b-bcce-b30209900000'] } })],
      }),
    });
    await h.service.handle(sourceEvent(EventTypes.MessageReceived));
    expect(h.transactions).toBe(1); // the pre-filter cannot know the domain
    expect(inserts(h, 'webhook_events')).toHaveLength(0);
    expect(inserts(h, 'webhook_deliveries')).toHaveLength(0);
  });

  it('inserts deliveries beyond the backlog bound as dead (backlog_exceeded)', async () => {
    const h = harness({ pendingCount: 1001, maxPending: 1000 });
    await h.service.handle(sourceEvent(EventTypes.MessageReceived));
    const [delivery] = inserts(h, 'webhook_deliveries');
    expect(delivery?.values).toEqual(expect.arrayContaining(['dead', 'backlog_exceeded']));
    expect(await counter(h, 'webhook_deliveries_dead_total')).toMatch(/ 1$/m);
  });

  it('requests a threat alert for the first event of a window, even without subscribers', async () => {
    const h = harness({ index: orgIndex({ subscriptions: [] }) });
    const event = sourceEvent(EventTypes.PolicyDecided);
    await h.service.handle(event);
    expect(inserts(h, 'webhook_events')).toHaveLength(1); // stored for the alert's refs
    expect(inserts(h, 'webhook_deliveries')).toHaveLength(0);
    const [window] = inserts(h, 'notification_alert_windows');
    expect(window?.values).toEqual(expect.arrayContaining([ORG_ID, 'threat_detected', '-']));
    expect(h.outbox).toHaveLength(1);
    const row = h.outbox[0]!;
    expect(row).toMatchObject({
      eventId: webhookEventId(event.eventId, 'alert:threat_detected'),
      eventType: 'notification.alert_requested.v1',
      aggregateType: 'organization',
      aggregateId: ORG_ID.toString(),
      correlationId: event.correlationId,
      organizationId: ORG_ID,
    });
    const payload = notificationAlertRequestedV1.parse(row.payload);
    expect(payload).toMatchObject({
      kind: 'threat_detected',
      severity: 'high',
      refs: {
        webhookEventId: webhookEventId(event.eventId, 'email.threat.detected', 'scan'),
        messageId: '9001',
        receivedAt: '2026-11-01T10:15:30.123Z',
      },
      window: { from: '2026-11-01T10:00:00.000Z', to: '2026-11-01T11:00:00.000Z' },
      counts: { suppressedBefore: 0 },
    });
    expect(await counter(h, 'webhook_alert_requests_total')).toContain(
      'kind="threat_detected",result="requested"',
    );
  });

  it('counts later events of an open window without a second alert', async () => {
    const h = harness({ index: orgIndex({ subscriptions: [] }), windowInsert: 2 });
    await h.service.handle(sourceEvent(EventTypes.PolicyDecided));
    expect(h.outbox).toHaveLength(0);
    expect(await counter(h, 'webhook_alert_requests_total')).toContain('result="throttled"');
  });

  it('respects the tenant minimum severity and the enabled flags', async () => {
    const settings = structuredClone(
      NOTIFICATION_SETTINGS_DEFAULTS,
    ) as ResolvedNotificationSettings;
    // A suspicious (medium) threat under the default `high` minimum: no alert, no transaction.
    const h = harness({ index: orgIndex({ subscriptions: [], settings }) });
    await h.service.handle(sourceEvent(EventTypes.PolicyDecided, { finalVerdict: 'suspicious' }));
    expect(h.transactions).toBe(0);
    settings.alerts.domainDnsFailed.enabled = false;
    const dns = harness({ index: orgIndex({ subscriptions: [], settings }) });
    await dns.service.handle(sourceEvent(EventTypes.DomainDnsRecordsChanged));
    expect(dns.transactions).toBe(0);
  });

  it('a DNS failure alert is scoped to the domain', async () => {
    const h = harness({ index: orgIndex({ subscriptions: [] }) });
    await h.service.handle(sourceEvent(EventTypes.DomainDnsRecordsChanged));
    const [window] = inserts(h, 'notification_alert_windows');
    expect(window?.values).toEqual(
      expect.arrayContaining(['domain_dns_failed', '01890a5d-ac96-774b-bcce-b302099a8057']),
    );
    expect(notificationAlertRequestedV1.parse(h.outbox[0]!.payload).refs).toMatchObject({
      domainId: '77',
    });
  });

  it('dead-letters a payload the guard refuses (webhook_payload_unsafe)', async () => {
    const h = harness({
      index: orgIndex({ subscriptions: [SUB({ eventTypes: ['domain.dns.failed'] })] }),
    });
    const changes = [
      {
        recordKey: 'https://evil.example/x',
        purpose: 'mx',
        previousStatus: 'valid',
        status: 'invalid',
      },
    ];
    const error = await h.service
      .handle(sourceEvent(EventTypes.DomainDnsRecordsChanged, { changes }))
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(NonRetryableError);
    expect((error as NonRetryableError).code).toBe('webhook_payload_unsafe');
    expect(await counter(h, 'webhook_fanout_events_total')).toContain('result="unsafe"');
  });

  it('dead-letters a payload its strict schema refuses (webhook_payload_invalid)', async () => {
    const h = harness({
      index: orgIndex({ subscriptions: [SUB({ eventTypes: ['domain.verified'] })] }),
      facts: fakeFacts({
        domain: (_o, id, publicId) =>
          Promise.resolve({ id, publicId, name: 'not a domain!', status: 'verified' }),
      }),
    });
    const error = await h.service
      .handle(sourceEvent(EventTypes.DomainStatusChanged, { status: 'verified' }))
      .catch((e: unknown) => e);
    expect((error as NonRetryableError).code).toBe('webhook_payload_invalid');
  });

  it('retries an inconsistent read (retryable error, counted as error)', async () => {
    const h = harness({
      facts: fakeFacts({
        message: () => Promise.reject(new InconsistentReadError('message', 'missing')),
      }),
    });
    await expect(h.service.handle(sourceEvent(EventTypes.MessageReceived))).rejects.toBeInstanceOf(
      InconsistentReadError,
    );
    expect(await counter(h, 'webhook_fanout_events_total')).toContain('result="error"');
  });

  it('treats a missing organization as nothing to do', async () => {
    const h = harness({ index: null });
    await expect(h.service.handle(sourceEvent(EventTypes.MessageReceived))).resolves.toBe(
      'handled',
    );
    expect(h.transactions).toBe(0);
  });
});
