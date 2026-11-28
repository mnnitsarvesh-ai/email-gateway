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
  messageFacts,
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
    integrationAlertThrottleMinutes?: number;
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
    riskReasonCodes: (_tx: unknown, k: never) => facts.riskReasonCodes(k),
    copyDetections: (_tx: unknown, k: never) => facts.copyDetections(k),
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
    ...(options.integrationAlertThrottleMinutes !== undefined && {
      integrationAlertThrottleMinutes: options.integrationAlertThrottleMinutes,
    }),
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

  it('API-mode DLP detection requests dlp_detected (message refs, no scope, its own throttle)', async () => {
    const settings = structuredClone(
      NOTIFICATION_SETTINGS_DEFAULTS,
    ) as ResolvedNotificationSettings;
    settings.alerts.dlpDetected.throttleMinutes = 15;
    const facts = fakeFacts({
      message: () => Promise.resolve(messageFacts({ ingestSource: 'journal_intake' })),
    });
    const h = harness({ index: orgIndex({ subscriptions: [], settings }), facts });
    const event = sourceEvent(EventTypes.MessageCopyDetected, {
      verdict: 'clean',
      dlp: { action: 'quarantine', verdict: 'suspicious', categories: ['payment_card'] },
    });
    await h.service.handle(event);
    const [window] = inserts(h, 'notification_alert_windows');
    expect(window?.values).toEqual(expect.arrayContaining([ORG_ID, 'dlp_detected', '-']));
    const alert = notificationAlertRequestedV1.parse(h.outbox[0]!.payload);
    expect(h.outbox[0]!.eventId).toBe(webhookEventId(event.eventId, 'alert:dlp_detected'));
    expect(alert).toMatchObject({
      kind: 'dlp_detected',
      severity: 'high',
      refs: {
        webhookEventId: webhookEventId(event.eventId, 'mailbox.dlp.detected', 'dlp'),
        messageId: '9001',
        receivedAt: '2026-11-01T10:15:30.123Z',
      },
      window: { from: '2026-11-01T10:15:00.000Z', to: '2026-11-01T10:30:00.000Z' },
    });
    expect(await counter(h, 'webhook_alert_requests_total')).toContain(
      'kind="dlp_detected",result="requested"',
    );
  });

  it('API-mode threat detection requests threat_detected; DLP under its minimum severity does not', async () => {
    const facts = fakeFacts({
      message: () => Promise.resolve(messageFacts({ ingestSource: 'journal_intake' })),
    });
    const h = harness({ index: orgIndex({ subscriptions: [] }), facts });
    const event = sourceEvent(EventTypes.MessageCopyDetected, {
      dlp: { action: 'alert', verdict: 'suspicious', categories: [] },
    });
    await h.service.handle(event);
    // phishing → high threat alert; DLP `alert` is low, under the default `medium` minimum.
    expect(h.outbox).toHaveLength(1);
    expect(notificationAlertRequestedV1.parse(h.outbox[0]!.payload)).toMatchObject({
      kind: 'threat_detected',
      refs: { webhookEventId: webhookEventId(event.eventId, 'mailbox.threat.detected', 'scan') },
    });
    expect(inserts(h, 'webhook_events')).toHaveLength(1);
    expect(await counter(h, 'webhook_alert_requests_total')).not.toContain('dlp_detected');
  });

  it('delivers mailbox.* events to subscribers by type, direction and verdict filters', async () => {
    const facts = () =>
      fakeFacts({
        message: () => Promise.resolve(messageFacts({ ingestSource: 'mailbox_api' })),
      });
    const subscribed = harness({
      index: orgIndex({
        subscriptions: [
          SUB({
            eventTypes: ['mailbox.threat.detected', 'mailbox.dlp.detected'],
            filters: { directions: ['outbound'] },
          }),
        ],
      }),
      facts: facts(),
    });
    const outbound = sourceEvent(EventTypes.MessageCopyDetected, {
      direction: 'outbound',
      dlp: { action: 'block', verdict: 'suspicious', categories: ['payment_card'] },
      copies: { counted: 1, remediation: { pending: 0, simulated: 0, skipped: 1, none: 0 } },
      detectionIds: ['01890a5d-ac96-774b-bcce-b302099a80f2'],
    });
    await subscribed.service.handle(outbound);
    expect(inserts(subscribed, 'webhook_deliveries')).toHaveLength(2);

    // An inbound detection does not match a directions = [outbound] filter; a verdicts filter
    // applies to the threat type only.
    const filtered = harness({
      index: orgIndex({
        subscriptions: [
          SUB({ eventTypes: ['mailbox.threat.detected'], filters: { directions: ['outbound'] } }),
          SUB({
            id: 502n,
            eventTypes: ['mailbox.threat.detected'],
            filters: { verdicts: ['spam'] },
          }),
        ],
        settings: (() => {
          const s = structuredClone(NOTIFICATION_SETTINGS_DEFAULTS) as ResolvedNotificationSettings;
          s.alerts.threatDetected.enabled = false;
          return s;
        })(),
      }),
      facts: facts(),
    });
    await filtered.service.handle(sourceEvent(EventTypes.MessageCopyDetected));
    expect(filtered.transactions).toBe(0);
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

  it('a critical connection requests integration_unhealthy scoped to the connection (step 8.2 D12)', async () => {
    const h = harness({
      index: orgIndex({ subscriptions: [] }),
      integrationAlertThrottleMinutes: 30,
    });
    await h.service.handle(sourceEvent(EventTypes.IntegrationHealthChanged));
    const [event] = inserts(h, 'webhook_events');
    expect(event?.values).toEqual(expect.arrayContaining(['integration.health_changed', 'high']));
    expect(inserts(h, 'webhook_deliveries')).toEqual([]);
    const [window] = inserts(h, 'notification_alert_windows');
    expect(window?.values).toEqual(
      expect.arrayContaining([
        'integration_unhealthy',
        '01890a5d-ac96-774b-bcce-b302099a80a0',
        // The 30-minute platform throttle window containing the event time (10:15:32).
        new Date('2026-11-01T10:00:00.000Z'),
      ]),
    );
    const alert = notificationAlertRequestedV1.parse(h.outbox[0]!.payload);
    expect(alert.kind).toBe('integration_unhealthy');
    expect(alert.refs).toEqual({
      webhookEventId: expect.any(String),
      connectionId: '01890a5d-ac96-774b-bcce-b302099a80a0',
    });
    expect(alert.window).toEqual({
      from: '2026-11-01T10:00:00.000Z',
      to: '2026-11-01T10:30:00.000Z',
    });
  });

  it('a non-critical health transition is delivered to subscribers without an alert', async () => {
    const quiet = harness({ index: orgIndex({ subscriptions: [] }) });
    await quiet.service.handle(
      sourceEvent(EventTypes.IntegrationHealthChanged, {
        previousStatus: 'critical',
        status: 'healthy',
        failingChecks: [],
      }),
    );
    expect(quiet.transactions).toBe(0);
    const h = harness({
      index: orgIndex({ subscriptions: [SUB({ eventTypes: ['integration.health_changed'] })] }),
    });
    await h.service.handle(
      sourceEvent(EventTypes.IntegrationHealthChanged, {
        previousStatus: 'healthy',
        status: 'warning',
      }),
    );
    expect(inserts(h, 'webhook_deliveries')).toHaveLength(1);
    expect(inserts(h, 'notification_alert_windows')).toEqual([]);
    expect(h.outbox).toEqual([]);
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
