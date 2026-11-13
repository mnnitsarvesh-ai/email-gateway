import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Test, type TestingModule } from '@nestjs/testing';
import {
  AdvisoryLocks,
  AmqpConnection,
  ConfirmPublisher,
  MetricsService,
  uuidv7,
} from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import {
  type EventEnvelope,
  EventTypes,
  notificationAlertRequestedV1,
} from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import { type DnsBackend, RestrictedResolver } from '@email-gateway/url-security';
import { parseStoredEnvelope, webhookEventId } from '@email-gateway/webhooks';
import { Redis } from 'ioredis';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../src/app.module';
import { loadWorkerConfig, type WorkerConfig } from '../src/config';
import {
  createDeliveryComponents,
  createPoster,
  type DeliveryComponents,
} from '../src/delivery/delivery.module';
import { InflightCounters, orgKey, subKey } from '../src/delivery/inflight';
import { WebhookMetrics } from '../src/metrics/webhook-metrics';
import { createTestVhost, eventually, requireEnv, type TestVhost } from './support/broker';
import { Fixtures } from './support/fixtures';
import { TestReceiver } from './support/receiver';

/**
 * webhook-worker integration (step 6.2 §10.3): the real MySQL writer, Redis and RabbitMQ (a
 * throwaway vhost with topology v11). The fanout runs as the Nest app (role `fanout`) consuming
 * `email.webhooks`; source events are published with the relay's codec (`ConfirmPublisher`). The
 * delivery role is driven tick by tick (`createDeliveryComponents`, restricted to this run's
 * organizations) against an in-process HTTPS receiver reached through the TEST-ONLY dial map after
 * the SSRF guard validated `hooks.receiver.test` → 203.0.113.20 (stub DNS); never the Internet.
 */

const silent = createLogger({ service: 'webhook-worker-it', level: 'silent' });
const fx = new Fixtures();
const receiver = new TestReceiver();
let vhost: TestVhost;
let app: TestingModule;
let publisherConnection: AmqpConnection;
let publisher: ConfirmPublisher;
let redis: Redis;
let config: Readonly<WorkerConfig>;
let delivery: DeliveryComponents;
let deliveryMetrics: MetricsService;
let locks: AdvisoryLocks;
let caDir: string;

const HOOKS = 'https://hooks.receiver.test';
/** An organization / subscription id no row uses (the slot-leak test only touches Redis). */
const LEAK_ORG = 9_000_000_000_000n + BigInt(Math.floor(Math.random() * 1_000_000));

/** Stub DNS (the authoritative check runs on every answer): the receiver, a rebinding name. */
const resolver = new RestrictedResolver({}, (): DnsBackend => {
  const answers: Record<string, { v4?: string[]; v6?: string[] }> = {
    'hooks.receiver.test': { v4: ['203.0.113.20'] },
    'rebind.receiver.test': { v4: ['203.0.113.20', '127.0.0.1'] },
    'metadata.receiver.test': { v4: ['169.254.169.254'] },
  };
  const make = (family: 'v4' | 'v6') => (name: string) => {
    const list = answers[name]?.[family];
    return list
      ? Promise.resolve(list)
      : Promise.reject(
          Object.assign(new Error('nodata'), { code: answers[name] ? 'ENODATA' : 'ENOTFOUND' }),
        );
  };
  return { resolve4: make('v4'), resolve6: make('v6'), cancel: () => undefined };
});

function envelope(
  eventType: string,
  organizationId: bigint,
  payload: Record<string, unknown>,
): EventEnvelope {
  return {
    eventId: fx.track(uuidv7()),
    eventType,
    occurredAt: new Date().toISOString(),
    correlationId: `it-wh-${fx.suffix}-corr`,
    organizationId: organizationId.toString(),
    payload,
  };
}

const received = (org: bigint, m: { messageId: bigint; receivedAt: Date }): EventEnvelope =>
  envelope(EventTypes.MessageReceived, org, {
    messageId: m.messageId.toString(),
    receivedAt: m.receivedAt.toISOString(),
    direction: 'inbound',
    emlS3Key: `org/${org.toString()}/eml/it.eml`,
    sizeBytes: 4096,
    envelopeFrom: 'alice.sender@partner.example',
    recipientCount: 2,
  });

const decided = (
  org: bigint,
  m: { messageId: bigint; receivedAt: Date; scanId: bigint },
): EventEnvelope =>
  envelope(EventTypes.PolicyDecided, org, {
    messageId: m.messageId.toString(),
    receivedAt: m.receivedAt.toISOString(),
    direction: 'inbound',
    lifecycleRound: 0,
    scanId: m.scanId.toString(),
    trigger: 'scanned',
    disposition: 'quarantine',
    finalAction: 'quarantine',
    finalVerdict: 'malware',
    riskScore: 900,
    nonTerminalActions: [],
    decisive: { source: 'platform_default', policyId: null, versionNo: null, ruleId: null },
    overrideApplied: false,
    policyGeneration: '0',
    snapshotSha256: 'd'.repeat(64),
    inputSha256: 'e'.repeat(64),
    evaluatedAt: new Date().toISOString(),
  });

const publish = (e: EventEnvelope): Promise<void> => publisher.publish({ envelope: e });

async function deliveriesOf(subscriptionId: bigint) {
  return fx.prisma.webhookDelivery.findMany({
    where: { subscriptionId },
    orderBy: [{ eventOccurredAt: 'asc' }, { id: 'asc' }],
  });
}

async function waitForDeliveries(subscriptionId: bigint, count: number): Promise<void> {
  await eventually(
    async () => (await deliveriesOf(subscriptionId)).length >= count,
    20_000,
    `${count} deliveries of subscription ${subscriptionId}`,
  );
}

/** One delivery tick, then waits for its attempts to be recorded. */
async function tick(): Promise<void> {
  await delivery.loop.tick();
  await delivery.loop.drain();
}

/** Ticks until `condition` holds (retries wait for their due time). */
async function tickUntil(condition: () => Promise<boolean>, timeoutMs: number, what: string) {
  await eventually(
    async () => {
      await tick();
      return condition();
    },
    timeoutMs,
    what,
    200,
  );
}

/** A fresh organization with one subscription (subscription index TTL is 1 s). */
async function scenario(
  label: string,
  path: string,
  options: Partial<Parameters<Fixtures['subscription']>[1]> = {},
) {
  const org = await fx.organization(label);
  const sub = await fx.subscription(org.id, {
    url: `${HOOKS}${path}`,
    eventTypes: ['email.received'],
    ...options,
  });
  receiver.registerSecrets(path, [sub.secret]);
  return { org, sub };
}

beforeAll(async () => {
  await receiver.start();
  caDir = mkdtempSync(join(tmpdir(), 'webhook-worker-it-ca-'));
  const caPath = join(caDir, 'ca.pem');
  writeFileSync(caPath, receiver.pki.ca);
  vhost = await createTestVhost();
  config = loadWorkerConfig({
    ...process.env,
    APP_ENV: 'local',
    LOG_LEVEL: 'fatal',
    WEBHOOK_WORKER_ROLES: 'fanout',
    RABBITMQ_WEBHOOK_URL: vhost.adminUrl,
    WEBHOOK_SUBSCRIPTION_CACHE_SECONDS: '1',
    WEBHOOK_RETRY_BASE_SECONDS: '1',
    WEBHOOK_RETRY_MAX_DELAY_SECONDS: '60',
    WEBHOOK_MAX_ATTEMPTS: '3',
    WEBHOOK_DISABLE_AFTER_FAILURES: '5',
    WEBHOOK_DISABLE_AFTER_HOURS: '1',
    WEBHOOK_HTTP_CONNECT_TIMEOUT_MS: '1000',
    WEBHOOK_HTTP_TOTAL_TIMEOUT_MS: '5000',
    WEBHOOK_DELIVERY_POLL_INTERVAL_MS: '100',
    WEBHOOK_ALLOWED_PORTS: '443',
    WEBHOOK_ALLOW_HTTP: 'false',
    WEBHOOK_TEST_ALLOW_CIDRS: '203.0.113.0/24',
    WEBHOOK_TEST_DIAL_MAP: `203.0.113.20:443=127.0.0.1:${receiver.port}`,
    WEBHOOK_EXTRA_CA_PATH: caPath,
  });
  app = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] }).compile();
  await app.init();
  await app.get(AmqpConnection).waitUntilConnected(15_000);
  publisherConnection = new AmqpConnection({
    urls: [vhost.adminUrl],
    connectionName: 'it-event-relay',
    logger: silent,
    reconnect: { baseMs: 50, maxMs: 500 },
  });
  publisherConnection.start();
  await publisherConnection.waitUntilConnected(15_000);
  publisher = new ConfirmPublisher({
    connection: publisherConnection,
    logger: silent,
    appId: 'event-relay',
    confirmTimeoutMs: 15_000,
    maxMessageBytes: 131_072,
  });
  redis = new Redis(requireEnv('REDIS_URL'), { maxRetriesPerRequest: 2 });
  locks = new AdvisoryLocks(requireEnv('DATABASE_URL'));
  deliveryMetrics = new MetricsService({ service: 'webhook-worker-it' });
  delivery = createDeliveryComponents(config, {
    prisma: fx.prisma,
    redis,
    locks,
    metrics: new WebhookMetrics(deliveryMetrics),
    logger: silent,
    poster: createPoster(config, { resolver }),
    organizationIds: fx.organizationIds,
    lockName: `eg:webhook-maint-it-${fx.suffix}`,
  });
}, 180_000);

afterAll(async () => {
  await delivery?.loop.stop().catch(() => undefined);
  await app?.close();
  await publisher?.close().catch(() => undefined);
  await publisherConnection?.close().catch(() => undefined);
  await vhost?.cleanup().catch(() => undefined);
  await locks?.close().catch(() => undefined);
  if (redis) {
    for (const id of fx.organizationIds) await redis.del(orgKey(id));
    await redis.del(orgKey(LEAK_ORG), subKey(LEAK_ORG), subKey(LEAK_ORG + 1n));
    const subs = await fx.prisma.webhookSubscription.findMany({
      where: { organizationId: { in: fx.organizationIds } },
      select: { id: true },
    });
    for (const s of subs) {
      await redis.del(subKey(s.id));
      const rate = await redis.keys(`wh:rate:sub:${s.id.toString()}:*`);
      if (rate.length > 0) await redis.del(...rate);
    }
    redis.disconnect();
  }
  await receiver.stop();
  await fx.cleanup();
  if (caDir) rmSync(caDir, { recursive: true, force: true });
}, 120_000);

describe('fanout (W1, W3, W5) from real broker events', () => {
  it('projects to event and delivery rows; each organization only gets its own events', async () => {
    const a = await scenario('a', '/a/main');
    const b = await scenario('b', '/b/main');
    const ma = await fx.message(a.org.id);
    const mb = await fx.message(b.org.id);
    const ea = received(a.org.id, ma);
    await publish(ea);
    await publish(received(b.org.id, mb));
    await waitForDeliveries(a.sub.id, 1);
    await waitForDeliveries(b.sub.id, 1);

    const [rowA] = await fx.prisma.webhookEvent.findMany({ where: { organizationId: a.org.id } });
    expect(rowA).toMatchObject({
      eventId: webhookEventId(ea.eventId, 'email.received', ''),
      eventType: 'email.received',
      sourceEventId: ea.eventId,
      sourceEventType: 'mail.message.received.v1',
      messageId: ma.messageId,
      severity: 'info',
    });
    const env = parseStoredEnvelope(rowA!.payloadJson);
    expect(env.organizationId).toBe(a.org.publicId);
    expect(env.data).toMatchObject({
      message: {
        id: ma.publicId,
        senderDomain: 'partner.example',
        headerFromDomain: 'partner.example',
        recipientDomains: ['corp.example', 'other.example'],
        internetMessageId: '<it-msg@partner.example>',
      },
    });
    // Metadata only: no local part, no subject, no object key.
    for (const forbidden of ['alice', 'bob@', 'carol', 'Quarterly', 'org/', 'eml']) {
      expect(rowA!.payloadJson.toLowerCase()).not.toContain(forbidden.toLowerCase());
    }
    const [deliveryA] = await deliveriesOf(a.sub.id);
    expect(deliveryA).toMatchObject({
      organizationId: a.org.id,
      eventId: rowA!.eventId,
      status: 'pending',
      deliverySeq: 0,
      trigger: 'event',
      attemptCount: 0,
    });

    await tickUntil(
      async () =>
        (await deliveriesOf(a.sub.id))[0]?.status === 'succeeded' &&
        (await deliveriesOf(b.sub.id))[0]?.status === 'succeeded',
      15_000,
      'both delivered',
    );
    const gotA = receiver.received('/a/main');
    const gotB = receiver.received('/b/main');
    expect(gotA).toHaveLength(1);
    expect(gotB).toHaveLength(1);
    expect(JSON.parse(gotA[0]!.body).organizationId).toBe(a.org.publicId);
    expect(JSON.parse(gotB[0]!.body).organizationId).toBe(b.org.publicId);
    expect(gotA[0]!.body).toBe(rowA!.payloadJson); // the stored bytes
    // The receiver verified the signature with the subscription's secret (and only its own).
    expect(gotA[0]!.signatureValid).toBe(true);
    expect(gotB[0]!.signatureValid).toBe(true);
    expect(gotA[0]!.headers).toMatchObject({
      'user-agent': 'EmailGateway-Webhooks/1',
      'content-type': 'application/json',
      'eg-event-id': rowA!.eventId,
      'idempotency-key': rowA!.eventId,
      'eg-event-type': 'email.received',
      'eg-delivery-id': deliveryA!.publicId,
      'eg-delivery-attempt': '1',
      'eg-subscription-id': a.sub.publicId,
    });
    const attempts = await fx.prisma.webhookDeliveryAttempt.findMany({
      where: { organizationId: a.org.id },
    });
    expect(attempts).toHaveLength(1);
    expect(attempts[0]).toMatchObject({
      attemptNo: 1,
      outcome: 'succeeded',
      httpStatus: 200,
      signatureCount: 1,
    });
    const sub = await fx.prisma.webhookSubscription.findUniqueOrThrow({ where: { id: a.sub.id } });
    expect(sub.lastSuccessAt).not.toBeNull();
  });

  it('a redelivered source event creates nothing twice (ledger)', async () => {
    const s = await scenario('dup', '/dup/main');
    const m = await fx.message(s.org.id);
    const e = received(s.org.id, m);
    await publish(e);
    await waitForDeliveries(s.sub.id, 1);
    await publish(e);
    await eventually(
      async () => (await app.get(MetricsService).metrics()).includes('result="duplicate"'),
      10_000,
      'duplicate counted',
    );
    expect(await deliveriesOf(s.sub.id)).toHaveLength(1);
    expect(await fx.prisma.webhookEvent.count({ where: { organizationId: s.org.id } })).toBe(1);
  });

  it('acks events nothing subscribes to without a ledger row', async () => {
    const s = await scenario('noop', '/noop/main');
    const m = await fx.message(s.org.id);
    const scanned = envelope(EventTypes.MessageScanned, s.org.id, {
      messageId: m.messageId.toString(),
      receivedAt: m.receivedAt.toISOString(),
      direction: 'inbound',
      emlS3Key: `org/${s.org.id.toString()}/eml/it.eml`,
      lifecycleRound: 0,
      scanId: m.scanId.toString(),
      scanKind: 'initial',
      outcome: 'scanned',
      verdict: 'clean',
      engines: [{ engine: 'rspamd', required: true, outcome: 'clean', attempts: 1 }],
      reasonCodes: [],
      completedAt: new Date().toISOString(),
    });
    await publish(scanned);
    await eventually(
      async () =>
        /webhook_fanout_events_total\{[^}]*source_type="mail\.message\.scanned\.v1"[^}]*result="noop"[^}]*\}/.test(
          await app.get(MetricsService).metrics(),
        ),
      10_000,
      'noop counted',
    );
    expect(await fx.prisma.messageIdempotency.count({ where: { eventId: scanned.eventId } })).toBe(
      0,
    );
  });

  it('requests one threat alert per window and one DNS failure alert (outbox rows)', async () => {
    const org = await fx.organization('alerts');
    const domain = await fx.domain(org.id, 'alerts');
    const sub = await fx.subscription(org.id, {
      url: `${HOOKS}/alerts/main`,
      eventTypes: ['email.threat.detected', 'domain.dns.failed'],
    });
    const m1 = await fx.message(org.id, { domainId: domain.id });
    const m2 = await fx.message(org.id, { domainId: domain.id });
    const first = decided(org.id, m1);
    await publish(first);
    await waitForDeliveries(sub.id, 1);
    await publish(decided(org.id, m2));
    await waitForDeliveries(sub.id, 2);
    const [threat] = await fx.prisma.webhookEvent.findMany({
      where: { organizationId: org.id, eventType: 'email.threat.detected' },
      orderBy: { id: 'asc' },
    });
    expect(JSON.parse(threat!.payloadJson)).toMatchObject({
      type: 'email.threat.detected',
      data: {
        detection: { stage: 'scan', verdict: 'malicious', reasonCodes: ['phishing.known_bad_url'] },
      },
    });
    const windows = await fx.prisma.notificationAlertWindow.findMany({
      where: { organizationId: org.id },
    });
    expect(windows).toHaveLength(1);
    expect(windows[0]).toMatchObject({ kind: 'threat_detected', scopeKey: '-', eventCount: 2 });
    await publish(
      envelope(EventTypes.DomainDnsRecordsChanged, org.id, {
        domainId: domain.id.toString(),
        domainPublicId: domain.publicId,
        name: domain.name,
        domainStatus: 'active',
        changes: [{ recordKey: 'mx', purpose: 'mx', previousStatus: 'valid', status: 'missing' }],
        checkedAt: new Date().toISOString(),
      }),
    );
    await waitForDeliveries(sub.id, 3);
    const outbox = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: org.id, eventType: 'notification.alert_requested.v1' },
      orderBy: { id: 'asc' },
    });
    expect(outbox).toHaveLength(2);
    const [threatAlert, dnsAlert] = outbox.map((o) =>
      notificationAlertRequestedV1.parse(o.payload),
    );
    expect(outbox[0]).toMatchObject({
      eventId: webhookEventId(first.eventId, 'alert:threat_detected'),
      aggregateType: 'organization',
      aggregateId: org.id.toString(),
      correlationId: first.correlationId,
    });
    expect(threatAlert).toMatchObject({
      kind: 'threat_detected',
      severity: 'high',
      refs: { webhookEventId: threat!.eventId, messageId: m1.messageId.toString() },
    });
    expect(dnsAlert).toMatchObject({
      kind: 'domain_dns_failed',
      severity: 'high',
      refs: { domainId: domain.id.toString() },
    });
    expect(JSON.stringify(outbox.map((o) => o.payload))).not.toContain('@');
  });
});

describe('delivery (W8–W11)', () => {
  it('retries a failing receiver with backoff, then succeeds', async () => {
    const s = await scenario('retry', '/retry/main');
    receiver.program('/retry/main', [{ status: 500 }, { status: 500 }], 200);
    await publish(received(s.org.id, await fx.message(s.org.id)));
    await waitForDeliveries(s.sub.id, 1);
    await tickUntil(
      async () => (await deliveriesOf(s.sub.id))[0]?.status === 'succeeded',
      20_000,
      'delivered after two failures',
    );
    const attempts = await fx.prisma.webhookDeliveryAttempt.findMany({
      where: { subscriptionId: s.sub.id },
      orderBy: { attemptNo: 'asc' },
    });
    expect(attempts.map((a) => [a.attemptNo, a.outcome, a.httpStatus])).toEqual([
      [1, 'http_error', 500],
      [2, 'http_error', 500],
      [3, 'succeeded', 200],
    ]);
    // Backoff 1 s × 2^(n−1) with jitter ≥ 0.8.
    const got = receiver.received('/retry/main');
    expect(got[1]!.receivedAt - got[0]!.receivedAt).toBeGreaterThanOrEqual(800);
    expect(got[2]!.receivedAt - got[1]!.receivedAt).toBeGreaterThanOrEqual(1600);
    expect(new Set(got.map((r) => r.headers['eg-delivery-id'])).size).toBe(1);
    expect(got.map((r) => r.headers['eg-delivery-attempt'])).toEqual(['1', '2', '3']);
    expect(attempts[0]!.responseSnippet).toBe('ok');
  });

  it('honours Retry-After', async () => {
    const s = await scenario('retry-after', '/retry-after/main');
    receiver.program('/retry-after/main', [{ status: 429, retryAfter: '2' }], 200);
    await publish(received(s.org.id, await fx.message(s.org.id)));
    await waitForDeliveries(s.sub.id, 1);
    await tick();
    const [afterFirst] = await deliveriesOf(s.sub.id);
    const [attempt] = await fx.prisma.webhookDeliveryAttempt.findMany({
      where: { subscriptionId: s.sub.id },
    });
    expect(attempt).toMatchObject({ outcome: 'http_error', httpStatus: 429, retryAfterSeconds: 2 });
    expect(
      afterFirst!.nextAttemptAt!.getTime() - attempt!.attemptedAt.getTime(),
    ).toBeGreaterThanOrEqual(2000);
    await tickUntil(
      async () => (await deliveriesOf(s.sub.id))[0]?.status === 'succeeded',
      15_000,
      'delivered after Retry-After',
    );
    const got = receiver.received('/retry-after/main');
    expect(got[1]!.receivedAt - got[0]!.receivedAt).toBeGreaterThanOrEqual(2000);
  });

  it('dead-letters after max attempts; single and range replays re-send the stored event once', async () => {
    const s = await scenario('dead', '/dead/main');
    receiver.program('/dead/main', [], 503);
    await publish(received(s.org.id, await fx.message(s.org.id)));
    await waitForDeliveries(s.sub.id, 1);
    await tickUntil(
      async () => (await deliveriesOf(s.sub.id))[0]?.status === 'dead',
      20_000,
      'dead',
    );
    const [dead] = await deliveriesOf(s.sub.id);
    expect(dead).toMatchObject({
      status: 'dead',
      attemptCount: 3,
      lastError: 'http_503',
      lastResponseCode: 503,
    });
    expect(dead!.completedAt).not.toBeNull();
    expect(await deliveryMetrics.metrics()).toMatch(/webhook_deliveries_dead_total\{[^}]*\} [1-9]/);

    // Single replay (the api's insert, W12): delivery_seq = max + 1, trigger replay.
    receiver.program('/dead/main', [], 200);
    await fx.prisma.webhookDelivery.create({
      data: {
        eventOccurredAt: dead!.eventOccurredAt,
        publicId: uuidv7(),
        subscriptionId: s.sub.id,
        organizationId: s.org.id,
        eventId: dead!.eventId,
        eventType: dead!.eventType,
        deliverySeq: 1,
        trigger: 'replay',
        status: 'pending',
        nextAttemptAt: new Date(),
      },
    });
    // Range replay over the dead original.
    const replay = await fx.prisma.webhookReplay.create({
      data: {
        publicId: uuidv7(),
        organizationId: s.org.id,
        subscriptionId: s.sub.id,
        requestedByType: 'user',
        requestedById: uuidv7(),
        rangeFrom: new Date(dead!.eventOccurredAt.getTime() - 60_000),
        rangeTo: new Date(dead!.eventOccurredAt.getTime() + 60_000),
        statuses: ['dead'],
      },
    });
    expect(await delivery.replays.step(replay.id)).toBe('completed');
    expect(await delivery.replays.step(replay.id)).toBe('skipped'); // idempotent: finished
    const stored = await fx.prisma.webhookReplay.findUniqueOrThrow({ where: { id: replay.id } });
    expect(stored).toMatchObject({
      status: 'completed',
      matchedCount: 1,
      createdCount: 1,
      truncated: false,
    });
    const all = await deliveriesOf(s.sub.id);
    expect(all.map((d) => [d.deliverySeq, d.trigger, d.status]).sort()).toEqual([
      [0, 'event', 'dead'],
      [1, 'replay', 'pending'],
      [2, 'replay', 'pending'],
    ]);
    expect(all.find((d) => d.deliverySeq === 2)!.replayId).toBe(replay.id);
    await tickUntil(
      async () =>
        (await deliveriesOf(s.sub.id)).filter((d) => d.status === 'succeeded').length === 2,
      15_000,
      'both replays delivered',
    );
    const got = receiver.received('/dead/main');
    const replays = got.slice(-2);
    expect(replays.map((r) => r.body)).toEqual([got[0]!.body, got[0]!.body]); // same bytes
    expect(new Set(replays.map((r) => r.headers['eg-event-id']))).toEqual(new Set([dead!.eventId]));
    expect(new Set(got.map((r) => r.headers['eg-delivery-id'])).size).toBe(3);
    expect(replays.every((r) => r.signatureValid)).toBe(true);
  });

  it('disables a subscription after sustained failure (audit + alert), cancels its pending deliveries', async () => {
    const s = await scenario('disable', '/disable/main', {
      consecutiveFailures: 4,
      failingSince: new Date(Date.now() - 2 * 3_600_000),
      maxConcurrency: 1,
    });
    receiver.program('/disable/main', [], 500);
    await publish(received(s.org.id, await fx.message(s.org.id)));
    await publish(received(s.org.id, await fx.message(s.org.id)));
    await waitForDeliveries(s.sub.id, 2);
    await tick(); // max_concurrency 1: one attempt
    const sub = await fx.prisma.webhookSubscription.findUniqueOrThrow({ where: { id: s.sub.id } });
    expect(sub).toMatchObject({
      status: 'disabled',
      disabledReason: 'sustained_failure',
      consecutiveFailures: 5,
      rowVersion: 2,
    });
    const audits = await fx.prisma.auditLog.findMany({ where: { organizationId: s.org.id } });
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({
      actorType: 'system',
      actorId: null,
      action: 'webhook.auto_disabled',
      resourceType: 'webhook',
      resourceId: s.sub.publicId,
      metadata: { subscriptionId: s.sub.publicId, consecutiveFailures: 5 },
    });
    expect(JSON.stringify(audits[0]!.metadata)).not.toContain('receiver.test');
    const outbox = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: s.org.id, eventType: 'notification.alert_requested.v1' },
    });
    expect(outbox).toHaveLength(1);
    expect(notificationAlertRequestedV1.parse(outbox[0]!.payload)).toMatchObject({
      kind: 'webhook_disabled',
      refs: { subscriptionId: s.sub.publicId },
    });
    // The other pending delivery is cancelled by the next claim (the retried one, once due, by
    // the claim or the maintenance pass); nothing more is sent.
    await tick();
    expect((await deliveriesOf(s.sub.id)).map((d) => d.status)).toContain('cancelled');
    await delivery.maintenance.runOnce();
    expect((await deliveriesOf(s.sub.id)).map((d) => d.status)).toEqual(['cancelled', 'cancelled']);
    expect(receiver.received('/disable/main')).toHaveLength(1);
  });

  it('never connects to SSRF targets: blocked deliveries fail with blocked:<reason>', async () => {
    const org = await fx.organization('ssrf');
    const targets = [
      ['https://127.0.0.1/x', 'blocked:loopback'],
      ['https://169.254.169.254/latest/meta-data/', 'blocked:metadata'],
      ['https://metadata.receiver.test/x', 'blocked:metadata'],
      ['https://rebind.receiver.test/x', 'blocked:loopback'],
    ] as const;
    const subs = [];
    for (const [url] of targets) {
      subs.push(await fx.subscription(org.id, { url, eventTypes: ['email.received'] }));
    }
    await publish(received(org.id, await fx.message(org.id)));
    for (const s of subs) await waitForDeliveries(s.id, 1);
    const before = receiver.connections;
    await tick();
    for (const [i, s] of subs.entries()) {
      const [d] = await deliveriesOf(s.id);
      expect(d).toMatchObject({ status: 'failed', lastError: targets[i]![1], attemptCount: 1 });
      const [a] = await fx.prisma.webhookDeliveryAttempt.findMany({
        where: { subscriptionId: s.id },
      });
      expect(a).toMatchObject({ outcome: 'blocked', errorCode: targets[i]![1], httpStatus: null });
    }
    expect(receiver.connections).toBe(before);
    expect(await deliveryMetrics.metrics()).toMatch(
      /webhook_ssrf_blocked_total\{[^}]*reason="metadata"[^}]*\} 2/,
    );
  });

  it('a slow organization does not delay another organization beyond one tick', async () => {
    const slow = await scenario('slow', '/slow/main');
    const fast = await scenario('fast', '/fast/main');
    receiver.program('/slow/main', [{ status: 200, delayMs: 3000 }], 200);
    await publish(received(slow.org.id, await fx.message(slow.org.id)));
    await publish(received(fast.org.id, await fx.message(fast.org.id)));
    await waitForDeliveries(slow.sub.id, 1);
    await waitForDeliveries(fast.sub.id, 1);
    const started = Date.now();
    const report = await delivery.loop.tick();
    expect(report.claimed).toBeGreaterThanOrEqual(2);
    await eventually(
      async () => (await deliveriesOf(fast.sub.id))[0]?.status === 'succeeded',
      2_500,
      'fast organization delivered while the slow one is in flight',
    );
    expect(Date.now() - started).toBeLessThan(2_500);
    expect((await deliveriesOf(slow.sub.id))[0]?.status).toBe('pending');
    await delivery.loop.drain();
    expect((await deliveriesOf(slow.sub.id))[0]?.status).toBe('succeeded');
  });

  it('uses the (status, organization_id, next_attempt_at) index for the due and claim queries', async () => {
    const now = new Date();
    // Prisma returns EXPLAIN columns positionally (f0…f11): f5 = possible_keys, f6 = key.
    const explain = async (sql: Prisma.Sql) => {
      const [row] = await fx.prisma.$queryRaw<Array<Record<string, string | null>>>(
        Prisma.sql`EXPLAIN ${sql}`,
      );
      return {
        possibleKeys: String(row?.possible_keys ?? row?.f5 ?? ''),
        key: String(row?.key ?? row?.f6 ?? ''),
      };
    };
    const due = await explain(delivery.claimer.dueOrganizationsSql(now));
    expect(due.key).toBe('webhook_deliveries_status_org_next_idx');
    const claim = await explain(delivery.claimer.claimSql(fx.organizationIds[0]!, now, 10));
    expect(claim.possibleKeys).toContain('webhook_deliveries_status_org_next_idx');
    expect(claim.key).toBe('webhook_deliveries_status_org_next_idx');
  });
});

/** Pending, due rows of `sub` inserted directly (no stored event: they are never sent). */
async function dueRows(
  org: bigint,
  sub: bigint,
  count: number,
  nextAttemptAt: Date,
): Promise<void> {
  const occurredAt = new Date(Date.now() - 3_600_000);
  await fx.prisma.webhookDelivery.createMany({
    data: Array.from({ length: count }, () => ({
      eventOccurredAt: occurredAt,
      publicId: uuidv7(),
      subscriptionId: sub,
      organizationId: org,
      eventId: uuidv7(),
      eventType: 'email.received',
      deliverySeq: 0,
      trigger: 'event' as const,
      status: 'pending' as const,
      nextAttemptAt,
    })),
  });
}

describe('tenant gates, paused backlogs, slots and replay bounds (verifier round 1 fixes)', () => {
  it('sends nothing for a suspended organization or a revoked feature: due rows are cancelled', async () => {
    const suspended = await scenario('suspended', '/suspended/main');
    const revoked = await scenario('revoked', '/revoked/main');
    receiver.program('/suspended/main', [], 200);
    receiver.program('/revoked/main', [], 200);
    await publish(received(suspended.org.id, await fx.message(suspended.org.id)));
    await publish(received(revoked.org.id, await fx.message(revoked.org.id)));
    await waitForDeliveries(suspended.sub.id, 1);
    await waitForDeliveries(revoked.sub.id, 1);
    await fx.prisma.organization.update({
      where: { id: suspended.org.id },
      data: { status: 'suspended', statusChangedAt: new Date() },
    });
    await fx.prisma.organizationFeature.update({
      where: {
        organizationId_featureKey: { organizationId: revoked.org.id, featureKey: 'webhooks' },
      },
      data: { enabled: false },
    });
    await tick();
    expect((await deliveriesOf(suspended.sub.id))[0]).toMatchObject({
      status: 'cancelled',
      lastError: 'organization_inactive',
      attemptCount: 0,
    });
    expect((await deliveriesOf(revoked.sub.id))[0]).toMatchObject({
      status: 'cancelled',
      lastError: 'webhooks_not_enabled',
      attemptCount: 0,
    });
    expect(receiver.received('/suspended/main')).toHaveLength(0);
    expect(receiver.received('/revoked/main')).toHaveLength(0);
    // A range replay of the suspended organization fails without creating anything.
    const replay = await fx.prisma.webhookReplay.create({
      data: {
        publicId: uuidv7(),
        organizationId: suspended.org.id,
        subscriptionId: suspended.sub.id,
        requestedByType: 'user',
        requestedById: uuidv7(),
        rangeFrom: new Date(Date.now() - 3_600_000),
        rangeTo: new Date(),
        statuses: ['cancelled'],
      },
    });
    expect(await delivery.replays.step(replay.id)).toBe('failed');
    expect(
      await fx.prisma.webhookReplay.findUniqueOrThrow({ where: { id: replay.id } }),
    ).toMatchObject({ status: 'failed', errorCode: 'organization_inactive', createdCount: 0 });
    expect(await deliveriesOf(suspended.sub.id)).toHaveLength(1);
    // The fanout projects nothing more for either organization (once its 1 s index cache expired).
    await new Promise((r) => setTimeout(r, 1_100));
    await publish(received(suspended.org.id, await fx.message(suspended.org.id)));
    await publish(received(revoked.org.id, await fx.message(revoked.org.id)));
    await new Promise((r) => setTimeout(r, 2_500));
    expect(await deliveriesOf(suspended.sub.id)).toHaveLength(1);
    expect(await deliveriesOf(revoked.sub.id)).toHaveLength(1);
  });

  it("a paused subscription's backlog (> 200 due rows) is parked and never blocks an active one", async () => {
    const s = await scenario('paused-backlog', '/paused-backlog/main');
    receiver.program('/paused-backlog/main', [], 200);
    const paused = await fx.subscription(s.org.id, {
      url: `${HOOKS}/paused-backlog/paused`,
      eventTypes: ['email.received'],
      status: 'paused',
    });
    // Older than anything of the active subscription: first in the claim order.
    await dueRows(s.org.id, paused.id, 450, new Date(Date.now() - 1_800_000));
    await publish(received(s.org.id, await fx.message(s.org.id)));
    await waitForDeliveries(s.sub.id, 1);
    let ticks = 0;
    await tickUntil(
      async () => {
        ticks += 1;
        return (await deliveriesOf(s.sub.id))[0]?.status === 'succeeded';
      },
      30_000,
      'active subscription delivered behind a paused backlog',
    );
    expect(ticks).toBeLessThanOrEqual(Math.ceil(451 / 32) + 2); // 2 × 16 rows read per claim
    const parked = await fx.prisma.webhookDelivery.groupBy({
      by: ['status'],
      where: { subscriptionId: paused.id, nextAttemptAt: null },
      _count: { _all: true },
    });
    expect(parked).toEqual([{ status: 'pending', _count: { _all: 450 } }]);
    expect(receiver.received('/paused-backlog/paused')).toHaveLength(0);
    // The due gauges ignore paused work (only this organization is due here: run restricted).
    const gauges = createDeliveryComponents(config, {
      prisma: fx.prisma,
      redis,
      locks,
      metrics: new WebhookMetrics(deliveryMetrics),
      logger: silent,
      organizationIds: [s.org.id],
      lockName: `eg:webhook-maint-it-${fx.suffix}-gauges`,
    }).maintenance;
    // Not parked yet (e.g. in flight at pause time): still not counted.
    await dueRows(s.org.id, paused.id, 3, new Date(Date.now() - 600_000));
    const report = await gauges.runOnce();
    expect(report).toMatchObject({ dueBacklog: 0, oldestDueAgeSeconds: 0, unparked: 0 });
    await gauges.stop();
    // Resume (the api un-parks in the PATCH transaction; the maintenance pass catches the rest).
    await fx.prisma.webhookSubscription.update({
      where: { id: paused.id },
      data: { status: 'active' },
    });
    const resumed = await delivery.maintenance.runOnce();
    expect(resumed.unparked).toBeGreaterThanOrEqual(450);
    expect(
      await fx.prisma.webhookDelivery.count({
        where: { subscriptionId: paused.id, status: 'pending', nextAttemptAt: null },
      }),
    ).toBe(0);
    // Clean up: the rows have no stored event; cancel them before any later tick.
    await fx.prisma.webhookSubscription.update({
      where: { id: paused.id },
      data: { status: 'disabled', disabledReason: 'manual', disabledAt: new Date() },
    });
    await delivery.maintenance.runOnce();
    expect(
      await fx.prisma.webhookDelivery.count({
        where: { subscriptionId: paused.id, status: 'pending' },
      }),
    ).toBe(0);
  });

  it("a crashed process's in-flight slots expire after one lease on real Redis, however busy", async () => {
    let now = Date.now();
    const counters = new InflightCounters(
      redis,
      { leaseMs: 60_000, maxPerOrganization: 2, ratePerMinute: 100_000 },
      () => now,
    );
    // A process takes a slot and is killed (no release).
    expect((await counters.reserve(LEAK_ORG, LEAK_ORG, 4)).result).toBe('ok');
    // Traffic keeps both keys alive for longer than the lease (50 s of reserve/release here).
    for (let i = 0; i < 5; i += 1) {
      now += 10_000;
      const r = await counters.reserve(LEAK_ORG, LEAK_ORG + 1n, 4);
      expect(r.result).toBe('ok');
      expect((await counters.reserve(LEAK_ORG, LEAK_ORG + 1n, 4)).result).toBe('organization');
      await counters.release(r.reservation!);
    }
    expect(await redis.pttl(orgKey(LEAK_ORG))).toBeGreaterThan(55_000); // refreshed: never idle
    now += 15_000; // past the dead process's lease
    expect(await counters.organization(LEAK_ORG)).toBe(0);
    const a = await counters.reserve(LEAK_ORG, LEAK_ORG + 1n, 4);
    const b = await counters.reserve(LEAK_ORG, LEAK_ORG + 1n, 4);
    expect([a.result, b.result]).toEqual(['ok', 'ok']);
    expect(await redis.zcard(orgKey(LEAK_ORG))).toBe(2);
    expect(await redis.pttl(orgKey(LEAK_ORG))).toBeGreaterThan(0);
    await counters.release(a.reservation!);
    await counters.release(b.reservation!);
    expect(await counters.organization(LEAK_ORG)).toBe(0);
  });

  it('range replays respect WEBHOOK_REPLAY_MAX_PER_DELIVERY and wait for the subscription lock', async () => {
    const s = await scenario('replay-bound', '/replay-bound/main');
    receiver.program('/replay-bound/main', [], 200);
    await publish(received(s.org.id, await fx.message(s.org.id)));
    await waitForDeliveries(s.sub.id, 1);
    await tickUntil(
      async () => (await deliveriesOf(s.sub.id))[0]?.status === 'succeeded',
      15_000,
      'original delivered',
    );
    const [original] = await deliveriesOf(s.sub.id);
    const max = config.WEBHOOK_REPLAY_MAX_PER_DELIVERY;
    // `max` earlier replays (e.g. single replays through the api) already exist.
    await fx.prisma.webhookDelivery.createMany({
      data: Array.from({ length: max }, (_, i) => ({
        eventOccurredAt: original!.eventOccurredAt,
        publicId: uuidv7(),
        subscriptionId: s.sub.id,
        organizationId: s.org.id,
        eventId: original!.eventId,
        eventType: original!.eventType,
        deliverySeq: i + 1,
        trigger: 'replay' as const,
        status: 'succeeded' as const,
        completedAt: new Date(),
      })),
    });
    const replay = await fx.prisma.webhookReplay.create({
      data: {
        publicId: uuidv7(),
        organizationId: s.org.id,
        subscriptionId: s.sub.id,
        requestedByType: 'user',
        requestedById: uuidv7(),
        rangeFrom: new Date(original!.eventOccurredAt.getTime() - 60_000),
        rangeTo: new Date(original!.eventOccurredAt.getTime() + 60_000),
        statuses: ['succeeded'],
      },
    });
    // The api's single replay holds the subscription lock: the batch waits for it.
    let release: () => void = () => undefined;
    const held = new Promise<void>((r) => (release = r));
    let locked: () => void = () => undefined;
    const lockTaken = new Promise<void>((r) => (locked = r));
    const holder = fx.prisma.$transaction(
      async (tx) => {
        await tx.$queryRaw`SELECT id FROM webhook_subscriptions WHERE id = ${s.sub.id} FOR UPDATE`;
        locked();
        await held;
      },
      { timeout: 20_000 },
    );
    await lockTaken;
    let done = false;
    const step = delivery.replays.step(replay.id).then((r) => {
      done = true;
      return r;
    });
    await new Promise((r) => setTimeout(r, 500));
    expect(done).toBe(false);
    release();
    await holder;
    expect(await step).toBe('completed');
    expect(
      await fx.prisma.webhookReplay.findUniqueOrThrow({ where: { id: replay.id } }),
    ).toMatchObject({ status: 'completed', matchedCount: 1, createdCount: 0 });
    expect(await deliveriesOf(s.sub.id)).toHaveLength(1 + max);
    expect(await deliveryMetrics.metrics()).toMatch(
      /webhook_replay_events_skipped_total\{[^}]*reason="replay_limit"[^}]*\} [1-9]/,
    );
  });
});

describe('maintenance (W13)', () => {
  it('cancels pending deliveries of disabled subscriptions, purges deleted ones, sets gauges', async () => {
    const org = await fx.organization('maint');
    const disabled = await fx.subscription(org.id, {
      url: `${HOOKS}/maint/main`,
      eventTypes: ['email.received'],
    });
    await publish(received(org.id, await fx.message(org.id)));
    await waitForDeliveries(disabled.id, 1);
    await fx.prisma.webhookSubscription.update({
      where: { id: disabled.id },
      data: { status: 'disabled', disabledReason: 'manual', disabledAt: new Date() },
    });
    const gone = await fx.subscription(org.id, {
      url: `${HOOKS}/maint/old`,
      eventTypes: ['email.received'],
      status: 'deleted',
      deletedAt: new Date(Date.now() - 70 * 86_400_000),
    });
    const report = await delivery.maintenance.runOnce();
    expect(report.outcome).toBe('done');
    expect(report.cancelled).toBeGreaterThanOrEqual(1);
    expect((await deliveriesOf(disabled.id))[0]).toMatchObject({
      status: 'cancelled',
      lastError: 'subscription_disabled',
    });
    expect(await fx.prisma.webhookSubscription.count({ where: { id: gone.id } })).toBe(0);
    expect(report.subscriptionsDeleted).toBe(1);
    expect(await deliveryMetrics.metrics()).toMatch(/webhook_maintenance_leader\{[^}]*\} 1/);
    expect(typeof report.dueBacklog).toBe('number');
  });
});
