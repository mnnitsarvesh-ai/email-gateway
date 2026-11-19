import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AmqpConnection, ConfirmPublisher, QueueConsumer } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import type { EventEnvelope } from '@email-gateway/event-contracts';
import {
  EVENTS_CONSUMER,
  EVENTS_EVENT_TYPES,
  EVENTS_QUEUE,
  MAIL_CONSUMER,
  MAIL_EVENT_TYPES,
  MAIL_QUEUE,
} from '../src/detect/consumers';
import { LEDGERS } from '../src/shared/db';
import { createTestVhost, queueDepth, type TestVhost } from './support/broker';
import { Fixtures, ips, type MessageSpec, type SeededMessage } from './support/fixtures';
import { Clock, eventually, harness, silent, type Harness } from './support/harness';
import { configure } from './support/scenario';

/**
 * Step 8.4 §10.3 scenario 18 (high-volume ingestion), the laptop baseline of
 * docs/performance/ato.md: ≥ 50 000 scanned outbound events and ≥ 20 000 telemetry entries across
 * ≥ 20 organizations through RabbitMQ (throwaway vhost) into one in-process worker with the
 * production prefetch (32 per queue). Asserts no loss and no duplicates; prints the measurements
 * (`ATO-PERF {...}`). These are local numbers on one laptop, not a verification of the 1M/day
 * production estimate (D22).
 */
const ORGS = Number(process.env.IT_ATO_VOLUME_ORGS ?? 20);
const MESSAGES_PER_ORG = Number(process.env.IT_ATO_VOLUME_MESSAGES_PER_ORG ?? 2500);
const MAILBOXES_PER_ORG = 25;
const SUBMISSION_BATCHES_PER_ORG = 5; // × 200 entries
const AUTH_BATCHES_PER_ORG = 1; // × 200 entries
const PREFETCH = 32;
/** Events are spread over the last 15 minutes (the lag histogram then measures processing delay). */
const SPREAD_MS = 15 * 60_000;

const fx = new Fixtures();
const clock = new Clock();
let h: Harness;
let vhost: TestVhost;
let conn: AmqpConnection;
let pubConn: AmqpConnection;
let publisher: ConfirmPublisher;
const feeds: QueueConsumer<unknown>[] = [];

function connection(name: string): AmqpConnection {
  const c = new AmqpConnection({
    urls: [vhost.adminUrl],
    connectionName: name,
    logger: silent,
    reconnect: { baseMs: 50, maxMs: 500 },
  });
  c.start();
  return c;
}

function feed(queue: typeof EVENTS_QUEUE | typeof MAIL_QUEUE): QueueConsumer<unknown> {
  const events = queue === EVENTS_QUEUE;
  const consumer = new QueueConsumer<unknown>({
    connection: conn,
    publisher: new ConfirmPublisher({
      connection: conn,
      logger: silent,
      appId: 'ato-worker',
      confirmTimeoutMs: 15_000,
      maxMessageBytes: 131_072,
    }),
    queue,
    consumer: events ? EVENTS_CONSUMER : MAIL_CONSUMER,
    eventTypes: [...(events ? EVENTS_EVENT_TYPES : MAIL_EVENT_TYPES)],
    prefetch: PREFETCH,
    logger: silent,
  });
  consumer.start(events ? h.comps.eventsConsumer.handle : h.comps.mailConsumer.handle);
  feeds.push(consumer);
  return consumer;
}

async function publish(events: readonly EventEnvelope[]): Promise<void> {
  for (let i = 0; i < events.length; i += 500) {
    const results = await publisher.publishBatch(
      events.slice(i, i + 500).map((envelope) => ({ envelope })),
    );
    if (!results.every((r) => r.outcome === 'confirmed')) throw new Error('publish not confirmed');
  }
}

/** p50/p95 of a histogram from its cumulative buckets (upper bounds, seconds). */
async function quantiles(
  name: string,
  query?: string,
): Promise<{ p50: number | null; p95: number | null; count: number }> {
  const text = (await h.metrics.registry.getSingleMetricAsString(name))
    .split('\n')
    .filter((l) => query === undefined || l.includes(`query="${query}"`))
    .join('\n');
  const buckets = new Map<number, number>();
  let count = 0;
  for (const line of text.split('\n')) {
    const m = /_bucket\{.*le="([^"]+)".*\} (\d+(?:\.\d+)?)/.exec(line);
    if (m) {
      const le = m[1] === '+Inf' ? Infinity : Number(m[1]);
      buckets.set(le, (buckets.get(le) ?? 0) + Number(m[2]));
    }
    const c = /_count\{.*\} (\d+)/.exec(line);
    if (c) count += Number(c[1]);
  }
  const sorted = [...buckets.entries()].sort((a, b) => a[0] - b[0]);
  const q = (p: number) => sorted.find(([, n]) => n >= p * count)?.[0] ?? null;
  return { p50: q(0.5), p95: q(0.95), count };
}

beforeAll(async () => {
  vhost = await createTestVhost();
  h = await harness(fx, { clock });
  conn = connection('it-ato-volume');
  pubConn = connection('it-ato-volume-relay');
  await conn.waitUntilConnected(15_000);
  await pubConn.waitUntilConnected(15_000);
  publisher = new ConfirmPublisher({
    connection: pubConn,
    logger: silent,
    appId: 'event-relay',
    confirmTimeoutMs: 30_000,
    maxMessageBytes: 131_072,
  });
});

afterAll(async () => {
  for (const f of feeds) await f.stop().catch(() => undefined);
  await publisher?.close().catch(() => undefined);
  await conn?.close().catch(() => undefined);
  await pubConn?.close().catch(() => undefined);
  await h?.close();
  await vhost?.cleanup().catch(() => undefined);
  await fx.cleanup();
});

describe('high-volume ingestion (scenario 18)', () => {
  it(`${ORGS * MESSAGES_PER_ORG} scanned events and ${ORGS * (SUBMISSION_BATCHES_PER_ORG + AUTH_BATCHES_PER_ORG) * 200} telemetry entries across ${ORGS} organizations: no loss, no duplicates`, async () => {
    const t0 = Date.now();
    const now = Date.now();
    const telemetry: EventEnvelope[] = [];
    const seeded: SeededMessage[] = [];
    let submissionEntries = 0;
    let authEntries = 0;
    for (let o = 0; o < ORGS; o++) {
      const org = await fx.organization(`vol${o}`);
      await configure(h, org.id);
      const connectors = [
        await fx.connector(org.id, `c${o}a`),
        await fx.connector(org.id, `c${o}b`),
      ];
      const mailboxes = Array.from({ length: MAILBOXES_PER_ORG }, (_, i) => `mb${i}@${org.domain}`);
      const queueIds: (string | null)[] = [];
      const specs: MessageSpec[] = Array.from({ length: MESSAGES_PER_ORG }, (_, i) => {
        const queueId = i < SUBMISSION_BATCHES_PER_ORG * 200 ? fx.queueId() : null;
        queueIds.push(queueId);
        return {
          sender: mailboxes[i % mailboxes.length]!,
          receivedAt: new Date(now - SPREAD_MS + Math.floor((i * SPREAD_MS) / MESSAGES_PER_ORG)),
          recipients: Array.from(
            { length: 1 + (i % 3) },
            (_, r) => `r${r}@d${(i + r) % 50}-${o}.example`,
          ),
          internalRecipients: i % 10 === 0 ? [`colleague@${org.domain}`] : [],
          queueId,
          clientIp: ips.pune(),
          verdict: i % 200 === 0 ? 'malicious' : 'clean',
          reasonCodes: i % 200 === 0 ? ['url.phishing_high_confidence'] : [],
          domainId: org.domainId,
        };
      });
      seeded.push(...(await fx.messages(org.id, specs)));
      for (let b = 0; b < SUBMISSION_BATCHES_PER_ORG; b++) {
        const entries = Array.from({ length: 200 }, (_, k) => {
          const i = b * 200 + k;
          return {
            at: new Date(now - SPREAD_MS + Math.floor((i * SPREAD_MS) / MESSAGES_PER_ORG) - 500),
            connectorId: connectors[i % 2]!.id,
            queueId: queueIds[i]!,
            clientIp: ips.pune(),
            sender: mailboxes[i % mailboxes.length]!,
          };
        });
        submissionEntries += entries.length;
        telemetry.push(fx.smtpSubmission(org.id, entries));
      }
      for (let b = 0; b < AUTH_BATCHES_PER_ORG; b++) {
        const entries = Array.from({ length: 200 }, (_, k) => ({
          at: new Date(now - SPREAD_MS + k * 1000),
          result: k % 5 === 0 ? ('fail' as const) : ('ok' as const),
          connectorId: connectors[k % 2]!.id,
          clientIp: ips.london(),
        }));
        authEntries += entries.length;
        telemetry.push(fx.smtpAuth(org.id, entries));
      }
    }
    const seededMs = Date.now() - t0;
    const ledgerBefore = {
      events: await fx.prisma.messageIdempotency.count({
        where: { consumer: LEDGERS.events, processedAt: { gte: fx.startedAt } },
      }),
      mail: await fx.prisma.messageIdempotency.count({
        where: { consumer: LEDGERS.mail, processedAt: { gte: fx.startedAt } },
      }),
    };

    // Telemetry first (connector attribution of the queue ids), then the scanned events.
    const t1 = Date.now();
    await publish(telemetry);
    feed(EVENTS_QUEUE);
    await eventually(
      async () => (await queueDepth(vhost.vhost, EVENTS_QUEUE)).messages === 0,
      1_800_000,
      'telemetry drained',
      1000,
    );
    await eventually(
      async () =>
        (await fx.prisma.messageIdempotency.count({
          where: { consumer: LEDGERS.events, processedAt: { gte: fx.startedAt } },
        })) -
          ledgerBefore.events ===
        submissionEntries + authEntries,
      1_800_000,
      'every telemetry entry ledgered',
      500,
    );
    const telemetryMs = Date.now() - t1;

    const t2 = Date.now();
    const scanned = seeded.map((m) => fx.scanned(m));
    await publish(scanned);
    const publishMs = Date.now() - t2;
    const t3 = Date.now();
    feed(MAIL_QUEUE);
    await eventually(
      async () => (await queueDepth(vhost.vhost, MAIL_QUEUE)).messages === 0,
      3_600_000,
      'mail drained',
      1000,
    );
    await eventually(
      async () =>
        (await fx.prisma.messageIdempotency.count({
          where: { consumer: LEDGERS.mail, processedAt: { gte: fx.startedAt } },
        })) -
          ledgerBefore.mail ===
        seeded.length,
      3_600_000,
      'every message ledgered',
      1000,
    );
    const mailMs = Date.now() - t3;

    // No loss, no duplicates: the day rows count every message exactly once, per organization.
    const ids = fx.organizationIds;
    const mailboxDays = await fx.prisma.$queryRaw<Array<{ n: bigint | number }>>`
      SELECT COALESCE(SUM(d.messages), 0) AS n FROM ato_account_activity_daily d
      JOIN ato_accounts a ON a.id = d.account_id
      WHERE a.kind = 'mailbox' AND d.organization_id IN (${Prisma.join(ids)})`;
    const mailboxTotal = Number(mailboxDays[0]?.n ?? 0);
    expect(mailboxTotal).toBe(seeded.length);
    const authRows = await fx.prisma.atoAuthEvent.aggregate({
      where: { organizationId: { in: ids }, source: 'smtp_auth' },
      _sum: { attemptCount: true },
    });
    expect(authRows._sum.attemptCount).toBe(authEntries);
    const attributed = await fx.prisma.$queryRaw<Array<{ n: bigint | number }>>`
      SELECT COALESCE(SUM(d.messages), 0) AS n FROM ato_account_activity_daily d
      JOIN ato_accounts a ON a.id = d.account_id
      WHERE a.kind = 'smtp_connector' AND d.organization_id IN (${Prisma.join(ids)})`;
    expect(Number(attributed[0]?.n ?? 0)).toBe(ORGS * SUBMISSION_BATCHES_PER_ORG * 200);

    const perf = {
      organizations: ORGS,
      scannedEvents: seeded.length,
      telemetryEntries: submissionEntries + authEntries,
      telemetryBatches: telemetry.length,
      seedSeconds: Math.round(seededMs / 1000),
      telemetrySeconds: Math.round(telemetryMs / 1000),
      telemetryEntriesPerSecond: Math.round(
        ((submissionEntries + authEntries) * 1000) / telemetryMs,
      ),
      publishScannedSeconds: Math.round(publishMs / 1000),
      mailSeconds: Math.round(mailMs / 1000),
      mailEventsPerSecond: Math.round((seeded.length * 1000) / mailMs),
      detectionDuration: {
        outbound_message: await quantiles('ato_detection_duration_seconds'),
      },
      detectionLag: await quantiles('ato_detection_lag_seconds'),
      prepare: await quantiles('ato_db_query_seconds', 'prepare'),
      ledgerTx: await quantiles('ato_db_query_seconds', 'ledger_tx'),
      retriedErrors: await h.metric('ato_events_total', { result: 'error' }),
      signals: await fx.prisma.atoRiskSignal.count({ where: { organizationId: { in: ids } } }),
      incidents: await fx.prisma.securityIncident.count({ where: { organizationId: { in: ids } } }),
      accounts: await fx.prisma.atoAccount.count({ where: { organizationId: { in: ids } } }),
      prefetch: PREFETCH,
    };
    process.stdout.write(`ATO-PERF ${JSON.stringify(perf)}\n`);
    expect(perf.incidents).toBeGreaterThan(0);
  }, 7_200_000);
});
