import { type ChildProcess, spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AmqpConnection, ConfirmPublisher, QueueConsumer } from '@email-gateway/common';
import { atoMailKey, sha256Hex } from '@email-gateway/ato-detection';
import { FakeIdentityProviderAdapter } from '@email-gateway/ato-detection/fake-provider';
import { EventTypes, type EventEnvelope } from '@email-gateway/event-contracts';
import {
  EVENTS_CONSUMER,
  EVENTS_EVENT_TYPES,
  EVENTS_QUEUE,
  MAIL_CONSUMER,
  MAIL_EVENT_TYPES,
  MAIL_QUEUE,
  RESPONSES_CONSUMER,
  RESPONSES_EVENT_TYPES,
  RESPONSES_QUEUE,
} from '../src/detect/consumers';
import { LEDGERS } from '../src/shared/db';
import { boundAtoMail, createTestVhost, queueDepth, type TestVhost } from './support/broker';
import { Fixtures, ips } from './support/fixtures';
import { Clock, eventually, harness, silent, type Harness } from './support/harness';
import { configure } from './support/scenario';

/**
 * Step 8.4 §10.3 over RabbitMQ (a throwaway vhost with topology v13): (17) redelivered events
 * have one effect, the `ato.responses` path end to end, the lossy `ato.mail` overflow (drop-head,
 * no dead letters) restored by the catch-up, and (19) recovery after a worker process is
 * SIGKILLed mid-batch (a real child `node dist/main.js`; the restarted consumer and the ledger
 * complete the work exactly once).
 */
const fx = new Fixtures();
const clock = new Clock();
const fake = new FakeIdentityProviderAdapter();
let h: Harness;
let vhost: TestVhost;
let conn: AmqpConnection;
let pubConn: AmqpConnection;
let publisher: ConfirmPublisher;
const feeds: QueueConsumer<unknown>[] = [];
const WORKER_DIST = resolve(__dirname, '../dist/main.js');

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

function feed(queue: typeof EVENTS_QUEUE | typeof MAIL_QUEUE | typeof RESPONSES_QUEUE, c = conn) {
  const spec =
    queue === EVENTS_QUEUE
      ? {
          consumer: EVENTS_CONSUMER,
          types: EVENTS_EVENT_TYPES,
          handle: h.comps.eventsConsumer.handle,
        }
      : queue === MAIL_QUEUE
        ? { consumer: MAIL_CONSUMER, types: MAIL_EVENT_TYPES, handle: h.comps.mailConsumer.handle }
        : {
            consumer: RESPONSES_CONSUMER,
            types: RESPONSES_EVENT_TYPES,
            handle: h.comps.respond.handle,
          };
  const consumer = new QueueConsumer<unknown>({
    connection: c,
    publisher: new ConfirmPublisher({
      connection: c,
      logger: silent,
      appId: 'ato-worker',
      confirmTimeoutMs: 15_000,
      maxMessageBytes: 131_072,
    }),
    queue,
    consumer: spec.consumer,
    eventTypes: [...spec.types],
    prefetch: 16,
    logger: silent,
  });
  consumer.start(spec.handle);
  feeds.push(consumer);
  return consumer;
}

async function publish(events: readonly EventEnvelope[]): Promise<void> {
  for (let i = 0; i < events.length; i += 200) {
    const results = await publisher.publishBatch(
      events.slice(i, i + 200).map((envelope) => ({ envelope })),
    );
    expect(results.every((r) => r.outcome === 'confirmed')).toBe(true);
  }
}

beforeAll(async () => {
  vhost = await createTestVhost();
  h = await harness(fx, { clock, fakeAdapter: fake });
  conn = connection('it-ato-worker');
  pubConn = connection('it-ato-relay');
  await conn.waitUntilConnected(15_000);
  await pubConn.waitUntilConnected(15_000);
  publisher = new ConfirmPublisher({
    connection: pubConn,
    logger: silent,
    appId: 'event-relay',
    confirmTimeoutMs: 15_000,
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

describe('ato.events and ato.responses over the broker', () => {
  it('a redelivered event (published twice) has one effect; the respond queue executes provider actions', async () => {
    const org = await fx.organization('bq');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'bq', org.domain);
    const events = feed(EVENTS_QUEUE);
    const responses = feed(RESPONSES_QUEUE);
    const login = await fx.login({
      organizationId: org.id,
      userId: user.id,
      email: user.email,
      outcome: 'failure',
      ip: ips.mumbai(),
      at: clock.now(),
    });
    await publish([login, login]);
    await eventually(
      async () => (await fx.prisma.atoAuthEvent.count({ where: { organizationId: org.id } })) === 1,
      30_000,
      'login processed',
    );
    await new Promise((r) => setTimeout(r, 500));
    expect(await fx.prisma.atoAuthEvent.count({ where: { organizationId: org.id } })).toBe(1);
    // A provider action through ato.responses (fake adapter, synchronous confirmation).
    const account = await fx.prisma.atoAccount.findFirstOrThrow({
      where: { organizationId: org.id },
    });
    await fx.prisma.atoProviderIntegration.create({
      data: {
        organizationId: org.id,
        provider: 'fake',
        bindingKey: sha256Hex('fake|-'),
        status: 'active',
        capabilities: {},
        cursors: {},
        nextPollAt: new Date(Date.now() + 3_600_000),
      },
    });
    fake.addIdentity(user.email, {
      provider: 'fake',
      externalId: `ext-bq-${fx.suffix}`,
      primaryEmail: user.email,
    });
    const action = await h.comps.db.transaction((tx) =>
      h.comps.store.requestResponse(tx, {
        organizationId: org.id,
        accountId: account.id,
        incidentId: null,
        actionType: 'revoke_oauth_grant',
        target: { scope: 'account', accountPublicId: account.publicId },
        actor: { type: 'system', id: null },
        authorization: 'automation_policy',
        providerKind: 'fake',
      }),
    );
    const out = await fx.prisma.messageOutbox.findFirstOrThrow({
      where: {
        organizationId: org.id,
        eventType: EventTypes.AtoResponseRequested,
        aggregateId: action.id.toString(),
      },
    });
    await publish([fx.envelope(EventTypes.AtoResponseRequested, org.id, out.payload)]);
    await eventually(
      async () =>
        (await fx.prisma.atoResponseAction.findUniqueOrThrow({ where: { id: action.id } }))
          .status !== 'approved',
      30_000,
      'provider action settled',
    );
    // revoke_oauth_grant is not declared by the fake adapter: unsupported, never claimed.
    expect(
      (await fx.prisma.atoResponseAction.findUniqueOrThrow({ where: { id: action.id } })).status,
    ).toBe('unsupported');
    await events.stop();
    await responses.stop();
  });
});

describe('the lossy ato.mail queue (D3)', () => {
  it('overflows by drop-head without dead letters; the catch-up restores every message', async () => {
    const org = await fx.organization('lossy');
    await configure(h, org.id);
    await boundAtoMail(vhost.vhost, 50);
    await eventually(
      async () => (await queueDepth(vhost.vhost, MAIL_QUEUE)).policy === 'it-ato-mail-small',
      30_000,
      'policy applied',
    );
    const sender = `bulk@${org.domain}`;
    const ago = (ms: number) => new Date(Date.now() - ms);
    const seeded = await fx.messages(
      org.id,
      Array.from({ length: 200 }, (_, i) => ({
        sender,
        receivedAt: ago(40 * 60_000 - i * 1000),
        recipients: [`r${i}@partner.example`],
        domainId: org.domainId,
      })),
    );
    const deadBefore = (await queueDepth(vhost.vhost, 'email.dead-letter')).messages;
    await publish(seeded.map((m) => fx.scanned(m)));
    await eventually(
      async () => (await queueDepth(vhost.vhost, MAIL_QUEUE)).messages === 50,
      30_000,
      'bounded at 50',
    );
    expect((await queueDepth(vhost.vhost, 'email.dead-letter')).messages).toBe(deadBefore);
    const mail = feed(MAIL_QUEUE);
    await eventually(
      async () => (await queueDepth(vhost.vhost, MAIL_QUEUE)).messages === 0,
      60_000,
      'drained',
    );
    await mail.stop();
    const processedLive = (
      await Promise.all(
        seeded.map((m) => h.comps.db.processed(LEDGERS.mail, atoMailKey(m.id, m.scanId))),
      )
    ).filter(Boolean).length;
    expect(processedLive).toBe(50);
    // Catch-up from the operator's enablement time restores the 150 dropped heads.
    await fx.prisma.organizationFeature.updateMany({
      where: { organizationId: org.id, featureKey: 'ato_detection' },
      data: { updatedAt: ago(2 * 3_600_000) },
    });
    h.comps.orgs.invalidate(org.id);
    while (await h.comps.maintenance.mailCatchup()) {
      /* batches until the cursor reaches the lag bound */
    }
    for (const m of seeded) {
      expect(await h.comps.db.processed(LEDGERS.mail, atoMailKey(m.id, m.scanId))).toBe(true);
    }
    const days = await fx.prisma.atoAccountActivityDaily.findMany({
      where: { organizationId: org.id },
    });
    expect(days.reduce((s, d) => s + d.messages, 0)).toBe(200);
  });
});

describe('recovery after a worker failure (scenario 19)', () => {
  it('SIGKILL of a worker process mid-batch: the restarted consumer completes every event exactly once', async () => {
    expect(
      existsSync(WORKER_DIST),
      'build the worker first (pnpm --filter @email-gateway/ato-worker build)',
    ).toBe(true);
    const org = await fx.organization('kill');
    await configure(h, org.id);
    const users = await Promise.all(
      Array.from({ length: 20 }, (_, i) => fx.user(org.id, `k${i}`, org.domain)),
    );
    const N = 1200;
    const events: EventEnvelope[] = [];
    for (let i = 0; i < N; i++) {
      const u = users[i % users.length]!;
      events.push(
        await fx.login({
          organizationId: org.id,
          userId: u.id,
          email: u.email,
          outcome: i % 7 === 0 ? 'success' : 'failure',
          ip: ips.pune(),
          at: new Date(Date.now() - (N - i) * 500),
        }),
      );
    }
    await publish(events);
    const GEOIP = resolve(__dirname, '../../../packages/ato-detection/test-fixtures/geoip');
    let child: ChildProcess | null = spawn(process.execPath, [WORKER_DIST], {
      cwd: resolve(__dirname, '..'),
      env: {
        ...process.env,
        APP_ENV: 'local',
        NODE_ENV: 'production',
        LOG_LEVEL: 'fatal',
        HTTP_PORT: '3186',
        ATO_WORKER_ROLES: 'detect',
        RABBITMQ_ATO_URL: vhost.adminUrl,
        ATO_EVENTS_PREFETCH: '16',
        ATO_GEOIP_CITY_DB_PATH: `${GEOIP}/synthetic-city.mmdb`,
        ATO_GEOIP_ASN_DB_PATH: `${GEOIP}/synthetic-asn.mmdb`,
        ATO_GEOIP_ANONYMOUS_DB_PATH: `${GEOIP}/synthetic-anonymous.mmdb`,
        ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES: 'true',
        ATO_PROVIDER_FAKE_ENABLED: 'false',
      },
      stdio: 'ignore',
    });
    try {
      const count = () => fx.prisma.atoAuthEvent.count({ where: { organizationId: org.id } });
      await eventually(
        async () => (await count()) >= N / 4,
        120_000,
        'the child processed a quarter',
        25,
      );
      child.kill('SIGKILL');
      await new Promise((r) => child!.once('exit', r));
      child = null;
      const atKill = await count();
      expect(atKill).toBeLessThan(N);
      const restarted = feed(EVENTS_QUEUE, connection('it-ato-restart'));
      await eventually(async () => (await count()) === N, 300_000, 'every event processed', 200);
      await new Promise((r) => setTimeout(r, 1000));
      await restarted.stop();
      expect(await count()).toBe(N);
      const ledger = await fx.prisma.messageIdempotency.count({
        where: { consumer: LEDGERS.events, eventId: { in: events.map((e) => e.eventId) } },
      });
      expect(ledger).toBe(N);
      const days = await fx.prisma.atoAccountActivityDaily.findMany({
        where: { organizationId: org.id },
      });
      expect(days.reduce((s, d) => s + d.authSuccess + d.authFailure, 0)).toBe(N);
    } finally {
      child?.kill('SIGKILL');
    }
  });
});
