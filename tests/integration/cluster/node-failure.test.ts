import { randomBytes, randomUUID } from 'node:crypto';
import {
  AmqpConnection,
  ConfirmPublisher,
  type EventHandler,
  processOnceHandler,
  QueueConsumer,
} from '@email-gateway/common';
import { PrismaClient } from '@email-gateway/database';
import { EXAMPLE_EVENT_PAYLOADS, type EventEnvelope } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { compose, run, waitFor } from '../support/compose';
import { stack } from '../support/env';

/**
 * Broker node failure on a 3-node RabbitMQ cluster (docs/plan/steps/07-rabbitmq.md §10 "Broker
 * node failure", WP5). NOT part of `test:integration`: run with `pnpm --filter
 * @email-gateway/integration-tests test:cluster` after this procedure (also in
 * docs/runbooks/rabbitmq-messaging.md "Node-failure test"):
 *
 *   1. docker compose stop api admin-portal smtp-adapter email-worker policy-engine \
 *        delivery-worker event-relay notification-worker archive-worker   # free memory (8 GB VM)
 *      (name the services: `docker compose --profile apps stop` also stops MySQL and the rest of
 *      the default profile, which the test needs; stop clamav only if the nodes do not become
 *      healthy for lack of memory)
 *   2. docker compose --profile rabbitmq-cluster up -d --wait rabbitmq-node1 rabbitmq-node2 rabbitmq-node3
 *   3. node --env-file=.env infrastructure/rabbitmq/init.mjs \
 *        --mgmt-url http://127.0.0.1:${RABBITMQ_CLUSTER_MGMT_HOST_PORT} --users
 *   4. pnpm --filter @email-gateway/integration-tests test:cluster
 *   5. docker compose --profile rabbitmq-cluster rm -sf rabbitmq-node1 rabbitmq-node2 rabbitmq-node3
 *      docker volume rm email-gateway_rabbitmq-cluster-1-data email-gateway_rabbitmq-cluster-2-data \
 *        email-gateway_rabbitmq-cluster-3-data
 *   6. (docker compose start clamav), docker compose --profile apps up -d --wait
 *
 * The test: a ConfirmPublisher (role user eg-relay) and a QueueConsumer of `email.received` (role
 * user eg-email-worker), both connected with ALL THREE node URLs (rotation on reconnect), and a
 * processOnce ledger on the MySQL writer under a unique consumer name. 3 000 events are
 * published to `email.ingestion` at a steady rate with confirms; when a third is confirmed, the
 * node that leads the `email.received` quorum queue (`rabbitmq-queues quorum_status`) is killed
 * (`docker kill`), publishing continues (every unconfirmed event is published again with the
 * same event id until confirmed), then the node is started again. Asserted: every confirmed
 * event id was handled exactly once (one ledger row, one `handled` outcome), nothing was lost,
 * a new leader was elected, the queue is empty at the end. Ledger rows are deleted afterwards.
 */
const TOTAL = Number(process.env.CLUSTER_TEST_EVENTS ?? 3_000);
const BATCH = 20;
const BATCH_INTERVAL_MS = 50;
const RUN = randomBytes(4).toString('hex');
const LEDGER = `it.cluster.${RUN}`;
const ORG = String(9_000_000_000 + Math.floor(Math.random() * 1_000_000_000));
const VHOST = stack.rabbitmqVhost();
const NODES = [1, 2, 3].map((i) => ({
  service: `rabbitmq-node${i}`,
  node: `rabbit@rmq${i}`,
  port: Number(process.env[`RABBITMQ_CLUSTER_NODE${i}_HOST_PORT`] ?? 5700 + i),
}));

type Logger = ConstructorParameters<typeof AmqpConnection>[0]['logger'];
function silentLogger(): Logger {
  const noop = () => undefined;
  const make = (): unknown => ({
    child: () => make(),
    trace: noop,
    debug: noop,
    info: noop,
    warn: noop,
    error: noop,
    fatal: noop,
  });
  return make() as Logger;
}
const logger = silentLogger();

/** A role URL of `.env` pointed at each cluster node (credentials never logged). */
function nodeUrls(roleUrl: string): string[] {
  return NODES.map(({ port }) => {
    const url = new URL(roleUrl);
    url.hostname = '127.0.0.1';
    url.port = String(port);
    url.pathname = `/${encodeURIComponent(VHOST)}`;
    return url.toString();
  });
}

async function clusterRunning(): Promise<string | undefined> {
  const ps = await compose(
    ['--profile', 'rabbitmq-cluster', 'ps', '--status', 'running', '--services'],
    {
      timeoutMs: 20_000,
    },
  );
  const running = new Set(ps.stdout.split('\n').map((l) => l.trim()));
  const missing = NODES.filter((n) => !running.has(n.service)).map((n) => n.service);
  if (missing.length > 0) {
    return `cluster nodes not running: ${missing.join(', ')} (see the procedure in this file's header)`;
  }
  return undefined;
}

/** The leader node of a quorum queue, asked on a running node (`rabbitmq-queues quorum_status`). */
async function leaderOf(queue: string, askService: string): Promise<string | undefined> {
  const result = await compose(
    [
      '--profile',
      'rabbitmq-cluster',
      'exec',
      '-T',
      askService,
      'rabbitmq-queues',
      'quorum_status',
      queue,
      '--vhost',
      VHOST,
      '--formatter',
      'json',
    ],
    { timeoutMs: 30_000 },
  );
  if (result.exitCode !== 0) return undefined;
  try {
    const members = JSON.parse(result.stdout.slice(result.stdout.indexOf('['))) as {
      'Node Name'?: string;
      Membership?: string;
      'Raft State'?: string;
    }[];
    return members.find((m) => m['Raft State'] === 'leader')?.['Node Name'];
  } catch {
    return undefined;
  }
}

async function containerOf(service: string): Promise<string> {
  const ps = await compose(['--profile', 'rabbitmq-cluster', 'ps', '--all', '--quiet', service], {
    timeoutMs: 20_000,
  });
  const id = ps.stdout.trim().split('\n')[0] ?? '';
  if (!/^[0-9a-f]{12,64}$/.test(id)) throw new Error(`${service} container not found`);
  return id;
}

async function healthy(id: string): Promise<boolean> {
  const inspect = await run('docker', ['inspect', '--format', '{{.State.Health.Status}}', id], {
    timeoutMs: 20_000,
  });
  return inspect.stdout.trim() === 'healthy';
}

function envelope(): EventEnvelope {
  return {
    eventId: randomUUID(),
    eventType: 'mail.message.received.v1',
    occurredAt: new Date().toISOString(),
    correlationId: `it-cluster-${RUN}`,
    organizationId: ORG,
    payload: EXAMPLE_EVENT_PAYLOADS['mail.message.received.v1'],
  };
}

const problem = await clusterRunning();
let prisma: PrismaClient;
let pubConnection: AmqpConnection;
let subConnection: AmqpConnection;
let publisher: ConfirmPublisher;
let consumerPublisher: ConfirmPublisher;
let consumer: QueueConsumer<unknown> | undefined;
let killedId: string | undefined;

beforeAll(async () => {
  if (problem) throw new Error(problem);
  prisma = new PrismaClient({ datasourceUrl: stack.databaseUrl() });
  const roles = stack.rabbitmqRoleUrls();
  pubConnection = new AmqpConnection({
    urls: nodeUrls(roles.relay),
    connectionName: `it-cluster-relay-${RUN}`,
    logger,
    heartbeatSeconds: 5,
    reconnect: { baseMs: 200, maxMs: 2_000 },
  });
  subConnection = new AmqpConnection({
    urls: nodeUrls(roles.emailWorker),
    connectionName: `it-cluster-consumer-${RUN}`,
    logger,
    heartbeatSeconds: 5,
    reconnect: { baseMs: 200, maxMs: 2_000 },
  });
  pubConnection.start();
  subConnection.start();
  await pubConnection.waitUntilConnected(30_000);
  await subConnection.waitUntilConnected(30_000);
  publisher = new ConfirmPublisher({
    connection: pubConnection,
    logger,
    appId: 'event-relay',
    confirmTimeoutMs: 5_000,
    maxMessageBytes: 131_072,
  });
  consumerPublisher = new ConfirmPublisher({
    connection: subConnection,
    logger,
    appId: 'email-worker',
    confirmTimeoutMs: 5_000,
    maxMessageBytes: 131_072,
  });
}, 120_000);

afterAll(async () => {
  await consumer?.stop().catch(() => undefined);
  await publisher?.close().catch(() => undefined);
  await consumerPublisher?.close().catch(() => undefined);
  await pubConnection?.close().catch(() => undefined);
  await subConnection?.close().catch(() => undefined);
  if (killedId && !(await healthy(killedId).catch(() => false))) {
    await run('docker', ['start', killedId], { timeoutMs: 60_000 });
  }
  if (prisma) {
    await prisma.messageIdempotency.deleteMany({ where: { consumer: LEDGER } });
    await prisma.$disconnect();
  }
}, 180_000);

describe('RabbitMQ 3-node cluster: leader node killed mid-stream', { timeout: 900_000 }, () => {
  it(`processes ${TOTAL} confirmed events exactly once across the loss of the queue leader`, async () => {
    const leaderBefore = await leaderOf('email.received', NODES[1]!.service);
    expect(leaderBefore, 'quorum_status of email.received').toMatch(/^rabbit@rmq[123]$/);
    const victim = NODES.find((n) => n.node === leaderBefore)!;
    const survivor = NODES.find((n) => n.node !== leaderBefore)!;

    // Consumer: processOnce on the writer, counting `handled` outcomes per event id.
    const outcomes = new Map<string, string[]>();
    const inner = processOnceHandler(prisma, LEDGER, () => Promise.resolve(), {
      txTimeoutMs: 15_000,
    });
    const handler: EventHandler<unknown> = async (event) => {
      const outcome = await inner(event);
      outcomes.set(event.eventId, [...(outcomes.get(event.eventId) ?? []), outcome]);
      return outcome;
    };
    consumer = new QueueConsumer<unknown>({
      connection: subConnection,
      publisher: consumerPublisher,
      queue: 'email.received',
      consumer: LEDGER,
      eventTypes: ['mail.message.received.v1'],
      prefetch: 16,
      logger,
    });
    consumer.start(handler);

    // Publisher: steady batches; unconfirmed items are published again (same event id).
    const confirmed = new Set<string>();
    const pending: EventEnvelope[] = [];
    let created = 0;
    let republished = 0;
    let unconfirmedOutcomes = 0;
    let killedAt = 0;
    let restartedAt = 0;
    const started = Date.now();
    const chaos = (async () => {
      await waitFor(
        'a third of the events confirmed',
        () => Promise.resolve(confirmed.size >= TOTAL / 3),
        {
          timeoutMs: 300_000,
          intervalMs: 50,
        },
      );
      killedId = await containerOf(victim.service);
      const killed = await run('docker', ['kill', killedId], { timeoutMs: 60_000 });
      expect(killed.exitCode, killed.stderr).toBe(0);
      killedAt = Date.now();
      // Down while a further third is published.
      await waitFor(
        'two thirds confirmed with the leader down',
        () => Promise.resolve(confirmed.size >= (2 * TOTAL) / 3),
        { timeoutMs: 300_000, intervalMs: 100 },
      );
      const started2 = await run('docker', ['start', killedId], { timeoutMs: 60_000 });
      expect(started2.exitCode, started2.stderr).toBe(0);
      restartedAt = Date.now();
      await waitFor('the restarted node healthy', () => healthy(killedId!), {
        timeoutMs: 300_000,
        intervalMs: 2_000,
      });
    })();

    while (confirmed.size < TOTAL) {
      while (pending.length < BATCH && created < TOTAL) {
        pending.push(envelope());
        created += 1;
      }
      const batch = pending.splice(0, BATCH);
      if (batch.length === 0) {
        await new Promise((r) => setTimeout(r, BATCH_INTERVAL_MS));
        continue;
      }
      let results: { outcome: string }[];
      try {
        results = await publisher.publishBatch(batch.map((e) => ({ envelope: e })));
      } catch {
        // BrokerUnavailableError: the connection died; nothing of the batch is confirmed.
        results = batch.map(() => ({ outcome: 'unavailable' }));
        await pubConnection.waitUntilConnected(60_000).catch(() => undefined);
      }
      results.forEach((result, i) => {
        const event = batch[i]!;
        if (result.outcome === 'confirmed') confirmed.add(event.eventId);
        else {
          unconfirmedOutcomes += 1;
          republished += 1;
          pending.unshift(event);
        }
      });
      await new Promise((r) => setTimeout(r, BATCH_INTERVAL_MS));
    }
    const publishedAfterMs = Date.now() - started;
    await chaos;

    const leaderAfter = await waitFor(
      'a leader of email.received',
      () => leaderOf('email.received', survivor.service),
      { timeoutMs: 120_000, intervalMs: 2_000 },
    );

    // Every confirmed event handled exactly once; nothing lost.
    await waitFor(
      `${TOTAL} ledger rows`,
      async () => (await prisma.messageIdempotency.count({ where: { consumer: LEDGER } })) >= TOTAL,
      { timeoutMs: 300_000, intervalMs: 1_000 },
    );
    await new Promise((r) => setTimeout(r, 3_000));
    const ledger = await prisma.messageIdempotency.findMany({
      where: { consumer: LEDGER },
      select: { eventId: true },
    });
    const ledgerIds = new Set(ledger.map((r) => r.eventId));
    const lost = [...confirmed].filter((id) => !ledgerIds.has(id));
    expect(lost).toEqual([]);
    expect(ledger).toHaveLength(confirmed.size);
    const handledTwice = [...outcomes].filter(
      ([, list]) => list.filter((o) => o === 'handled').length !== 1,
    );
    expect(handledTwice).toEqual([]);
    const duplicates = [...outcomes.values()].reduce(
      (n, list) => n + list.filter((o) => o === 'duplicate').length,
      0,
    );
    const depth = await (async () => {
      const channel = await subConnection.createChannel();
      try {
        return (await channel.checkQueue('email.received')).messageCount;
      } finally {
        await channel.close().catch(() => undefined);
      }
    })();
    expect(depth).toBe(0);

    process.stdout.write(
      `[cluster-node-failure] events=${TOTAL} confirmed=${confirmed.size} ` +
        `leader_before=${leaderBefore} killed=${victim.node} leader_after=${leaderAfter} ` +
        `publish_s=${(publishedAfterMs / 1000).toFixed(1)} ` +
        `down_s=${((restartedAt - killedAt) / 1000).toFixed(1)} ` +
        `unconfirmed_outcomes=${unconfirmedOutcomes} republished=${republished} ` +
        `ledger_rows=${ledger.length} handled_twice=${handledTwice.length} ` +
        `ledger_duplicates=${duplicates} lost=${lost.length}\n`,
    );
  });
});
