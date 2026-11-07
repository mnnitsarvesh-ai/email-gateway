import { randomUUID } from 'node:crypto';
import { EXCHANGE_NAMES, QUEUE_NAMES } from '@email-gateway/event-contracts';
import { type ChannelModel, connect } from 'amqplib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ManagementApi } from './support/broker';
import { stack } from './support/env';

/**
 * Least privilege of the role users on the real vhost (step 3.2 Q10, review round 1; the
 * step 4.1 scanner user and the ops replay of scan.spam, docs/plan/steps/09-rspamd.md S2; step 4.2
 * A2 extends both to scan.attachment, docs/plan/steps/10-attachment-scanning.md; step 4.3 U2
 * (topology v5) extends them to scan.url and scan.url.results and adds the url-browser user of the
 * isolated browser worker, docs/plan/steps/11-url-protection.md; step 4.4 B3 (topology v6)
 * extends the scanner and the ops replay to scan.bec, docs/plan/steps/12-phishing-bec.md). Probes
 * never leave a message in a real queue: every publish probe is one the broker refuses (a
 * refused publish routes nothing), and the allowed read is a passive checkQueue. Topic
 * permissions restrict the routing keys each user may publish: an allowed key always matches a
 * real binding (`org.#` firehose, `retry.<queue>.#`, `dead-letter.#`), so the allowed side is
 * checked through the management API, and exercised end to end by the stack suites (the relay
 * publishes every event; the workers' retry and dead-letter hops; the api's replay).
 */
const PROBE_KEY = 'it.permission-probe';
const ACCESS_REFUSED = 403;
const api = new ManagementApi();

type Role = 'relay' | 'emailWorker' | 'scanner' | 'deliveryWorker' | 'ops' | 'urlBrowser';
const ROLES = ['relay', 'emailWorker', 'scanner', 'deliveryWorker', 'ops', 'urlBrowser'] as const;
const models = new Map<Role, ChannelModel>();
let countsBefore: number[] = [];

/**
 * The AMQP URLs of the role users: those of `stack.rabbitmqRoleUrls()` plus (step 4.3 U2) the
 * url-browser user (`RABBITMQ_URL_BROWSER_URL` of `.env`; never logged).
 */
function roleUrls(): Record<Role, string> {
  const urlBrowser = process.env.RABBITMQ_URL_BROWSER_URL;
  if (!urlBrowser) throw new Error('RABBITMQ_URL_BROWSER_URL is not set (step 4.3 .env keys)');
  return { ...stack.rabbitmqRoleUrls(), urlBrowser };
}

/** Message counts of the 17 real queues (administrator, passive declares). */
async function queueCounts(): Promise<number[]> {
  const url = new URL(stack.rabbitmqUrl());
  url.pathname = `/${encodeURIComponent(stack.rabbitmqVhost())}`;
  const admin = await connect(url.toString());
  try {
    const channel = await admin.createChannel();
    const counts: number[] = [];
    for (const queue of QUEUE_NAMES) counts.push((await channel.checkQueue(queue)).messageCount);
    return counts;
  } finally {
    await admin.close();
  }
}

beforeAll(async () => {
  countsBefore = await queueCounts();
  const urls = roleUrls();
  for (const role of ROLES) {
    const model = await connect(urls[role], {
      clientProperties: { connection_name: `it-perm-${role}` },
    });
    model.on('error', () => undefined);
    models.set(role, model);
  }
});

afterAll(async () => {
  await Promise.all([...models.values()].map((m) => m.close().catch(() => undefined)));
});

const model = (role: Role): ChannelModel => {
  const m = models.get(role);
  if (!m) throw new Error(`no connection for ${role}`);
  return m;
};

/** Runs `op` on a fresh channel and returns the AMQP reply code the broker closed it with. */
async function replyCodeOf(
  role: Role,
  op: (
    channel: Awaited<ReturnType<ChannelModel['createConfirmChannel']>>,
  ) => Promise<unknown> | void,
): Promise<number | undefined> {
  const channel = await model(role).createConfirmChannel();
  let code: number | undefined;
  const closed = new Promise<void>((resolve) => channel.once('close', () => resolve()));
  channel.on('error', (error: { code?: number }) => (code = error.code));
  try {
    await op(channel);
  } catch (error) {
    code ??= (error as { code?: number }).code;
  }
  await Promise.race([closed, new Promise((r) => setTimeout(r, 3_000))]);
  await channel.close().catch(() => undefined);
  return code;
}

const publishRefused = (role: Role, exchange: string) =>
  replyCodeOf(role, (ch) => {
    ch.publish(exchange, PROBE_KEY, Buffer.from('{}'), { mandatory: false }, () => undefined);
  });

const publishKeyRefused = (role: Role, exchange: string, routingKey: string) =>
  replyCodeOf(role, (ch) => {
    ch.publish(exchange, routingKey, Buffer.from('{}'), { mandatory: false }, () => undefined);
  });

const userOf = (role: Role) => decodeURIComponent(new URL(roleUrls()[role]).username);

interface TopicPermission {
  exchange: string;
  write: string;
  read: string;
}

/** Review round 1: the routing keys each role user may publish (init.mjs ROLE_USERS). */
const EXPECTED_TOPICS: Record<Role, TopicPermission[]> = {
  relay: EXCHANGE_NAMES.map((exchange) => ({
    exchange,
    write: '^org\\.[1-9][0-9]{0,19}\\.',
    read: '^$',
  })),
  emailWorker: [
    { exchange: 'email.ingestion', write: '^retry\\.email\\.received\\.', read: '^$' },
    { exchange: 'email.events', write: '^dead-letter\\.email\\.received(\\.|$)', read: '^$' },
  ],
  // Step 4.1 S2: the scan role publishes only the retry and dead-letter hops of its queues;
  // step 4.2 A2 (topology v4) adds scan.attachment, step 4.3 U2 (v5) scan.url and
  // scan.url.results, anchored on `.org.` so that `url` never covers scan.url.inspect; step 4.4
  // B3 (v6) scan.bec.
  scanner: [
    {
      exchange: 'email.security',
      write: '^retry\\.scan\\.(spam|attachment|url|url\\.results|bec)\\.org\\.',
      read: '^$',
    },
    {
      exchange: 'email.events',
      write: '^dead-letter\\.scan\\.(spam|attachment|url|url\\.results|bec)(\\.org\\.|$)',
      read: '^$',
    },
  ],
  // Step 4.3 U2, U15: the browser worker publishes its result events and its queue's hops only.
  urlBrowser: [
    {
      exchange: 'email.security',
      write:
        '^(org\\.[1-9][0-9]{0,19}\\.mail\\.url\\.inspection_completed\\.v1$|retry\\.scan\\.url\\.inspect\\.)',
      read: '^$',
    },
    {
      exchange: 'email.events',
      write: '^dead-letter\\.scan\\.url\\.inspect(\\.|$)',
      read: '^$',
    },
  ],
  deliveryWorker: [
    {
      exchange: 'email.delivery',
      write: '^(retry|delay)\\.email\\.delivery\\.pending\\.',
      read: '^$',
    },
    {
      exchange: 'email.events',
      write: '^dead-letter\\.email\\.delivery\\.pending(\\.|$)',
      read: '^$',
    },
  ],
  ops: [
    { exchange: 'email.ingestion', write: '^retry\\.email\\.received\\.', read: '^$' },
    { exchange: 'email.delivery', write: '^retry\\.email\\.delivery\\.pending\\.', read: '^$' },
    // Step 4.1 S2 / 4.2 A2 / 4.3 U2 / 4.4 B3: replay of the work queues scan.spam,
    // scan.attachment, scan.url, scan.url.inspect, scan.url.results and scan.bec (home exchange
    // email.security).
    {
      exchange: 'email.security',
      write: '^retry\\.scan\\.(spam|attachment|url|url\\.inspect|url\\.results|bec)\\.',
      read: '^$',
    },
  ],
};

describe('RabbitMQ role permissions on the real vhost', () => {
  it.each(ROLES)(
    '%s has exactly its topic permissions (the routing keys it may publish)',
    async (role) => {
      const actual = await api.get<TopicPermission[]>(
        `/topic-permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf(role))}`,
      );
      const id = (t: TopicPermission) => `${t.exchange} ${t.write} ${t.read}`;
      expect(actual.map(id).sort()).toEqual(EXPECTED_TOPICS[role].map(id).sort());
    },
  );

  it('relay may publish event keys only (org.<id>.<type>), never a retry, delay or other key', async () => {
    for (const exchange of EXCHANGE_NAMES) {
      expect(await publishKeyRefused('relay', exchange, PROBE_KEY), exchange).toBe(ACCESS_REFUSED);
    }
    expect(
      await publishKeyRefused(
        'relay',
        'email.delivery',
        'retry.email.delivery.pending.org.1.mail.delivery.approved.v1',
      ),
    ).toBe(ACCESS_REFUSED);
  });

  it('no consumer and not the api (ops) can publish an event key: approvals are minted by the relay only', async () => {
    const approval = 'org.1.mail.delivery.approved.v1';
    expect(await publishKeyRefused('deliveryWorker', 'email.delivery', approval)).toBe(
      ACCESS_REFUSED,
    );
    expect(await publishKeyRefused('ops', 'email.delivery', approval)).toBe(ACCESS_REFUSED);
    expect(
      await publishKeyRefused('emailWorker', 'email.ingestion', 'org.1.mail.message.received.v1'),
    ).toBe(ACCESS_REFUSED);
    expect(
      await publishKeyRefused('ops', 'email.ingestion', 'org.1.mail.message.received.v1'),
    ).toBe(ACCESS_REFUSED);
  });

  it('a consumer publishes the hops of its own queue only', async () => {
    // The email-worker cannot reach the approval queue through a retry key of another queue.
    expect(
      await publishKeyRefused(
        'emailWorker',
        'email.events',
        'dead-letter.email.delivery.pending.org.1.mail.delivery.approved.v1',
      ),
    ).toBe(ACCESS_REFUSED);
    expect(
      await publishKeyRefused(
        'deliveryWorker',
        'email.events',
        'dead-letter.email.received.org.1.mail.message.received.v1',
      ),
    ).toBe(ACCESS_REFUSED);
    expect(await publishKeyRefused('deliveryWorker', 'email.events', PROBE_KEY)).toBe(
      ACCESS_REFUSED,
    );
    expect(await publishKeyRefused('emailWorker', 'email.ingestion', PROBE_KEY)).toBe(
      ACCESS_REFUSED,
    );
  });

  it('relay cannot read any queue', async () => {
    expect(await replyCodeOf('relay', (ch) => ch.consume('email.received', () => undefined))).toBe(
      ACCESS_REFUSED,
    );
  });

  it('email-worker reads email.received (passive check)', async () => {
    const channel = await model('emailWorker').createChannel();
    await expect(channel.checkQueue('email.received')).resolves.toMatchObject({
      queue: 'email.received',
    });
    await channel.close();
  });

  it('email-worker cannot publish to email.delivery (approvals) or other stage exchanges', async () => {
    for (const exchange of ['email.delivery', 'email.security', 'email.policy', 'email.archive']) {
      expect(await publishRefused('emailWorker', exchange), exchange).toBe(ACCESS_REFUSED);
    }
  });

  it('email-worker cannot consume email.delivery.pending', async () => {
    expect(
      await replyCodeOf('emailWorker', (ch) =>
        ch.consume('email.delivery.pending', () => undefined),
      ),
    ).toBe(ACCESS_REFUSED);
  });

  it('delivery-worker reads email.delivery.pending (passive)', async () => {
    const channel = await model('deliveryWorker').createChannel();
    await expect(channel.checkQueue('email.delivery.pending')).resolves.toMatchObject({
      queue: 'email.delivery.pending',
    });
    await channel.close();
  });

  it('delivery-worker cannot read email.received nor publish to email.ingestion', async () => {
    expect(
      await replyCodeOf('deliveryWorker', (ch) => ch.consume('email.received', () => undefined)),
    ).toBe(ACCESS_REFUSED);
    expect(await publishRefused('deliveryWorker', 'email.ingestion')).toBe(ACCESS_REFUSED);
  });

  it('ops reads email.dead-letter (passive), may write only the replay exchanges, cannot consume email.received', async () => {
    const channel = await model('ops').createChannel();
    await expect(channel.checkQueue('email.dead-letter')).resolves.toMatchObject({
      queue: 'email.dead-letter',
    });
    await channel.close();
    // Review round 1: write narrowed to the home exchanges of the replayable queues. Step 4.1
    // adds email.security (scan.spam; 4.2 scan.attachment), where the topic permission still
    // refuses every key but `retry.scan.(spam|attachment).`, so the probe key is refused there.
    for (const exchange of ['email.security', 'email.policy', 'email.archive', 'email.events']) {
      expect(await publishRefused('ops', exchange), exchange).toBe(ACCESS_REFUSED);
    }
    // Dormant scan queues are not replayable (v6: only the work queues scan.spam,
    // scan.attachment, scan.url, scan.url.inspect, scan.url.results and scan.bec are).
    expect(
      await publishKeyRefused(
        'ops',
        'email.security',
        'retry.scan.sandbox.org.1.mail.attachment.sandbox_requested.v1',
      ),
    ).toBe(ACCESS_REFUSED);
    expect(await replyCodeOf('ops', (ch) => ch.consume('email.received', () => undefined))).toBe(
      ACCESS_REFUSED,
    );
  });

  it.each(ROLES)('%s cannot declare queues or exchanges, nor bind', async (role) => {
    const name = `it.probe.${randomUUID()}`;
    expect(
      await replyCodeOf(role, (ch) => ch.assertQueue(name, { durable: false, autoDelete: true })),
    ).toBe(ACCESS_REFUSED);
    expect(
      await replyCodeOf(role, (ch) => ch.assertExchange(name, 'topic', { durable: false })),
    ).toBe(ACCESS_REFUSED);
    expect(
      await replyCodeOf(role, (ch) => ch.bindQueue('email.received', 'email.ingestion', 'it.#')),
    ).toBe(ACCESS_REFUSED);
  });

  it('scanner (steps 4.1–4.4) reads scan.spam, scan.attachment, scan.url, scan.url.results and scan.bec (passive) and nothing else', async () => {
    const channel = await model('scanner').createChannel();
    for (const queue of [
      'scan.spam',
      'scan.attachment',
      'scan.url',
      'scan.url.results',
      'scan.bec',
    ]) {
      await expect(channel.checkQueue(queue), queue).resolves.toMatchObject({ queue });
    }
    await channel.close();
    for (const queue of [
      'email.received',
      'email.delivery.pending',
      'scan.auth',
      'scan.url.inspect',
      'scan.dlp',
      'scan.sandbox',
      'email.dead-letter',
    ]) {
      expect(await replyCodeOf('scanner', (ch) => ch.consume(queue, () => undefined)), queue).toBe(
        ACCESS_REFUSED,
      );
    }
  });

  it('scanner publishes only the hops of its queues: no event key, no other exchange', async () => {
    // Scan results and sandbox requests reach the broker through the outbox and the relay, never
    // from the worker.
    expect(
      await publishKeyRefused('scanner', 'email.security', 'org.1.mail.message.scanned.v1'),
    ).toBe(ACCESS_REFUSED);
    expect(
      await publishKeyRefused(
        'scanner',
        'email.security',
        'org.1.mail.attachment.sandbox_requested.v1',
      ),
    ).toBe(ACCESS_REFUSED);
    expect(
      await publishKeyRefused(
        'scanner',
        'email.security',
        'retry.scan.sandbox.org.1.mail.attachment.sandbox_requested.v1',
      ),
    ).toBe(ACCESS_REFUSED);
    // v5: the inspection requests go through the outbox; the browser worker's queue and its
    // result events are not the scanner's.
    for (const key of [
      'org.1.mail.url.inspection_requested.v1',
      'org.1.mail.url.inspection_completed.v1',
      'org.1.mail.url.clicked.v1',
      'retry.scan.url.inspect.org.1.mail.url.inspection_requested.v1',
      'retry.scan.dlp.org.1.mail.message.parsed.v1',
      // v6: the stage trigger goes through the outbox and the relay, never from the worker.
      'org.1.mail.message.scan_stage_ready.v1',
    ]) {
      expect(await publishKeyRefused('scanner', 'email.security', key), key).toBe(ACCESS_REFUSED);
    }
    expect(
      await publishKeyRefused(
        'scanner',
        'email.events',
        'dead-letter.scan.url.inspect.org.1.mail.url.inspection_requested.v1',
      ),
    ).toBe(ACCESS_REFUSED);
    expect(
      await publishKeyRefused(
        'scanner',
        'email.events',
        'dead-letter.email.received.org.1.mail.message.received.v1',
      ),
    ).toBe(ACCESS_REFUSED);
    for (const exchange of ['email.ingestion', 'email.delivery', 'email.policy', 'email.archive']) {
      expect(await publishRefused('scanner', exchange), exchange).toBe(ACCESS_REFUSED);
    }
  });

  it('url-browser (step 4.3) reads scan.url.inspect (passive) and nothing else', async () => {
    const channel = await model('urlBrowser').createChannel();
    await expect(channel.checkQueue('scan.url.inspect')).resolves.toMatchObject({
      queue: 'scan.url.inspect',
    });
    await channel.close();
    for (const queue of QUEUE_NAMES.filter((q) => q !== 'scan.url.inspect')) {
      expect(
        await replyCodeOf('urlBrowser', (ch) => ch.consume(queue, () => undefined)),
        queue,
      ).toBe(ACCESS_REFUSED);
    }
  });

  it('url-browser publishes only inspection results and its own hops: no other event, queue or exchange', async () => {
    for (const key of [
      PROBE_KEY,
      'org.1.mail.url.inspection_requested.v1',
      'org.1.mail.url.clicked.v1',
      'org.1.mail.message.scanned.v1',
      'org.1.mail.message.rescan_requested.v1',
      'org.01.mail.url.inspection_completed.v1',
      'org.1.mail.url.inspection_completed.v1.extra',
      'retry.scan.url.org.1.mail.message.parsed.v1',
      'retry.scan.url.results.org.1.mail.url.inspection_completed.v1',
      'retry.scan.spam.org.1.mail.message.parsed.v1',
    ]) {
      expect(await publishKeyRefused('urlBrowser', 'email.security', key), key).toBe(
        ACCESS_REFUSED,
      );
    }
    for (const key of [
      PROBE_KEY,
      'dead-letter.scan.url.org.1.mail.message.parsed.v1',
      'dead-letter.scan.url.results.org.1.mail.url.inspection_completed.v1',
      'org.1.mail.message.state_changed.v1',
    ]) {
      expect(await publishKeyRefused('urlBrowser', 'email.events', key), key).toBe(ACCESS_REFUSED);
    }
    for (const exchange of ['email.ingestion', 'email.delivery', 'email.policy', 'email.archive']) {
      expect(await publishRefused('urlBrowser', exchange), exchange).toBe(ACCESS_REFUSED);
    }
    const permission = await api.get<{ configure: string; write: string; read: string }>(
      `/permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf('urlBrowser'))}`,
    );
    expect(permission).toMatchObject({
      configure: '^$',
      write: '^email\\.(security|events)$',
      read: '^scan\\.url\\.inspect$',
    });
  });

  it('role users cannot open the administrator vhost /', async () => {
    const url = new URL(stack.rabbitmqRoleUrls().relay);
    url.pathname = '/%2F';
    await expect(connect(url.toString())).rejects.toThrow();
  });

  it('left no probe in the real queues (no probe key routes anywhere)', async () => {
    expect(await queueCounts()).toEqual(countsBefore);
  });
});
