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
 * extends the scanner and the ops replay to scan.bec, docs/plan/steps/12-phishing-bec.md; step
 * 4.5 D2 (topology v7) extends them to scan.dlp, docs/plan/steps/13-dlp.md; step 4.6 X11
 * (topology v8) extends the scanner to scan.sandbox.submissions and scan.sandbox.results, the
 * ops replay to the three sandbox queues, and adds the sandbox-controller user eg-sandbox,
 * docs/plan/steps/14-sandbox.md; step 5.2 P15 (topology v9) adds the policy-engine user
 * eg-policy-engine and the notification-worker user eg-notification and extends the ops replay
 * to email.policy.evaluate and email.notifications, docs/plan/steps/16-policy-engine.md; step 5.3
 * Q27 (topology v10) extends the policy-engine user and the ops replay to email.quarantine, the
 * release executor's work queue, docs/plan/steps/17-quarantine.md; step 6.2 §4.3 (topology v11)
 * adds the webhook-worker user eg-webhook (email.webhooks) and extends the ops replay to
 * email.webhooks on email.events, docs/plan/steps/19-webhooks-notifications.md). Probes
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

type Role =
  | 'relay'
  | 'emailWorker'
  | 'scanner'
  | 'deliveryWorker'
  | 'ops'
  | 'urlBrowser'
  | 'sandbox'
  | 'policyEngine'
  | 'notification'
  | 'webhook';
const ROLES = [
  'relay',
  'emailWorker',
  'scanner',
  'deliveryWorker',
  'ops',
  'urlBrowser',
  'sandbox',
  'policyEngine',
  'notification',
  'webhook',
] as const;
const models = new Map<Role, ChannelModel>();
let countsBefore: number[] = [];

/**
 * The AMQP URLs of the role users: those of `stack.rabbitmqRoleUrls()` plus (step 4.3 U2) the
 * url-browser user (`RABBITMQ_URL_BROWSER_URL` of `.env`) and (step 4.6 X11) the
 * sandbox-controller user (`RABBITMQ_SANDBOX_URL`) and (step 5.2 P15) the policy-engine and
 * notification-worker users (`RABBITMQ_POLICY_ENGINE_URL`, `RABBITMQ_NOTIFICATION_URL`) and
 * (step 6.2) the webhook-worker user (`RABBITMQ_WEBHOOK_URL`); never logged.
 */
function roleUrls(): Record<Role, string> {
  const urlBrowser = process.env.RABBITMQ_URL_BROWSER_URL;
  if (!urlBrowser) throw new Error('RABBITMQ_URL_BROWSER_URL is not set (step 4.3 .env keys)');
  const sandbox = process.env.RABBITMQ_SANDBOX_URL;
  if (!sandbox) throw new Error('RABBITMQ_SANDBOX_URL is not set (step 4.6 .env keys)');
  const policyEngine = process.env.RABBITMQ_POLICY_ENGINE_URL;
  if (!policyEngine) throw new Error('RABBITMQ_POLICY_ENGINE_URL is not set (step 5.2 .env keys)');
  const notification = process.env.RABBITMQ_NOTIFICATION_URL;
  if (!notification) throw new Error('RABBITMQ_NOTIFICATION_URL is not set (step 5.2 .env keys)');
  const webhook = process.env.RABBITMQ_WEBHOOK_URL;
  if (!webhook) throw new Error('RABBITMQ_WEBHOOK_URL is not set (step 6.2 .env keys)');
  return { ...stack.rabbitmqRoleUrls(), urlBrowser, sandbox, policyEngine, notification, webhook };
}

/** Message counts of the 21 real queues (administrator, passive declares). */
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
  // B3 (v6) scan.bec; step 4.5 D2 (v7) scan.dlp; step 4.6 X11 (v8) scan.sandbox.submissions and
  // scan.sandbox.results.
  scanner: [
    {
      exchange: 'email.security',
      write:
        '^retry\\.scan\\.(spam|attachment|url|url\\.results|bec|dlp|sandbox\\.submissions|sandbox\\.results)\\.org\\.',
      read: '^$',
    },
    {
      exchange: 'email.events',
      write:
        '^dead-letter\\.scan\\.(spam|attachment|url|url\\.results|bec|dlp|sandbox\\.submissions|sandbox\\.results)(\\.org\\.|$)',
      read: '^$',
    },
  ],
  // Step 4.6 X11: the sandbox-controller publishes its result events and its queue's hops only
  // (`.org.`-anchored: scan.sandbox is a dot-prefix of the email-worker's sandbox queues).
  sandbox: [
    {
      exchange: 'email.security',
      write:
        '^(org\\.[1-9][0-9]{0,19}\\.mail\\.sandbox\\.task_completed\\.v1$|retry\\.scan\\.sandbox\\.org\\.)',
      read: '^$',
    },
    {
      exchange: 'email.events',
      write: '^dead-letter\\.scan\\.sandbox(\\.org\\.|$)',
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
  // Step 5.2 P15 (v9): the policy-engine and the notification-worker publish only the retry
  // (email.policy) and dead-letter (email.events) hops of their own queue; step 5.3 Q27 (v10):
  // the policy-engine owns two queues (email.policy.evaluate and email.quarantine).
  policyEngine: [
    {
      exchange: 'email.policy',
      write: '^retry\\.email\\.(policy\\.evaluate|quarantine)\\.',
      read: '^$',
    },
    {
      exchange: 'email.events',
      write: '^dead-letter\\.email\\.(policy\\.evaluate|quarantine)(\\.|$)',
      read: '^$',
    },
  ],
  notification: [
    { exchange: 'email.policy', write: '^retry\\.email\\.notifications\\.', read: '^$' },
    {
      exchange: 'email.events',
      write: '^dead-letter\\.email\\.notifications(\\.|$)',
      read: '^$',
    },
  ],
  // Step 6.2 §4.3 (v11): the webhook-worker publishes only its queue's hops, both on email.events.
  webhook: [
    {
      exchange: 'email.events',
      write: '^(retry\\.email\\.webhooks\\.|dead-letter\\.email\\.webhooks(\\.|$))',
      read: '^$',
    },
  ],
  ops: [
    { exchange: 'email.ingestion', write: '^retry\\.email\\.received\\.', read: '^$' },
    { exchange: 'email.delivery', write: '^retry\\.email\\.delivery\\.pending\\.', read: '^$' },
    // Step 4.1 S2 / 4.2 A2 / 4.3 U2 / 4.4 B3 / 4.5 D2 / 4.6 X11: replay of the work queues
    // scan.spam, scan.attachment, scan.url, scan.url.inspect, scan.url.results, scan.bec, scan.dlp,
    // scan.sandbox, scan.sandbox.submissions and scan.sandbox.results (home exchange
    // email.security).
    {
      exchange: 'email.security',
      write:
        '^retry\\.scan\\.(spam|attachment|url|url\\.inspect|url\\.results|bec|dlp|sandbox|sandbox\\.submissions|sandbox\\.results)\\.',
      read: '^$',
    },
    // Step 5.2 P15 (v9): replay of email.policy.evaluate and email.notifications; step 5.3 Q27
    // (v10): and of email.quarantine.
    {
      exchange: 'email.policy',
      write: '^retry\\.email\\.(policy\\.evaluate|notifications|quarantine)\\.',
      read: '^$',
    },
    // Step 6.2 (v11): replay of email.webhooks (home exchange email.events), retry hops only.
    { exchange: 'email.events', write: '^retry\\.email\\.webhooks\\.', read: '^$' },
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
    // refuses every key but `retry.scan.(spam|attachment).`, so the probe key is refused there;
    // step 5.2 adds email.policy (topic permission: the retry hops of the two v9 work queues).
    for (const exchange of ['email.security', 'email.policy', 'email.archive', 'email.events']) {
      expect(await publishRefused('ops', exchange), exchange).toBe(ACCESS_REFUSED);
    }
    // Dormant scan queues are not replayable (v8: only the work queues scan.spam,
    // scan.attachment, scan.url, scan.url.inspect, scan.url.results, scan.bec, scan.dlp and the
    // three sandbox queues are; the reserved scan.auth is not).
    expect(
      await publishKeyRefused(
        'ops',
        'email.security',
        'retry.scan.auth.org.1.mail.message.parsed.v1',
      ),
    ).toBe(ACCESS_REFUSED);
    // v8: replay may never mint a sandbox task, result or completion (event keys).
    for (const key of [
      'org.1.mail.sandbox.task_requested.v1',
      'org.1.mail.sandbox.task_completed.v1',
      'org.1.mail.attachment.sandbox_completed.v1',
    ]) {
      expect(await publishKeyRefused('ops', 'email.security', key), key).toBe(ACCESS_REFUSED);
    }
    expect(await replyCodeOf('ops', (ch) => ch.consume('email.received', () => undefined))).toBe(
      ACCESS_REFUSED,
    );
    // v7: replay may never mint a DLP incident (an event key).
    expect(
      await publishKeyRefused('ops', 'email.security', 'org.1.mail.message.dlp_incident.v1'),
    ).toBe(ACCESS_REFUSED);
    // v9: replay may never mint a policy decision, archive or notification request; v10: nor a
    // quarantine release or notification request (event keys).
    for (const key of [
      'org.1.mail.policy.decided.v1',
      'org.1.mail.policy.notification_requested.v1',
      'org.1.mail.quarantine.release_requested.v1',
      'org.1.mail.quarantine.notification_requested.v1',
      'retry.email.policy.org.1.mail.message.scanned.v1',
    ]) {
      expect(await publishKeyRefused('ops', 'email.policy', key), key).toBe(ACCESS_REFUSED);
    }
    const ops = await api.get<TopicPermission[]>(
      `/topic-permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf('ops'))}`,
    );
    const policyWrite = new RegExp(ops.find((t) => t.exchange === 'email.policy')?.write ?? '^$');
    expect(policyWrite.test('retry.email.policy.evaluate.org.1.mail.message.scanned.v1')).toBe(
      true,
    );
    expect(
      policyWrite.test('retry.email.notifications.org.1.mail.policy.notification_requested.v1'),
    ).toBe(true);
    // v10 (step 5.3 Q27): email.quarantine is a replayable work queue.
    expect(
      policyWrite.test('retry.email.quarantine.org.1.mail.quarantine.release_requested.v1'),
    ).toBe(true);
    expect(policyWrite.test('retry.email.quarantines.org.1.x.v1')).toBe(false);
    const opsPermission = await api.get<{ write: string }>(
      `/permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf('ops'))}`,
    );
    // v11 (step 6.2): email.events for the email.webhooks replay (topic: retry hops only).
    expect(opsPermission.write).toBe('^email\\.(ingestion|delivery|security|policy|events)$');
    const eventsWrite = new RegExp(ops.find((t) => t.exchange === 'email.events')?.write ?? '^$');
    expect(eventsWrite.test('retry.email.webhooks.org.1.mail.message.received.v1')).toBe(true);
    // Never an event key, a dead letter or another queue's hop on email.events.
    for (const key of [
      'org.1.mail.message.state_changed.v1',
      'org.1.domain.dns.records_changed.v1',
      'dead-letter.email.webhooks',
      'dead-letter.email.received.org.1.mail.message.received.v1',
      'retry.email.analytics.org.1.mail.message.received.v1',
      'retry.email.webhooksx.org.1.x.v1',
    ]) {
      expect(eventsWrite.test(key), key).toBe(false);
      expect(await publishKeyRefused('ops', 'email.events', key), key).toBe(ACCESS_REFUSED);
    }
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

  it('scanner (steps 4.1–4.6) reads scan.spam, scan.attachment, scan.url, scan.url.results, scan.bec, scan.dlp, scan.sandbox.submissions and scan.sandbox.results (passive) and nothing else', async () => {
    const channel = await model('scanner').createChannel();
    for (const queue of [
      'scan.spam',
      'scan.attachment',
      'scan.url',
      'scan.url.results',
      'scan.bec',
      'scan.dlp',
      'scan.sandbox.submissions',
      'scan.sandbox.results',
    ]) {
      await expect(channel.checkQueue(queue), queue).resolves.toMatchObject({ queue });
    }
    await channel.close();
    for (const queue of [
      'email.received',
      'email.delivery.pending',
      'scan.auth',
      'scan.url.inspect',
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
      // v6: the stage trigger goes through the outbox and the relay, never from the worker.
      'org.1.mail.message.scan_stage_ready.v1',
      // v7 (step 4.5 D14): the DLP incident is written to the outbox in the dlp finalize
      // transaction and published by the relay, never by the worker.
      'org.1.mail.message.dlp_incident.v1',
      // v8 (step 4.6 X11): the task and the completion go through the outbox; the result is the
      // controller's (direct publish); the controller's queue hops are not the scanner's.
      'org.1.mail.sandbox.task_requested.v1',
      'org.1.mail.sandbox.task_completed.v1',
      'org.1.mail.attachment.sandbox_completed.v1',
      'retry.scan.sandbox.org.1.mail.sandbox.task_requested.v1',
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

  it('scanner may publish the retry and dead-letter hops of scan.dlp (v7), anchored on .org.', async () => {
    // The allowed side is checked against the broker's topic permissions (a real publish of an
    // allowed key would leave a message in scan.dlp or email.dead-letter).
    const actual = await api.get<TopicPermission[]>(
      `/topic-permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf('scanner'))}`,
    );
    const write = (exchange: string) =>
      new RegExp(actual.find((t) => t.exchange === exchange)?.write ?? '^$');
    const retry = write('email.security');
    const deadLetter = write('email.events');
    for (const type of ['mail.message.parsed.v1', 'mail.message.rescan_requested.v1']) {
      expect(retry.test(`retry.scan.dlp.org.1.${type}`), type).toBe(true);
      expect(deadLetter.test(`dead-letter.scan.dlp.org.1.${type}`), type).toBe(true);
    }
    expect(deadLetter.test('dead-letter.scan.dlp')).toBe(true);
    // Never the incident event key, the sandbox queue or an unanchored dlp-prefixed queue name.
    expect(retry.test('org.1.mail.message.dlp_incident.v1')).toBe(false);
    expect(retry.test('retry.scan.dlpx.org.1.mail.message.parsed.v1')).toBe(false);
    expect(retry.test('retry.scan.dlp.x.org.1.mail.message.parsed.v1')).toBe(false);
    expect(deadLetter.test('dead-letter.scan.dlp.x')).toBe(false);
    expect(retry.test('retry.scan.sandbox.org.1.mail.attachment.sandbox_requested.v1')).toBe(false);
  });

  it('scanner may publish the retry and dead-letter hops of scan.sandbox.submissions and scan.sandbox.results (v8), never scan.sandbox', async () => {
    const actual = await api.get<TopicPermission[]>(
      `/topic-permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf('scanner'))}`,
    );
    const write = (exchange: string) =>
      new RegExp(actual.find((t) => t.exchange === exchange)?.write ?? '^$');
    const retry = write('email.security');
    const deadLetter = write('email.events');
    const hops: [string, string][] = [
      ['scan.sandbox.submissions', 'mail.attachment.sandbox_requested.v1'],
      ['scan.sandbox.results', 'mail.sandbox.task_completed.v1'],
    ];
    for (const [queue, type] of hops) {
      expect(retry.test(`retry.${queue}.org.1.${type}`), queue).toBe(true);
      expect(deadLetter.test(`dead-letter.${queue}.org.1.${type}`), queue).toBe(true);
      expect(deadLetter.test(`dead-letter.${queue}`), queue).toBe(true);
    }
    expect(retry.test('retry.scan.sandbox.org.1.mail.sandbox.task_requested.v1')).toBe(false);
    expect(deadLetter.test('dead-letter.scan.sandbox.org.1.mail.sandbox.task_requested.v1')).toBe(
      false,
    );
    expect(deadLetter.test('dead-letter.scan.sandbox')).toBe(false);
    expect(retry.test('retry.scan.sandbox.submissionsx.org.1.x.v1')).toBe(false);
  });

  it('sandbox-controller (step 4.6) reads scan.sandbox (passive) and nothing else', async () => {
    const channel = await model('sandbox').createChannel();
    await expect(channel.checkQueue('scan.sandbox')).resolves.toMatchObject({
      queue: 'scan.sandbox',
    });
    await channel.close();
    for (const queue of QUEUE_NAMES.filter((q) => q !== 'scan.sandbox')) {
      expect(await replyCodeOf('sandbox', (ch) => ch.consume(queue, () => undefined)), queue).toBe(
        ACCESS_REFUSED,
      );
    }
  });

  it('sandbox-controller publishes only task results and its own hops: no other event, queue or exchange', async () => {
    for (const key of [
      PROBE_KEY,
      'org.1.mail.sandbox.task_requested.v1',
      'org.1.mail.attachment.sandbox_requested.v1',
      'org.1.mail.attachment.sandbox_completed.v1',
      'org.1.mail.message.scanned.v1',
      'org.1.mail.url.inspection_completed.v1',
      'org.01.mail.sandbox.task_completed.v1',
      'org.1.mail.sandbox.task_completed.v1.extra',
      'org.1.mail.sandbox.task_completed.v2',
      // The email-worker's sandbox queues are dot-extensions of scan.sandbox: the controller's
      // `.org.`-anchored retry key never reaches them.
      'retry.scan.sandbox.submissions.org.1.mail.attachment.sandbox_requested.v1',
      'retry.scan.sandbox.results.org.1.mail.sandbox.task_completed.v1',
      'retry.scan.url.inspect.org.1.mail.url.inspection_requested.v1',
      'retry.scan.spam.org.1.mail.message.parsed.v1',
    ]) {
      expect(await publishKeyRefused('sandbox', 'email.security', key), key).toBe(ACCESS_REFUSED);
    }
    for (const key of [
      PROBE_KEY,
      'dead-letter.scan.sandbox.submissions.org.1.mail.attachment.sandbox_requested.v1',
      'dead-letter.scan.sandbox.results',
      'dead-letter.scan.url.inspect.org.1.mail.url.inspection_requested.v1',
      'org.1.mail.message.state_changed.v1',
    ]) {
      expect(await publishKeyRefused('sandbox', 'email.events', key), key).toBe(ACCESS_REFUSED);
    }
    for (const exchange of ['email.ingestion', 'email.delivery', 'email.policy', 'email.archive']) {
      expect(await publishRefused('sandbox', exchange), exchange).toBe(ACCESS_REFUSED);
    }
    const permission = await api.get<{ configure: string; write: string; read: string }>(
      `/permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf('sandbox'))}`,
    );
    expect(permission).toMatchObject({
      configure: '^$',
      write: '^email\\.(security|events)$',
      read: '^scan\\.sandbox$',
    });
    // The allowed side (checked against the broker's topic permissions, never published).
    const actual = await api.get<TopicPermission[]>(
      `/topic-permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf('sandbox'))}`,
    );
    const write = (exchange: string) =>
      new RegExp(actual.find((t) => t.exchange === exchange)?.write ?? '^$');
    expect(
      write('email.security').test('org.18446744073709551615.mail.sandbox.task_completed.v1'),
    ).toBe(true);
    expect(
      write('email.security').test('retry.scan.sandbox.org.1.mail.sandbox.task_requested.v1'),
    ).toBe(true);
    expect(
      write('email.events').test('dead-letter.scan.sandbox.org.1.mail.sandbox.task_requested.v1'),
    ).toBe(true);
    expect(write('email.events').test('dead-letter.scan.sandbox')).toBe(true);
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

  it.each([
    ['policyEngine', ['email.policy.evaluate', 'email.quarantine']],
    ['notification', ['email.notifications']],
    ['webhook', ['email.webhooks']],
  ] as const)('%s (steps 5.2, 5.3, 6.2) reads %s (passive) and nothing else', async (role, own) => {
    const channel = await model(role).createChannel();
    for (const queue of own) {
      await expect(channel.checkQueue(queue)).resolves.toMatchObject({ queue });
    }
    await channel.close();
    for (const queue of QUEUE_NAMES.filter((q) => !(own as readonly string[]).includes(q))) {
      expect(await replyCodeOf(role, (ch) => ch.consume(queue, () => undefined)), queue).toBe(
        ACCESS_REFUSED,
      );
    }
  });

  it('policy-engine publishes only its own hops: decisions and approvals go through the outbox and the relay', async () => {
    for (const key of [
      PROBE_KEY,
      // Event keys are the relay's: never a decision, archive or notification request directly.
      'org.1.mail.policy.decided.v1',
      'org.1.mail.policy.notification_requested.v1',
      // v10: never a quarantine release or notification request directly (outbox and relay).
      'org.1.mail.quarantine.release_requested.v1',
      'org.1.mail.quarantine.notification_requested.v1',
      // Not the hops of the other email.policy queues.
      'retry.email.notifications.org.1.mail.policy.notification_requested.v1',
      'retry.email.policy.org.1.mail.message.scanned.v1',
    ]) {
      expect(await publishKeyRefused('policyEngine', 'email.policy', key), key).toBe(
        ACCESS_REFUSED,
      );
    }
    for (const key of [
      PROBE_KEY,
      'dead-letter.email.notifications.org.1.mail.policy.notification_requested.v1',
      'dead-letter.email.delivery.pending',
      'org.1.mail.message.state_changed.v1',
    ]) {
      expect(await publishKeyRefused('policyEngine', 'email.events', key), key).toBe(
        ACCESS_REFUSED,
      );
    }
    // Never an approval (email.delivery), an archive request (email.archive) or a scan event.
    for (const exchange of [
      'email.ingestion',
      'email.security',
      'email.delivery',
      'email.archive',
    ]) {
      expect(await publishRefused('policyEngine', exchange), exchange).toBe(ACCESS_REFUSED);
    }
    expect(
      await publishKeyRefused('policyEngine', 'email.delivery', 'org.1.mail.delivery.approved.v1'),
    ).toBe(ACCESS_REFUSED);
    expect(
      await publishKeyRefused(
        'policyEngine',
        'email.archive',
        'org.1.mail.message.archive_requested.v1',
      ),
    ).toBe(ACCESS_REFUSED);
    const permission = await api.get<{ configure: string; write: string; read: string }>(
      `/permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf('policyEngine'))}`,
    );
    expect(permission).toMatchObject({
      configure: '^$',
      write: '^email\\.(policy|events)$',
      read: '^email\\.(policy\\.evaluate|quarantine)$',
    });
    // The allowed side (checked against the broker's topic permissions, never published).
    const actual = await api.get<TopicPermission[]>(
      `/topic-permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf('policyEngine'))}`,
    );
    const write = (exchange: string) =>
      new RegExp(actual.find((t) => t.exchange === exchange)?.write ?? '^$');
    expect(
      write('email.policy').test('retry.email.policy.evaluate.org.1.mail.message.scanned.v1'),
    ).toBe(true);
    expect(
      write('email.events').test(
        'dead-letter.email.policy.evaluate.org.1.mail.message.parse_failed.v1',
      ),
    ).toBe(true);
    expect(write('email.events').test('dead-letter.email.policy.evaluate')).toBe(true);
    // v10 (step 5.3 Q27): the release executor's hops on email.quarantine, nothing wider.
    expect(
      write('email.policy').test(
        'retry.email.quarantine.org.1.mail.quarantine.release_requested.v1',
      ),
    ).toBe(true);
    expect(
      write('email.events').test(
        'dead-letter.email.quarantine.org.1.mail.quarantine.release_requested.v1',
      ),
    ).toBe(true);
    expect(write('email.events').test('dead-letter.email.quarantine')).toBe(true);
    expect(write('email.policy').test('retry.email.quarantines.org.1.x.v1')).toBe(false);
    expect(write('email.events').test('dead-letter.email.quarantinex')).toBe(false);
    expect(write('email.events').test('dead-letter.email.notifications')).toBe(false);
  });

  it('notification-worker publishes only its own hops: no event key, queue or exchange', async () => {
    for (const key of [
      PROBE_KEY,
      'org.1.mail.policy.notification_requested.v1',
      'org.1.mail.policy.decided.v1',
      'retry.email.policy.evaluate.org.1.mail.message.scanned.v1',
      'retry.email.quarantine.org.1.mail.quarantine.release_requested.v1',
      'org.1.mail.quarantine.notification_requested.v1',
    ]) {
      expect(await publishKeyRefused('notification', 'email.policy', key), key).toBe(
        ACCESS_REFUSED,
      );
    }
    for (const key of [
      PROBE_KEY,
      'dead-letter.email.policy.evaluate.org.1.mail.message.scanned.v1',
      'org.1.mail.message.state_changed.v1',
    ]) {
      expect(await publishKeyRefused('notification', 'email.events', key), key).toBe(
        ACCESS_REFUSED,
      );
    }
    for (const exchange of [
      'email.ingestion',
      'email.security',
      'email.delivery',
      'email.archive',
    ]) {
      expect(await publishRefused('notification', exchange), exchange).toBe(ACCESS_REFUSED);
    }
    const permission = await api.get<{ configure: string; write: string; read: string }>(
      `/permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf('notification'))}`,
    );
    expect(permission).toMatchObject({
      configure: '^$',
      write: '^email\\.(policy|events)$',
      read: '^email\\.notifications$',
    });
    const actual = await api.get<TopicPermission[]>(
      `/topic-permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf('notification'))}`,
    );
    const write = (exchange: string) =>
      new RegExp(actual.find((t) => t.exchange === exchange)?.write ?? '^$');
    expect(
      write('email.policy').test(
        'retry.email.notifications.org.1.mail.policy.notification_requested.v1',
      ),
    ).toBe(true);
    expect(write('email.events').test('dead-letter.email.notifications')).toBe(true);
  });

  it('webhook-worker (step 6.2) publishes only the hops of email.webhooks: no event key, queue or exchange', async () => {
    for (const key of [
      PROBE_KEY,
      // Alert requests and webhook events go through the outbox and the relay (or HTTP).
      'org.1.notification.alert_requested.v1',
      'org.1.domain.dns.records_changed.v1',
      'org.1.mail.message.state_changed.v1',
      // Not the hops of another queue whose home exchange is email.events.
      'retry.email.analytics.org.1.mail.message.received.v1',
      'dead-letter.email.notifications.org.1.notification.alert_requested.v1',
      'dead-letter.email.received',
      'retry.email.webhooksx.org.1.x.v1',
      'dead-letter.email.webhooksx',
    ]) {
      expect(await publishKeyRefused('webhook', 'email.events', key), key).toBe(ACCESS_REFUSED);
    }
    for (const exchange of [
      'email.ingestion',
      'email.security',
      'email.policy',
      'email.delivery',
      'email.archive',
    ]) {
      expect(await publishRefused('webhook', exchange), exchange).toBe(ACCESS_REFUSED);
    }
    expect(
      await publishKeyRefused('webhook', 'email.policy', 'org.1.notification.alert_requested.v1'),
    ).toBe(ACCESS_REFUSED);
    const permission = await api.get<{ configure: string; write: string; read: string }>(
      `/permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf('webhook'))}`,
    );
    expect(permission).toMatchObject({
      configure: '^$',
      write: '^email\\.events$',
      read: '^email\\.webhooks$',
    });
    // The allowed side (checked against the broker's topic permissions, never published).
    const actual = await api.get<TopicPermission[]>(
      `/topic-permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf('webhook'))}`,
    );
    const write = new RegExp(actual.find((t) => t.exchange === 'email.events')?.write ?? '^$');
    expect(write.test('retry.email.webhooks.org.1.mail.policy.decided.v1')).toBe(true);
    expect(write.test('dead-letter.email.webhooks.org.1.mail.policy.decided.v1')).toBe(true);
    expect(write.test('dead-letter.email.webhooks')).toBe(true);
  });

  it('relay may publish the two step 6.2 event keys (the org.<id>. prefix on every exchange)', async () => {
    const actual = await api.get<TopicPermission[]>(
      `/topic-permissions/${encodeURIComponent(stack.rabbitmqVhost())}/${encodeURIComponent(userOf('relay'))}`,
    );
    const write = (exchange: string) =>
      new RegExp(actual.find((t) => t.exchange === exchange)?.write ?? '^$');
    expect(write('email.events').test('org.1.domain.dns.records_changed.v1')).toBe(true);
    expect(write('email.policy').test('org.1.notification.alert_requested.v1')).toBe(true);
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
