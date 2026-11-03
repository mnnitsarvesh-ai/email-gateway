import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { composeExec, composeOk, waitFor } from './support/compose';
import { rawLmtp } from './support/lmtp-raw';
import { buildMessage } from './support/messages';
import { flushQueue, listQueue, waitForLog, waitForQueueDrained } from './support/postfix';
import { sha256, SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady, smtpStackGate } from './support/smtp-stack';
import { reply, swaks } from './support/smtp-tools';

/**
 * Durability of the inbound path (docs/plan/steps/04-smtp-gateway.md §2.0 invariant 2, D7; §9
 * stack suites 5, 6 and 7): `250` only after durable acceptance, infrastructure failures are
 * `4xx`, Postfix's queue survives restarts, and an LMTP retry after a lost `250` never creates a
 * second message. MinIO is stopped and Postfix restarted for real; both are always brought back.
 */
const gate = await smtpStackGate();
const fx = new SmtpFixtures();
let org = 0n;
let domain: FixtureDomain;

async function sendInbound(local: string, subject: string) {
  const to = [`${local}@${domain.name}`];
  const { text } = buildMessage({ from: 'sender@example.org', to, subject });
  const result = await swaks({
    server: 'postfix',
    port: 25,
    from: 'sender@example.org',
    to,
    data: text,
  });
  expect(reply(result, 'DATA-END').text).toMatch(/^250 2\.0\.0 Ok: queued as /);
  return result.queueId!;
}

const stored = (queueId: string) =>
  fx.prisma.emailMessage.count({ where: { organizationId: org, mtaQueueId: queueId } });

async function startMinio() {
  await composeOk(['start', 'minio'], { timeoutMs: 120_000 });
  await waitFor(
    'MinIO to be ready',
    async () => (await fetch(`${process.env.S3_ENDPOINT}/minio/health/ready`)).ok,
    { timeoutMs: 90_000, intervalMs: 1_000 },
  );
}

async function waitForPostfix() {
  await waitFor(
    'postfix to run',
    async () => (await composeExec('postfix', ['postfix', 'status'])).exitCode === 0,
    { timeoutMs: 90_000, intervalMs: 1_000 },
  );
}

/** Deferred in the inbound queue with the adapter's generic LMTP tempfail. */
async function waitForDeferred(queueId: string, since: Date) {
  await waitForLog(
    'postfix',
    since,
    new RegExp(`${queueId}: to=<.*status=deferred.*451 4\\.3\\.0`),
    90_000,
  );
  const entry = (await listQueue('postfix')).find((m) => m.queue_id === queueId);
  expect(entry?.queue_name).toBe('deferred');
  expect(entry?.recipients[0]?.delay_reason).toMatch(/451 4\.3\.0 Temporary failure/);
}

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('durable');
  domain = await fx.domain(org, 'durable');
}, 60_000);

afterAll(async () => {
  if (gate.skip) return;
  // Never leave the stack degraded, whatever happened above.
  await startMinio();
  await waitForPostfix();
  await waitForQueueDrained('postfix', [domain.name]).catch(() => undefined);
  await fx.cleanup();
}, 300_000);

describe.skipIf(gate.skip)(
  'SMTP stack: persistence failure (suite 5)',
  { timeout: 300_000 },
  () => {
    it('accepts in-session, defers with LMTP 451 while S3 is down, stores exactly once after recovery', async () => {
      const since = new Date(Date.now() - 1_000);
      let queueId = '';
      try {
        await composeOk(['stop', 'minio'], { timeoutMs: 120_000 });
        queueId = await sendInbound('persist', 'Persistence failure');
        await waitForDeferred(queueId, since);
        expect(await stored(queueId)).toBe(0);
        expect(await fx.prisma.messageIdentity.count({ where: { organizationId: org } })).toBe(0);
      } finally {
        await startMinio();
      }
      await flushQueue('postfix');
      await waitFor(
        'the deferred message to be stored',
        async () => (await stored(queueId)) === 1,
        {
          timeoutMs: 120_000,
          intervalMs: 1_000,
        },
      );
      await waitForQueueDrained('postfix', [domain.name]);
      expect(await stored(queueId)).toBe(1);
      expect(await fx.prisma.messageIdentity.count({ where: { organizationId: org } })).toBe(1);
      // Step 3.1: the email-worker adds the parsed parts under org/{id}/part/; the EML is counted.
      expect(await fx.emlObjectKeys(org)).toHaveLength(1);
    });
  },
);

describe.skipIf(gate.skip)('SMTP stack: gateway restart (suite 6)', { timeout: 300_000 }, () => {
  it('keeps deferred mail across `docker compose restart postfix` and delivers it after recovery', async () => {
    const since = new Date(Date.now() - 1_000);
    let queueId = '';
    try {
      await composeOk(['stop', 'minio'], { timeoutMs: 120_000 });
      queueId = await sendInbound('restart', 'Survives restart');
      await waitForDeferred(queueId, since);
      await composeOk(['restart', 'postfix'], { timeoutMs: 180_000 });
      await waitForPostfix();
      // The queue file is on the postfix-spool volume: still there after the restart.
      const entry = (await listQueue('postfix')).find((m) => m.queue_id === queueId);
      expect(entry?.queue_name).toBe('deferred');
      expect(await stored(queueId)).toBe(0);
    } finally {
      await startMinio();
      await waitForPostfix();
    }
    await flushQueue('postfix');
    await waitFor(
      'the message to be delivered after recovery',
      async () => (await stored(queueId)) === 1,
      {
        timeoutMs: 120_000,
        intervalMs: 1_000,
      },
    );
    await waitForQueueDrained('postfix', [domain.name]);
    expect(await stored(queueId)).toBe(1);
  });
});

describe.skipIf(gate.skip)(
  'SMTP stack: LMTP retry after a lost 250 (suite 7)',
  { timeout: 300_000 },
  () => {
    it('answers 250 to a duplicate LMTP transaction (same MTA, queue id and bytes) without new rows', async () => {
      const queueId = await sendInbound('retry', 'Retry after lost 250');
      const original = await waitFor('the original message', () =>
        fx.prisma.emailMessage
          .findFirst({ where: { organizationId: org, mtaQueueId: queueId } })
          .then((row) => row ?? undefined),
      );
      const bytes = await fx.object(original.emlObjectKey);
      expect(sha256(bytes)).toBe(original.emlSha256);
      // Step 2.3 (docs/plan/steps/05-routing.md R5, R9.1): with the delivery-worker running, the
      // development pass-through and the delivery recorder add their own email_events
      // (`delivery.*`, source delivery-worker) and outbox rows (`mail.delivery.*`) for this message;
      // this suite checks what INGESTION wrote, so it counts only those rows.
      const ingestionEvents = { organizationId: org, sourceService: 'smtp-adapter' };
      const ingestionOutbox = { organizationId: org, eventType: 'mail.message.received.v1' };
      const before = {
        identities: await fx.prisma.messageIdentity.count({ where: { organizationId: org } }),
        messages: await fx.messageCount(org),
        recipients: await fx.prisma.emailRecipient.count({ where: { organizationId: org } }),
        events: await fx.prisma.emailEvent.count({ where: ingestionEvents }),
        outbox: await fx.prisma.messageOutbox.count({ where: ingestionOutbox }),
        objects: (await fx.emlObjectKeys(org)).length,
      };
      const mtaId = (await composeExec('postfix', ['postconf', '-h', 'myhostname'])).stdout.trim();

      // Replays exactly what Postfix's LMTP client sends when it retries the same queue file.
      const replies = await rawLmtp({
        host: gate.adapterHost,
        port: 10050,
        lhlo: mtaId,
        xforward: [
          `NAME=client.integration.test ADDR=${original.clientIp ?? '[UNAVAILABLE]'} PROTO=ESMTP HELO=${original.clientHelo ?? '[UNAVAILABLE]'}`,
          `IDENT=${queueId} SOURCE=REMOTE`,
        ],
        from: original.envelopeFrom,
        to: [`retry@${domain.name}`],
        message: bytes,
      });
      expect(replies.get('RCPT#0')).toMatch(/^250 /);
      expect(replies.get('DATA-END#0')).toBe('250 2.0.0 Ok');

      expect({
        identities: await fx.prisma.messageIdentity.count({ where: { organizationId: org } }),
        messages: await fx.messageCount(org),
        recipients: await fx.prisma.emailRecipient.count({ where: { organizationId: org } }),
        events: await fx.prisma.emailEvent.count({ where: ingestionEvents }),
        outbox: await fx.prisma.messageOutbox.count({ where: ingestionOutbox }),
        objects: (await fx.emlObjectKeys(org)).length,
      }).toEqual(before);
      // The deterministic object key was overwritten with identical bytes, never orphaned.
      expect(sha256(await fx.object(original.emlObjectKey))).toBe(original.emlSha256);
    });
  },
);
