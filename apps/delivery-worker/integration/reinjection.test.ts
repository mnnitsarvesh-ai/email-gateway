import { buildGatewayTrace, countGatewayPasses } from '@email-gateway/common';
import { deliveryStatusChangedV1, EventTypes } from '@email-gateway/event-contracts';
import { parseReinjectionToken, reinjectionToken } from '@email-gateway/mail-routing';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { FakePostfix } from './support/fake-postfix';
import { DEFAULT_EML, Fixtures, type MessageFixture, workerConfig } from './support/fixtures';
import { buildWorker, FAST, makeDue, type TestWorker } from './support/worker';

const fx = new Fixtures();
const postfix = new FakePostfix();
let worker: TestWorker;
let org: bigint;
let tenantDomain: string;
let secret: string;
let gatewayId: string;

beforeAll(async () => {
  await postfix.start();
  const config = workerConfig({ ...FAST, ...postfix.configOverrides });
  secret = config.GATEWAY_TRACE_SECRET;
  gatewayId = config.GATEWAY_TRACE_ID;
  worker = buildWorker(fx, config);
  org = await fx.organization('reinject');
  tenantDomain = fx.name('in');
  await fx.domain(org, tenantDomain, { destination: 'mail.customer.example' });
});
afterEach(() => postfix.reset());
afterAll(async () => {
  await worker.close();
  await postfix.stop();
  await fx.cleanup();
});

async function planned(options: Parameters<Fixtures['message']>[1]): Promise<MessageFixture> {
  const message = await fx.message(org, options);
  const result = await worker.plan(fx.approval(message));
  expect(result).toMatchObject({ status: 'planned' });
  return message;
}

const statusByAddress = async (message: MessageFixture) => {
  const deliveries = await fx.deliveries(message);
  const out: Record<
    string,
    {
      status: string;
      errorClass: string | null;
      reason: string | null;
      queueId: string | null;
      code: number | null;
    }
  > = {};
  for (const d of deliveries) {
    const r = message.recipients.find((x) => x.id === d.recipientId)!;
    out[r.address] = {
      status: d.status,
      errorClass: d.lastErrorClass,
      reason: d.failureReason,
      queueId: d.outboundQueueId,
      code: d.finalSmtpCode,
    };
  }
  return out;
};

describe('reinjection (R8) into a fake postfix-outbound listener', () => {
  it('queues an outbound group from the 250: XFORWARD with the original client and the token, DSN parameters, one trace header', async () => {
    const message = await planned({
      direction: 'outbound',
      envelopeFrom: 'alice@sender.example',
      recipients: [{ address: 'bob@ext-q.test' }, { address: 'carol+x@ext-q.test' }],
    });
    expect(await worker.reinjectOnce()).toBe(1);
    expect(postfix.transactions).toHaveLength(1);
    const tx = postfix.transactions[0]!;
    const [row] = await fx.reinjections(message);
    const token = reinjectionToken(row!.publicId);
    expect(tx.listener).toBe('outbound');
    expect(tx.xforward).toMatchObject({
      ADDR: '203.0.113.7',
      HELO: 'mail.example.org',
      PROTO: 'ESMTP',
      IDENT: token,
      SOURCE: 'REMOTE',
    });
    expect(parseReinjectionToken(tx.xforward.IDENT!)).toBe(row!.publicId);
    expect(tx.mailFrom).toBe('alice@sender.example');
    expect(tx.envid).toBe(token);
    expect(tx.ret).toBe('HDRS');
    expect(tx.rcpts).toEqual([
      { address: 'bob@ext-q.test', notify: ['FAILURE', 'DELAY'], orcpt: 'rfc822;bob@ext-q.test' },
      {
        address: 'carol+x@ext-q.test',
        notify: ['FAILURE', 'DELAY'],
        orcpt: 'rfc822;carol+x@ext-q.test',
      }, // xtext-decoded by the server,
    ]);
    // Exactly one prepended trace (d=out for the organization), the EML otherwise unchanged.
    const text = tx.data.toString('utf8');
    const [first, ...rest] = text.split('\r\n');
    expect(first).toMatch(/^X-Gateway-Trace: v=1; g=/);
    expect(
      countGatewayPasses([first!.slice('X-Gateway-Trace: '.length)], {
        secret,
        gatewayId,
        organizationId: org,
        direction: 'out',
      }),
    ).toBe(1);
    expect(rest.join('\r\n')).toBe(DEFAULT_EML.replace(/\n/g, '\r\n'));
    expect(text.match(/X-Gateway-Trace/g)).toHaveLength(1);

    const [after] = await fx.reinjections(message);
    expect(after).toMatchObject({
      status: 'queued',
      queueId: tx.queueId,
      leaseExpiresAt: null,
      attempts: 1,
    });
    expect(after!.queuedAt).not.toBeNull();
    const statuses = await statusByAddress(message);
    // The hop's `250 … queued as` is never shown as the final SMTP result (review fix).
    expect(Object.values(statuses).map((s) => [s.status, s.queueId, s.code])).toEqual([
      ['queued', tx.queueId, null],
      ['queued', tx.queueId, null],
    ]);
    const audit = await fx.prisma.deliveryStatusEvent.findMany({
      where: { messageId: message.messageId, source: 'reinjection' },
    });
    expect(audit.map((a) => [a.toStatus, a.applied, a.queueId])).toEqual([
      ['queued', true, tx.queueId],
      ['queued', true, tx.queueId],
    ]);
    const outbox = await fx.prisma.messageOutbox.findMany({
      where: {
        aggregateId: message.messageId.toString(),
        eventType: EventTypes.DeliveryStatusChanged,
      },
    });
    expect(outbox.map((o) => deliveryStatusChangedV1.parse(o.payload).status)).toEqual([
      'queued',
      'queued',
    ]);
  });

  it('inbound mail goes to 10026 with NOTIFY=NEVER and a d=in trace; an unknown client address is [UNAVAILABLE]', async () => {
    // (smtp-server, unlike Postfix, forgets the EHLO after `HELO=[UNAVAILABLE]`, so the fake
    // session keeps a known HELO; the client's encoding of [UNAVAILABLE] is unit-tested.)
    await planned({
      direction: 'inbound',
      clientIp: null,
      recipients: [{ address: `user@${tenantDomain}` }],
    });
    await worker.reinjectOnce();
    const tx = postfix.transactions[0]!;
    expect(tx.listener).toBe('inbound');
    expect(tx.rcpts[0]!.notify).toEqual(['NEVER']);
    expect(tx.xforward).toMatchObject({ NAME: '', HELO: 'mail.example.org' });
    expect(tx.xforward.ADDR).toBeFalsy(); // [UNAVAILABLE]
    const trace = tx.data.toString('utf8').split('\r\n')[0]!.slice('X-Gateway-Trace: '.length);
    expect(
      countGatewayPasses([trace], { secret, gatewayId, organizationId: org, direction: 'in' }),
    ).toBe(1);
  });

  it('partial RCPT results: 2xx queued, 4xx moved to a new reinjection (deferred), 5xx failed', async () => {
    postfix.rcptReply = (address) =>
      address.startsWith('soft')
        ? {
            code: 450,
            message: '4.4.1 <soft>: Recipient address rejected: Destination not configured',
          }
        : address.startsWith('hard')
          ? { code: 554, message: '5.7.1 <hard>: Sender address rejected: suspended' }
          : null;
    const message = await planned({
      recipients: [
        { address: 'ok@ext-p.test' },
        { address: 'soft@ext-p.test' },
        { address: 'hard@ext-p.test' },
      ],
    });
    await worker.reinjectOnce();
    const statuses = await statusByAddress(message);
    expect(statuses['ok@ext-p.test']).toMatchObject({ status: 'queued' });
    // `450 4.4.1 … Destination not configured` is how postfix-outbound's 10026 refuses a tenant
    // domain without a usable destination (docs/deployment/mail-routing.md V5): classified
    // `no_destination` (R9.2, §9 item 4; WP5 fix, design §12). Other 4xx stay reinjection_4xx.
    expect(statuses['soft@ext-p.test']).toMatchObject({
      status: 'deferred',
      errorClass: 'no_destination',
      code: 450,
      queueId: null,
    });
    expect(statuses['hard@ext-p.test']).toMatchObject({
      status: 'failed',
      reason: 'reinjection_refused',
      code: 554,
    });
    const rows = await fx.reinjections(message);
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ status: 'queued', recipientCount: 1 });
    expect(rows[1]).toMatchObject({
      status: 'pending',
      recipientCount: 1,
      lastErrorClass: 'no_destination',
    });
    expect(rows[1]!.publicId).not.toBe(rows[0]!.publicId);
    expect(rows[1]!.idempotencyKey).not.toBe(rows[0]!.idempotencyKey);
    expect(rows[1]!.nextAttemptAt.getTime()).toBeGreaterThan(Date.now());
    const failedAudit = await fx.prisma.deliveryStatusEvent.findFirst({
      where: { messageId: message.messageId, toStatus: 'failed' },
    });
    expect(failedAudit).toMatchObject({ smtpCode: 554, enhancedStatus: '5.7.1' });

    // The new row retries only the deferred recipient, with its own token.
    postfix.reset();
    await makeDue(fx, [rows[1]!]);
    await worker.reinjectOnce();
    expect(postfix.transactions[0]!.rcpts.map((r) => r.address)).toEqual(['soft@ext-p.test']);
    expect(postfix.transactions[0]!.xforward.IDENT).toBe(reinjectionToken(rows[1]!.publicId));
    expect((await statusByAddress(message))['soft@ext-p.test']).toMatchObject({ status: 'queued' });
  });

  it('retries the whole group with exponential backoff on connection errors and a final 4xx', async () => {
    const message = await planned({ recipients: [{ address: 'r@ext-r.test' }] });
    const [row] = await fx.reinjections(message);
    // Nothing listens: connection error before the dot.
    await fx.prisma.deliveryReinjection.update({
      where: { id_receivedAt: { id: row!.id, receivedAt: row!.receivedAt } },
      data: { destinationKey: row!.destinationKey },
    });
    const offline = buildWorker(
      fx,
      workerConfig({ ...FAST, ...postfix.configOverrides, DELIVERY_REINJECT_OUTBOUND_PORT: '1' }),
    );
    const t0 = Date.now();
    await offline.reinjectOnce();
    let [after] = await fx.reinjections(message);
    expect(after).toMatchObject({
      status: 'pending',
      attempts: 1,
      lastErrorClass: 'reinjection_error',
    });
    const first = after!.nextAttemptAt.getTime() - t0;
    expect(first).toBeGreaterThanOrEqual(800);
    expect(first).toBeLessThan(1500);
    expect((await statusByAddress(message))['r@ext-r.test']).toMatchObject({
      status: 'deferred',
      errorClass: 'reinjection_error',
    });

    await makeDue(fx, [after!]);
    const t1 = Date.now();
    await offline.reinjectOnce();
    [after] = await fx.reinjections(message);
    expect(after!.attempts).toBe(2);
    expect(after!.nextAttemptAt.getTime() - t1).toBeGreaterThanOrEqual(1700); // 2 s ± 10 %
    await offline.close();

    // A final 4xx after DATA: the group is retried.
    postfix.dataReply = () => ({ code: 451, message: '4.3.0 Error: queue file write error' });
    await makeDue(fx, [after!]);
    await worker.reinjectOnce();
    [after] = await fx.reinjections(message);
    expect(after).toMatchObject({
      status: 'pending',
      attempts: 3,
      lastErrorClass: 'reinjection_4xx',
    });
    expect((await statusByAddress(message))['r@ext-r.test']).toMatchObject({
      status: 'deferred',
      code: 451,
    });

    // Then accepted.
    postfix.reset();
    await makeDue(fx, [after!]);
    await worker.reinjectOnce();
    expect((await statusByAddress(message))['r@ext-r.test']).toMatchObject({ status: 'queued' });
  });

  it('a final 5xx fails the accepted recipients (reinjection_refused)', async () => {
    postfix.dataReply = () => ({ code: 554, message: '5.4.0 Error: too many hops' });
    const message = await planned({ recipients: [{ address: 'h@ext-h.test' }] });
    await worker.reinjectOnce();
    expect((await statusByAddress(message))['h@ext-h.test']).toMatchObject({
      status: 'failed',
      reason: 'reinjection_refused',
      code: 554,
    });
    expect((await fx.reinjections(message))[0]).toMatchObject({ status: 'failed' });
    const msg = await fx.prisma.emailMessage.findUniqueOrThrow({
      where: { id_receivedAt: { id: message.messageId, receivedAt: message.receivedAt } },
    });
    // The derived lifecycle state (step 3.3 L9): every recipient failed, none delivered.
    expect(msg).toMatchObject({ status: 'rejected', statusReason: 'delivery_failed' });
  });

  it('fails the recipients with content_missing when the S3 object is gone, without connecting', async () => {
    const message = await planned({ upload: false, recipients: [{ address: 'm@ext-m.test' }] });
    await worker.reinjectOnce();
    expect(postfix.transactions).toHaveLength(0);
    expect((await statusByAddress(message))['m@ext-m.test']).toMatchObject({
      status: 'failed',
      reason: 'content_missing',
    });
    expect((await fx.reinjections(message))[0]).toMatchObject({
      status: 'failed',
      lastError: 'content missing',
    });
  });

  it('refuses a loop before connecting: too many gateway passes or Received headers', async () => {
    const traces = Array.from(
      { length: 4 },
      (_, i) =>
        `X-Gateway-Trace: ${buildGatewayTrace({ secret, gatewayId, organizationId: org, direction: i % 2 === 0 ? 'in' : 'out', now: new Date(Date.now() - i * 1000) })}`,
    );
    const looping = await planned({
      eml: `${traces.join('\n')}\n${DEFAULT_EML}`,
      recipients: [{ address: 'l@ext-l.test' }],
    });
    // Another organization's traces never count.
    const foreign = Array.from(
      { length: 6 },
      () =>
        `X-Gateway-Trace: ${buildGatewayTrace({ secret, gatewayId, organizationId: org + 1000n, direction: 'in' })}`,
    );
    const clean = await planned({
      eml: `${foreign.join('\n')}\n${DEFAULT_EML}`,
      recipients: [{ address: 'c@ext-l.test' }],
    });
    const hops = await planned({
      eml: `${'Received: from x by y\n'.repeat(25)}${DEFAULT_EML}`,
      recipients: [{ address: 'r@ext-l2.test' }],
    });
    await worker.reinjectOnce();
    expect((await statusByAddress(looping))['l@ext-l.test']).toMatchObject({
      status: 'failed',
      reason: 'loop_detected',
      errorClass: 'loop',
    });
    expect((await statusByAddress(hops))['r@ext-l2.test']).toMatchObject({
      status: 'failed',
      reason: 'loop_detected',
      errorClass: 'loop',
    });
    expect((await statusByAddress(clean))['c@ext-l.test']).toMatchObject({ status: 'queued' });
    expect(postfix.transactions.map((t) => t.rcpts[0]!.address)).toEqual(['c@ext-l.test']);
  });

  it('expires the deliveries after the max age (reinjection_expired)', async () => {
    const message = await planned({ recipients: [{ address: 'e@ext-e.test' }] });
    const rows = await fx.reinjections(message);
    await fx.prisma.deliveryReinjection.update({
      where: { id_receivedAt: { id: rows[0]!.id, receivedAt: rows[0]!.receivedAt } },
      data: { createdAt: new Date(Date.now() - 432_001_000), lastErrorClass: 'reinjection_error' },
    });
    await worker.reinjectOnce();
    expect(postfix.transactions).toHaveLength(0);
    expect((await statusByAddress(message))['e@ext-e.test']).toMatchObject({
      status: 'expired',
      reason: 'reinjection_expired',
      errorClass: 'reinjection_error',
    });
    expect((await fx.reinjections(message))[0]).toMatchObject({ status: 'failed' });
  });

  it('a held inbound domain is re-checked at each attempt and delivered once active again', async () => {
    const heldDomain = fx.name('held-r');
    const domainId = await fx.domain(org, heldDomain, { status: 'suspended' });
    const message = await planned({
      direction: 'inbound',
      recipients: [{ address: `u@${heldDomain}` }],
    });
    const rows = await fx.reinjections(message);
    await makeDue(fx, rows);
    await worker.reinjectOnce();
    expect(postfix.transactions).toHaveLength(0);
    let [row] = await fx.reinjections(message);
    expect(row).toMatchObject({ status: 'pending', lastErrorClass: 'gateway_hold' });
    await fx.prisma.domain.update({ where: { id: domainId }, data: { status: 'active' } });
    await makeDue(fx, [row!]);
    await worker.reinjectOnce();
    [row] = await fx.reinjections(message);
    expect(row).toMatchObject({ status: 'queued' });
    expect(postfix.transactions).toHaveLength(1);
  });

  it('a worker whose claim was lost records nothing; a released claim still records its 250', async () => {
    // Claim as the scheduler does, then another replica re-claims the row (attempts + 1) after
    // the reconciler released the expired lease.
    const message = await planned({ recipients: [{ address: 'lost@ext-l.test' }] });
    const [first] = await fx.reinjections(message);
    const where = { id_receivedAt: { id: first!.id, receivedAt: first!.receivedAt } };
    await fx.prisma.deliveryReinjection.update({
      where,
      data: { status: 'in_progress', attempts: 1, startedAt: new Date() },
    });
    const claimed = await fx.prisma.deliveryReinjection.findUniqueOrThrow({ where });
    await fx.prisma.deliveryReinjection.update({ where, data: { attempts: 2 } });
    expect(await worker.reinjector.process(claimed)).toBe('queued');
    expect(postfix.transactions).toHaveLength(1);
    expect((await statusByAddress(message))['lost@ext-l.test']).toMatchObject({
      status: 'pending',
      queueId: null,
    });
    expect(
      await fx.prisma.deliveryStatusEvent.count({
        where: { messageId: message.messageId, source: 'reinjection' },
      }),
    ).toBe(0);
    expect(await fx.prisma.deliveryReinjection.findUniqueOrThrow({ where })).toMatchObject({
      status: 'in_progress',
      attempts: 2,
      queueId: null,
    });

    // Released to pending (not re-claimed): postfix-outbound has the message, so the 250 is
    // recorded instead of letting the row be sent again.
    postfix.reset();
    await fx.prisma.deliveryReinjection.update({
      where,
      data: { status: 'pending', attempts: 1, nextAttemptAt: new Date(Date.now() + 3_600_000) },
    });
    await worker.reinjector.process(claimed);
    expect(await fx.prisma.deliveryReinjection.findUniqueOrThrow({ where })).toMatchObject({
      status: 'queued',
      queueId: postfix.transactions[0]!.queueId,
    });
    expect((await statusByAddress(message))['lost@ext-l.test']).toMatchObject({
      status: 'queued',
    });
  });
});
