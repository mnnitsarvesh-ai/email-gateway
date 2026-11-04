import { randomUUID } from 'node:crypto';
import type { TestingModule } from '@nestjs/testing';
import { buildGatewayTrace, MetricsService } from '@email-gateway/common';
import { EventTypes, messageStateChangedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { LmtpBounceListener } from '../src/bounces/bounces.module';
import { reinjectionToken } from '@email-gateway/mail-routing';
import { reputationKey } from '../src/shared/reputation';
import { postfixPostmasterCopy, singleHardBounce } from './support/dsn-fixtures';
import { Fixtures, queueId } from './support/fixtures';
import { deliver } from './support/lmtp-client';
import { requireEnv, startAdapterStack } from './support/stack';

/**
 * Bounce handler (docs/plan/steps/04-smtp-gateway.md D13) in-process against the real writer
 * MySQL and Redis: postmaster DSN copies over LMTP become bounce_events, hard-bounce
 * suppressions and reputation counters, exactly once per notice.
 */
const fx = new Fixtures();
let stack: TestingModule;
let port = 0;
let org = 0n;
let tenantDomain = '';
const BOUNCE_RCPT = `bounce-notices@${process.env.POSTFIX_BOUNCE_DOMAIN ?? 'bounces.gateway.internal'}`;
const ARRIVAL = new Date('2026-11-02T10:00:00.000Z');

const send = (message: string, to: string[] = [BOUNCE_RCPT], from = '') =>
  deliver({
    port,
    lhlo: 'out.gateway.local',
    xforward: { IDENT: queueId() },
    from,
    to,
    message,
  });

/** The outbound trace the delivery-worker adds when it reinjects mail on 10027 (D14). */
const trace = (organizationId: bigint, direction: 'in' | 'out' = 'out') =>
  `X-Gateway-Trace: ${buildGatewayTrace({
    secret: requireEnv('GATEWAY_TRACE_SECRET'),
    gatewayId: process.env.GATEWAY_TRACE_ID ?? 'gw-local',
    organizationId,
    direction,
  })}`;

async function reputation(): Promise<Record<string, string>> {
  // Counted on the day of processing (now), not the notice's arrival date.
  return fx.redis.hgetall(reputationKey(org, new Date()));
}

beforeAll(async () => {
  org = await fx.organization('bounce');
  tenantDomain = fx.name('bounce');
  await fx.domain(org, tenantDomain);
  stack = await startAdapterStack();
  port = stack.get(LmtpBounceListener).port();
});

afterAll(async () => {
  await stack?.close();
  await fx.cleanup();
});

describe('bounce notices', () => {
  const queue = queueId();
  const notice = () =>
    singleHardBounce(queue, `alice@${tenantDomain}`, 'Hard-Bounce@sink.test', [trace(org)]);

  it('records a hard bounce, suppresses the address and counts reputation', async () => {
    const result = await send(notice());
    expect(result.rcpt.map((r) => r.code)).toEqual([250]);
    expect(result.data.map((r) => r.text)).toEqual(['250 2.0.0 Ok']);

    const events = await fx.prisma.bounceEvent.findMany({ where: { organizationId: org } });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      occurredAt: ARRIVAL,
      messageId: null,
      recipientAddress: 'hard-bounce@sink.test',
      bounceType: 'hard',
      smtpCode: 550,
      enhancedStatus: '5.1.1',
      reportingMta: 'out.gateway.local',
    });
    expect(events[0]!.diagnostic).toMatch(/^smtp; 550 5\.1\.1 /);
    expect(events[0]!.dedupeKey).toMatch(/^[0-9a-f]{64}$/);

    const suppression = await fx.prisma.deliverySuppression.findUniqueOrThrow({
      where: { organizationId_address: { organizationId: org, address: 'hard-bounce@sink.test' } },
    });
    expect(suppression).toMatchObject({ reason: 'hard_bounce', source: 'bounce' });
    const days = (suppression.expiresAt!.getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(179);
    expect(days).toBeLessThanOrEqual(180);
    expect((await reputation()).bounced_hard).toBe('1');
  });

  it('answers 250 to a redelivered notice without new rows or counts', async () => {
    const result = await send(notice());
    expect(result.data.map((r) => r.code)).toEqual([250]);
    expect(await fx.prisma.bounceEvent.count({ where: { organizationId: org } })).toBe(1);
    expect(await fx.prisma.deliverySuppression.count({ where: { organizationId: org } })).toBe(1);
    expect((await reputation()).bounced_hard).toBe('1');
  });

  it('records a multi-recipient notice; only address failures suppress; manual rows are kept', async () => {
    await fx.prisma.deliverySuppression.create({
      data: {
        organizationId: org,
        address: 'manual@sink.test',
        reason: 'manual',
        source: 'api',
        expiresAt: null,
      },
    });
    const result = await send(
      postfixPostmasterCopy({
        queueId: queueId(),
        sender: `bob@${tenantDomain}`,
        originalHeaders: [trace(org)],
        recipients: [
          {
            address: 'manual@sink.test',
            action: 'failed',
            status: '5.1.1',
            diagnostic: 'smtp; 550 5.1.1 User unknown',
          },
          {
            address: 'blocked@sink.test',
            action: 'failed',
            status: '5.7.1',
            diagnostic: 'smtp; 550 5.7.1 Blocked',
          },
          { address: 'fine@sink.test', action: 'delivered', status: '2.0.0' },
        ],
      }),
    );
    expect(result.data.map((r) => r.code)).toEqual([250]);
    const addresses = (
      await fx.prisma.bounceEvent.findMany({
        where: { organizationId: org },
        orderBy: { id: 'asc' },
      })
    ).map((e) => e.recipientAddress);
    expect(addresses).toEqual(['hard-bounce@sink.test', 'manual@sink.test', 'blocked@sink.test']);
    const manual = await fx.prisma.deliverySuppression.findUniqueOrThrow({
      where: { organizationId_address: { organizationId: org, address: 'manual@sink.test' } },
    });
    expect(manual).toMatchObject({ reason: 'manual', source: 'api', expiresAt: null });
    expect(
      await fx.prisma.deliverySuppression.count({
        where: { organizationId: org, address: 'blocked@sink.test' },
      }),
    ).toBe(0);
    expect((await reputation()).bounced_hard).toBe('3');
  });

  it('records a delay warning as soft without suppression', async () => {
    const result = await send(
      postfixPostmasterCopy({
        kind: 'delay',
        queueId: queueId(),
        sender: `carol@${tenantDomain}`,
        originalHeaders: [trace(org)],
        recipients: [
          {
            address: 'soft-bounce@sink.test',
            action: 'delayed',
            status: '4.2.1',
            diagnostic: 'smtp; 450 4.2.1 Mailbox busy',
          },
        ],
      }),
    );
    expect(result.data.map((r) => r.code)).toEqual([250]);
    const delayed = await fx.prisma.bounceEvent.findFirstOrThrow({
      where: { organizationId: org, recipientAddress: 'soft-bounce@sink.test' },
    });
    expect(delayed).toMatchObject({ bounceType: 'soft', smtpCode: 450, enhancedStatus: '4.2.1' });
    expect(
      await fx.prisma.deliverySuppression.count({
        where: { organizationId: org, address: 'soft-bounce@sink.test' },
      }),
    ).toBe(0);
    expect((await reputation()).delayed).toBe('1');
  });

  it('ignores notices of non-tenant senders and accepts unparseable mail (250, nothing written)', async () => {
    const before = await fx.prisma.bounceEvent.count({ where: { organizationId: org } });
    const foreign = await send(singleHardBounce(queueId(), 'someone@external.test', 'x@sink.test'));
    expect(foreign.data.map((r) => r.code)).toEqual([250]);
    const junk = await send('Subject: not a DSN\r\n\r\nhello\r\n');
    expect(junk.data.map((r) => r.code)).toEqual([250]);
    expect(await fx.prisma.bounceEvent.count({ where: { organizationId: org } })).toBe(before);
  });

  it('ignores notices without a valid outbound trace of the sender organization (ingestion-hop failures, forgeries)', async () => {
    const before = await fx.prisma.bounceEvent.count({ where: { organizationId: org } });
    const other = await fx.organization('bounce-other');
    const sender = `dave@${tenantDomain}`;
    const variants: string[][] = [
      // A failure of the content_filter hop (e.g. the From check): no trace at all.
      [],
      // Another tenant's trace, an inbound trace, a forged signature.
      [trace(other)],
      [trace(org, 'in')],
      [trace(org).replace(/s=[A-Za-z0-9_-]+$/, 's=AAAAAAAAAAAAAAAAAAAAAA')],
    ];
    for (const originalHeaders of variants) {
      const result = await send(
        postfixPostmasterCopy({
          queueId: queueId(),
          sender,
          originalHeaders,
          recipients: [
            {
              address: 'ignored@sink.test',
              action: 'failed',
              status: '5.7.1',
              remoteMta: 'smtp-adapter',
              diagnostic:
                'smtp; 550 5.7.1 From header does not match the authenticated sender domain',
            },
          ],
        }),
      );
      expect(result.data.map((r) => r.code)).toEqual([250]);
    }
    expect(await fx.prisma.bounceEvent.count({ where: { organizationId: org } })).toBe(before);
    expect(
      await fx.prisma.deliverySuppression.count({
        where: { organizationId: org, address: 'ignored@sink.test' },
      }),
    ).toBe(0);
  });

  it('refuses a notice whose envelope sender is not the bounce daemon', async () => {
    for (const from of [`alice@${tenantDomain}`, 'double-bounce@mx.gateway.local']) {
      const result = await send(notice(), [BOUNCE_RCPT], from);
      expect(result.mail.text).toBe(
        '550 5.7.1 Sender address rejected: not allowed for bounce notices',
      );
    }
    // Postfix's own postmaster copies come from double-bounce@<out myhostname> or <>.
    const accepted = await send(notice(), [BOUNCE_RCPT], 'Double-Bounce@out.gateway.local');
    expect(accepted.data.map((r) => r.code)).toEqual([250]);
  });

  it('accepts only bounce-notices@<POSTFIX_BOUNCE_DOMAIN> as recipient', async () => {
    const result = await send(notice(), [
      'postmaster@bounces.gateway.internal',
      BOUNCE_RCPT.toUpperCase(),
    ]);
    expect(result.rcpt.map((r) => r.text)).toEqual([
      '550 5.1.1 Recipient address rejected: User unknown',
      '250 Accepted',
    ]);
  });
});

/**
 * Step 2.3 R9 "Bounce notices": a notice is matched to the reinjection that carried the mail
 * (by X-Postfix-Queue-ID, else by Original-Envelope-Id = the reinjection token) and becomes a
 * `bounce_notice` delivery signal for the organization and delivery of that reinjection, in any
 * direction. The 2.2 outbound behaviour (bounce_events, suppressions, reputation) is unchanged
 * and now carries the message reference.
 */
describe('bounce notices → per-recipient delivery status (step 2.3)', () => {
  const deliveryOf = (id: bigint) =>
    fx.prisma.emailDelivery.findFirstOrThrow({ where: { id, organizationId: org } });
  const auditOf = (deliveryId: bigint) =>
    fx.prisma.deliveryStatusEvent.findMany({ where: { deliveryId }, orderBy: { id: 'asc' } });

  it('matches by queue id: the outbound delivery bounces, and the bounce event names the message', async () => {
    const qid = queueId();
    const fixture = await fx.reinjectedMessage({
      organizationId: org,
      direction: 'outbound',
      envelopeFrom: `erin@${tenantDomain}`,
      recipients: ['Gone@ext-r.test'],
      queueId: qid,
    });
    const result = await send(
      singleHardBounce(qid, `erin@${tenantDomain}`, 'Gone@ext-r.test', [trace(org)]),
    );
    expect(result.data.map((r) => r.code)).toEqual([250]);

    const delivery = await deliveryOf(fixture.deliveryIds[0]!);
    expect(delivery).toMatchObject({
      status: 'bounced',
      enhancedStatus: '5.1.1',
      finalSmtpCode: 550,
      outboundQueueId: qid,
    });
    const audit = await auditOf(delivery.id);
    expect(audit.map((a) => [a.source, a.fromStatus, a.toStatus, a.applied])).toEqual([
      ['bounce_notice', 'queued', 'bounced', true],
    ]);
    expect(audit[0]!.queueId).toBe(qid);
    const recipient = await fx.prisma.emailRecipient.findFirstOrThrow({
      where: { messageId: fixture.messageId, organizationId: org },
    });
    expect(recipient.status).toBe('bounced');
    expect(
      await fx.prisma.emailEvent.count({
        where: { messageId: fixture.messageId, eventType: 'delivery.bounced' },
      }),
    ).toBe(1);
    // 2.2 behaviour, now with the message reference.
    const bounce = await fx.prisma.bounceEvent.findFirstOrThrow({
      where: { organizationId: org, recipientAddress: 'gone@ext-r.test' },
    });
    expect(bounce.messageId).toBe(fixture.messageId);
    expect(bounce.messageReceivedAt).toEqual(fixture.receivedAt);
    expect(
      await fx.prisma.deliverySuppression.count({
        where: { organizationId: org, address: 'gone@ext-r.test' },
      }),
    ).toBe(1);
    // The derived message state (step 3.3 L9): its only recipient bounced → rejected.
    const message = await fx.prisma.emailMessage.findFirstOrThrow({
      where: { id: fixture.messageId, organizationId: org },
    });
    expect(message).toMatchObject({
      status: 'rejected',
      statusReason: 'delivery_failed',
      version: 4,
    });
    const history = await fx.prisma.emailMessageStatusHistory.findFirstOrThrow({
      where: { messageId: fixture.messageId, receivedAt: fixture.receivedAt, version: 4 },
    });
    expect(history).toMatchObject({
      fromStatus: 'delivery_pending',
      toStatus: 'rejected',
      reasonCode: 'delivery_failed',
      actorRole: 'delivery',
      actorService: 'smtp-adapter',
      correlationId: `delivery:${delivery.id.toString()}`,
    });
    const stateChanged = await fx.prisma.messageOutbox.findFirstOrThrow({
      where: {
        organizationId: org,
        aggregateId: fixture.messageId.toString(),
        eventType: EventTypes.MessageStateChanged,
      },
    });
    expect(messageStateChangedV1.parse(stateChanged.payload)).toMatchObject({
      previousState: 'delivery_pending',
      state: 'rejected',
      reasonCode: 'delivery_failed',
      actorRole: 'delivery',
      actorService: 'smtp-adapter',
    });
    // Counted on the adapter's registry (the recorder context's lifecycleMetrics).
    expect(await stack.get(MetricsService).metrics()).toMatch(
      /lifecycle_transitions_total\{from="delivery_pending",to="rejected",result="applied",service="smtp-adapter"\} [1-9]/,
    );
  });

  it('a redelivered notice gives no second transition, event or outbox row', async () => {
    const qid = queueId();
    const fixture = await fx.reinjectedMessage({
      organizationId: org,
      direction: 'outbound',
      envelopeFrom: `erin@${tenantDomain}`,
      recipients: ['twice@ext-r.test'],
      queueId: qid,
    });
    const notice = singleHardBounce(qid, `erin@${tenantDomain}`, 'twice@ext-r.test', [trace(org)]);
    await send(notice);
    const counts = async () => ({
      audit: await fx.prisma.deliveryStatusEvent.count({
        where: { deliveryId: fixture.deliveryIds[0]! },
      }),
      events: await fx.prisma.emailEvent.count({ where: { messageId: fixture.messageId } }),
      outbox: await fx.prisma.messageOutbox.count({
        where: { organizationId: org, aggregateId: fixture.messageId.toString() },
      }),
      bounces: await fx.prisma.bounceEvent.count({
        where: { organizationId: org, recipientAddress: 'twice@ext-r.test' },
      }),
    });
    const before = await counts();
    // delivery.bounced + lifecycle.rejected; status_changed + state_changed (step 3.3).
    expect(before).toEqual({ audit: 1, events: 2, outbox: 2, bounces: 1 });
    const again = await send(notice);
    expect(again.data.map((r) => r.code)).toEqual([250]);
    expect(await counts()).toEqual(before);
  });

  it('matches by Original-Envelope-Id when the queue id is not bound: failed 4.x.x → expired', async () => {
    const fixture = await fx.reinjectedMessage({
      organizationId: org,
      direction: 'outbound',
      envelopeFrom: `frank@${tenantDomain}`,
      recipients: ['slow@ext-r.test'],
      queueId: null,
    });
    const result = await send(
      postfixPostmasterCopy({
        queueId: queueId(),
        envelopeId: reinjectionToken(fixture.reinjectionPublicId),
        sender: `frank@${tenantDomain}`,
        originalHeaders: [trace(org)],
        recipients: [
          {
            address: 'slow@ext-r.test',
            action: 'failed',
            status: '4.4.7',
            diagnostic:
              'X-Postfix; delivery temporarily suspended: connect to mx.ext-r.test[192.0.2.9]:25: Connection timed out',
          },
        ],
      }),
    );
    expect(result.data.map((r) => r.code)).toEqual([250]);
    const delivery = await deliveryOf(fixture.deliveryIds[0]!);
    expect(delivery.status).toBe('expired');
    expect(delivery.lastErrorClass).toBe('connect');
    expect((await auditOf(delivery.id)).map((a) => a.toStatus)).toEqual(['expired']);
  });

  it('a delay warning moves the delivery to deferred', async () => {
    const qid = queueId();
    const fixture = await fx.reinjectedMessage({
      organizationId: org,
      direction: 'outbound',
      envelopeFrom: `gina@${tenantDomain}`,
      recipients: ['busy@ext-r.test'],
      queueId: qid,
    });
    await send(
      postfixPostmasterCopy({
        kind: 'delay',
        queueId: qid,
        date: new Date(Date.now() + 1000).toUTCString(),
        sender: `gina@${tenantDomain}`,
        originalHeaders: [trace(org)],
        recipients: [
          {
            address: 'busy@ext-r.test',
            action: 'delayed',
            status: '4.2.1',
            diagnostic: 'smtp; 450 4.2.1 Mailbox busy',
          },
        ],
      }),
    );
    const delivery = await deliveryOf(fixture.deliveryIds[0]!);
    expect(delivery.status).toBe('deferred');
    expect(delivery.lastErrorClass).toBe('remote_4xx');
  });

  it('an inbound delivery notice with an external sender is recorded on the delivery, never suppressed', async () => {
    const qid = queueId();
    const fixture = await fx.reinjectedMessage({
      organizationId: org,
      direction: 'inbound',
      envelopeFrom: 'someone@external-sender.test',
      recipients: [`hard-bounce@${tenantDomain}`],
      queueId: qid,
    });
    const suppressionsBefore = await fx.prisma.deliverySuppression.count({
      where: { organizationId: org },
    });
    const bouncesBefore = await fx.prisma.bounceEvent.count({ where: { organizationId: org } });
    const reputationBefore = await reputation();
    const result = await send(
      singleHardBounce(qid, 'someone@external-sender.test', `hard-bounce@${tenantDomain}`, [
        trace(org, 'in'),
      ]),
    );
    expect(result.data.map((r) => r.code)).toEqual([250]);
    expect((await deliveryOf(fixture.deliveryIds[0]!)).status).toBe('bounced');
    expect(await fx.prisma.deliverySuppression.count({ where: { organizationId: org } })).toBe(
      suppressionsBefore,
    );
    expect(await fx.prisma.bounceEvent.count({ where: { organizationId: org } })).toBe(
      bouncesBefore,
    );
    expect(await reputation()).toEqual(reputationBefore);
  });

  it('the organization comes from the reinjection, never from the sender domain of the notice', async () => {
    const other = await fx.organization('bounce-foreign');
    const qid = queueId();
    const fixture = await fx.reinjectedMessage({
      organizationId: other,
      direction: 'inbound',
      envelopeFrom: `spoof@${tenantDomain}`,
      recipients: ['user@foreign-r.test'],
      queueId: qid,
    });
    const bouncesBefore = await fx.prisma.bounceEvent.count({ where: { organizationId: org } });
    await send(singleHardBounce(qid, `spoof@${tenantDomain}`, 'user@foreign-r.test', [trace(org)]));
    const delivery = await fx.prisma.emailDelivery.findFirstOrThrow({
      where: { id: fixture.deliveryIds[0]!, organizationId: other },
    });
    expect(delivery.status).toBe('bounced');
    const audit = await fx.prisma.deliveryStatusEvent.findMany({
      where: { deliveryId: delivery.id },
    });
    expect(audit.map((a) => a.organizationId)).toEqual([other]);
    // An inbound reinjection never feeds the sender organization's bounce statistics.
    expect(await fx.prisma.bounceEvent.count({ where: { organizationId: org } })).toBe(
      bouncesBefore,
    );
  });

  it('queue ids that differ only in letter case never match each other (L15)', async () => {
    // Postfix long queue ids are case-sensitive: 4jKFxV5fmHz12JnW and 4jKFxV5fMHz12Jnw are two
    // queue files. The queue-id columns are utf8mb4_bin since step 3.3.
    const suffix = randomUUID().replaceAll('-', '').slice(0, 6);
    const lower = `4jKFxV5fmHz12JnW${suffix}`;
    const upper = `4jKFxV5fMHz12Jnw${suffix}`;
    const first = await fx.reinjectedMessage({
      organizationId: org,
      direction: 'outbound',
      envelopeFrom: `ivy@${tenantDomain}`,
      recipients: ['case@ext-r.test'],
      queueId: lower,
    });
    const second = await fx.reinjectedMessage({
      organizationId: org,
      direction: 'outbound',
      envelopeFrom: `ivy@${tenantDomain}`,
      recipients: ['case@ext-r.test'],
      queueId: upper,
    });
    await send(singleHardBounce(upper, `ivy@${tenantDomain}`, 'case@ext-r.test', [trace(org)]));
    expect((await deliveryOf(second.deliveryIds[0]!)).status).toBe('bounced');
    expect((await deliveryOf(first.deliveryIds[0]!)).status).toBe('queued');
    expect(await auditOf(first.deliveryIds[0]!)).toEqual([]);
    const bounce = await fx.prisma.bounceEvent.findFirstOrThrow({
      where: { organizationId: org, recipientAddress: 'case@ext-r.test' },
    });
    expect(bounce.messageId).toBe(second.messageId);
    const states = await fx.prisma.emailMessage.findMany({
      where: { id: { in: [first.messageId, second.messageId] }, organizationId: org },
      select: { id: true, status: true },
    });
    expect(Object.fromEntries(states.map((m) => [m.id.toString(), m.status]))).toEqual({
      [first.messageId.toString()]: 'delivery_pending',
      [second.messageId.toString()]: 'rejected',
    });

    // A delay warning for the other file goes to the first delivery only.
    await send(
      postfixPostmasterCopy({
        kind: 'delay',
        queueId: lower,
        date: new Date(Date.now() + 1000).toUTCString(),
        sender: `ivy@${tenantDomain}`,
        originalHeaders: [trace(org)],
        recipients: [
          {
            address: 'case@ext-r.test',
            action: 'delayed',
            status: '4.2.1',
            diagnostic: 'smtp; 450 4.2.1 Mailbox busy',
          },
        ],
      }),
    );
    expect((await deliveryOf(first.deliveryIds[0]!)).status).toBe('deferred');
    expect((await deliveryOf(second.deliveryIds[0]!)).status).toBe('bounced');
    expect(
      (
        await fx.prisma.emailMessage.findFirstOrThrow({
          where: { id: first.messageId, organizationId: org },
        })
      ).status,
    ).toBe('delivery_retry');
  });

  it('an unmatched notice keeps the 2.2 behaviour (no message reference, no delivery signal)', async () => {
    const before = await fx.prisma.deliveryStatusEvent.count({ where: { organizationId: org } });
    await send(
      singleHardBounce(queueId(), `hank@${tenantDomain}`, 'nomatch@ext-r.test', [trace(org)]),
    );
    const bounce = await fx.prisma.bounceEvent.findFirstOrThrow({
      where: { organizationId: org, recipientAddress: 'nomatch@ext-r.test' },
    });
    expect(bounce.messageId).toBeNull();
    expect(bounce.messageReceivedAt).toBeNull();
    expect(await fx.prisma.deliveryStatusEvent.count({ where: { organizationId: org } })).toBe(
      before,
    );
  });
});
