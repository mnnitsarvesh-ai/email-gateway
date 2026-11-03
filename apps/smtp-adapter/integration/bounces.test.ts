import type { TestingModule } from '@nestjs/testing';
import { buildGatewayTrace } from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { LmtpBounceListener } from '../src/bounces/bounces.module';
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
