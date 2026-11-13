import { NonRetryableError } from '@email-gateway/common';
import type { EventEnvelope, PolicyNotificationRequestedV1 } from '@email-gateway/event-contracts';
import { describe, expect, it, vi } from 'vitest';
import type { NoticeMail, NoticeMailer } from './mailer';
import { NoticeSendError } from './mailer';
import type { NotificationMetrics } from './notification-metrics';
import type { NotificationReads } from './notification-reads';
import { addressDomain, PolicyNotificationHandler } from './policy-notification.handler';
import { PreferenceFilter } from './preference-filter';

/** Stored `notification_user_preferences` rows the fake transaction returns (step 6.2 N4). */
let preferenceRows: Array<{ organizationId: bigint; userId: bigint; preferences: unknown }> = [];
const tx = {
  notificationUserPreference: {
    findMany: vi.fn((args: { where: { userId: { in: bigint[] } } }) =>
      Promise.resolve(preferenceRows.filter((r) => args.where.userId.in.includes(r.userId))),
    ),
  },
} as never;
const logger = { child: () => logger, info: vi.fn(), warn: vi.fn() } as never;

function event(
  over: Partial<PolicyNotificationRequestedV1> = {},
): EventEnvelope<PolicyNotificationRequestedV1> {
  return {
    eventId: '0190f0f0-0000-7000-8000-00000000e001',
    eventType: 'mail.policy.notification_requested.v1',
    occurredAt: '2026-11-11T10:00:01.000Z',
    correlationId: 'corr-12345678',
    organizationId: '7',
    payload: {
      messageId: '501',
      receivedAt: '2026-11-11T10:00:00.000Z',
      direction: 'inbound',
      lifecycleRound: 0,
      kind: 'policy_alert',
      severity: 'warning',
      disposition: 'quarantine',
      decisive: { source: 'platform_default', policyId: null, versionNo: null, ruleId: null },
      ruleRefs: [],
      requestedAt: '2026-11-11T10:00:01.000Z',
      ...over,
    },
  };
}

function setup(options: { configured?: boolean; fail?: boolean; message?: boolean } = {}) {
  const sent: NoticeMail[] = [];
  const mailer: NoticeMailer = {
    configured: options.configured ?? true,
    from: options.configured === false ? null : 'Gateway <no-reply@gw.example>',
    send: vi.fn((mail: NoticeMail) =>
      options.fail
        ? Promise.reject(new NoticeSendError(451))
        : (sent.push(mail), Promise.resolve()),
    ),
    close: () => undefined,
  };
  const reads = {
    message: vi.fn(() =>
      Promise.resolve(
        options.message === false
          ? null
          : {
              id: 501n,
              publicId: '0190f0f0-0000-7000-8000-0000000001f5',
              organizationId: 7n,
              receivedAt: new Date('2026-11-11T10:00:00.000Z'),
              direction: 'outbound',
              envelopeFrom: 'Alice@ACME.example',
              internetMessageId: '<m1@acme.example>',
              recipientCount: 3,
            },
      ),
    ),
    organizationName: vi.fn(() => Promise.resolve('Acme')),
    policyName: vi.fn(() => Promise.resolve('Cards')),
    alertRecipients: vi.fn(() =>
      Promise.resolve([
        { id: 1n, email: 'admin1@acme.example' },
        { id: 2n, email: 'admin2@acme.example' },
      ]),
    ),
    activeDomain: vi.fn((_tx: unknown, _org: bigint, domain: string) =>
      Promise.resolve(domain === 'acme.example'),
    ),
  };
  const counts: Array<Record<string, string>> = [];
  const suppressed: Array<[Record<string, string>, number]> = [];
  const metrics = {
    messages: { inc: (labels: Record<string, string>) => counts.push(labels) },
    alertsSuppressed: {
      inc: (labels: Record<string, string>, n: number) => suppressed.push([labels, n]),
    },
    sendDuration: { startTimer: () => () => 0 },
  } as unknown as NotificationMetrics;
  preferenceRows = [];
  const handler = new PolicyNotificationHandler(
    reads as unknown as NotificationReads,
    mailer,
    metrics,
    logger,
    { maxRecipients: 50, portalUrl: 'https://portal.example' },
    new PreferenceFilter(metrics),
  );
  return { handler, reads, sent, counts, suppressed };
}

describe('PolicyNotificationHandler (P25)', () => {
  it('sends a policy alert to the organization’s policy administrators, Bcc, deterministic id', async () => {
    const ctx = setup();
    expect(await ctx.handler.handle(event(), tx)).toBe('sent');
    expect(ctx.reads.message).toHaveBeenCalledWith(
      tx,
      7n,
      501n,
      new Date('2026-11-11T10:00:00.000Z'),
    );
    expect(ctx.reads.alertRecipients).toHaveBeenCalledWith(tx, 7n, 50, null);
    expect(ctx.sent).toHaveLength(1);
    expect(ctx.sent[0]).toMatchObject({
      recipients: ['admin1@acme.example', 'admin2@acme.example'],
      messageId: '<policy-notice.0190f0f0-0000-7000-8000-00000000e001@gw.example>',
    });
    expect(ctx.sent[0]!.text).toContain(
      'https://portal.example/messages/0190f0f0-0000-7000-8000-0000000001f5',
    );
    expect(ctx.sent[0]!.text).not.toContain('alice');
    expect(ctx.counts).toEqual([{ kind: 'policy_alert', result: 'sent' }]);
  });

  it('leaves out administrators who opted out of policy_alert (step 6.2 N4) and counts them', async () => {
    const ctx = setup();
    preferenceRows = [
      { organizationId: 7n, userId: 1n, preferences: { optOut: ['policy_alert'] } },
      { organizationId: 7n, userId: 2n, preferences: { optOut: ['threat_detected'] } },
    ];
    expect(await ctx.handler.handle(event(), tx)).toBe('sent');
    expect(ctx.sent[0]!.recipients).toEqual(['admin2@acme.example']);
    expect(ctx.suppressed).toEqual([[{ kind: 'policy_alert', reason: 'opt_out' }, 1]]);
    // Every administrator opted out: nothing is sent.
    const all = setup();
    preferenceRows = [1n, 2n].map((userId) => ({
      organizationId: 7n,
      userId,
      preferences: { optOut: ['policy_alert'] },
    }));
    expect(await all.handler.handle(event(), tx)).toBe('no_recipients');
    expect(all.sent).toHaveLength(0);
  });

  it('counts no_recipients without administrators and disabled without a relay', async () => {
    const none = setup();
    none.reads.alertRecipients.mockResolvedValue([]);
    expect(await none.handler.handle(event(), tx)).toBe('no_recipients');
    expect(none.sent).toHaveLength(0);
    const disabled = setup({ configured: false });
    expect(await disabled.handler.handle(event(), tx)).toBe('disabled');
    expect(disabled.counts).toEqual([{ kind: 'policy_alert', result: 'disabled' }]);
  });

  it('sends the non-delivery notice only to a sender in an active domain of the organization', async () => {
    const ctx = setup();
    const notice = event({
      kind: 'sender_non_delivery',
      direction: 'outbound',
      disposition: 'reject',
    });
    expect(await ctx.handler.handle(notice, tx)).toBe('sent');
    expect(ctx.sent[0]!.recipients).toEqual(['alice@acme.example']);
    expect(ctx.sent[0]!.text).toContain('Message-ID: m1@acme.example');
    expect(ctx.sent[0]!.text).toContain('Recipients: 3');
    const external = setup();
    external.reads.message.mockResolvedValue({
      ...(await external.reads.message()),
      envelopeFrom: 'someone@external.example',
    } as never);
    expect(await external.handler.handle(notice, tx)).toBe('no_recipients');
    expect(external.sent).toHaveLength(0);
    const nullSender = setup();
    nullSender.reads.message.mockResolvedValue({
      ...(await nullSender.reads.message()),
      envelopeFrom: '',
    } as never);
    expect(await nullSender.handler.handle(notice, tx)).toBe('no_recipients');
  });

  it('rethrows relay failures (retryable) and dead-letters a missing message', async () => {
    const failing = setup({ fail: true });
    await expect(failing.handler.handle(event(), tx)).rejects.toBeInstanceOf(NoticeSendError);
    expect(failing.counts).toEqual([{ kind: 'policy_alert', result: 'failed' }]);
    const missing = setup({ message: false });
    await expect(missing.handler.handle(event(), tx)).rejects.toBeInstanceOf(NonRetryableError);
  });

  it('parses sender addresses strictly', () => {
    expect(addressDomain(' Bob@Acme.Example ')).toEqual({
      address: 'bob@acme.example',
      domain: 'acme.example',
    });
    expect(addressDomain('')).toBeNull();
    expect(addressDomain('a@b@c, d@e')).toBeNull();
    expect(addressDomain('noat')).toBeNull();
  });
});
