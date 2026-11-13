import { NonRetryableError } from '@email-gateway/common';
import type { EventEnvelope, NotificationAlertRequestedV1 } from '@email-gateway/event-contracts';
import {
  buildEnvelope,
  resolveNotificationSettings,
  WEBHOOK_EXAMPLE_DATA,
} from '@email-gateway/webhooks';
import { describe, expect, it, vi } from 'vitest';
import { AlertNotificationHandler } from './alert-notification.handler';
import type { StoredAlertEvent } from './alert-reads';
import type { NoticeMail, NoticeMailer } from './mailer';
import { NoticeSendError } from './mailer';
import type { NotificationMetrics } from './notification-metrics';
import { PreferenceFilter } from './preference-filter';

const logger = { child: () => logger, info: vi.fn(), warn: vi.fn() } as never;
const ORG_PUBLIC = '0192f0c4-0000-7000-8000-00000000a001';
const EVENT_ID = '0190f0f0-0000-7000-8000-00000000e301';
const SOURCE_EVENT = '0190f0f0-0000-7000-8000-00000000e300';
const MESSAGE_PUBLIC = WEBHOOK_EXAMPLE_DATA['email.threat.detected'].message.id;
const DOMAIN_PUBLIC = WEBHOOK_EXAMPLE_DATA['domain.dns.failed'].domain.id;
const SUBSCRIPTION = '0192f0c4-aaaa-7bbb-8ccc-000000000001';
const RECEIVED = '2026-11-13T09:14:02.481Z';
const WINDOW = { from: '2026-11-13T09:00:00.000Z', to: '2026-11-13T10:00:00.000Z' };

let preferenceRows: Array<{ organizationId: bigint; userId: bigint; preferences: unknown }> = [];
const tx = {
  notificationUserPreference: {
    findMany: vi.fn((args: { where: { organizationId: bigint; userId: { in: bigint[] } } }) =>
      Promise.resolve(
        preferenceRows.filter(
          (r) =>
            r.organizationId === args.where.organizationId &&
            args.where.userId.in.includes(r.userId),
        ),
      ),
    ),
  },
} as never;

function alert(
  kind: NotificationAlertRequestedV1['kind'],
  over: Partial<NotificationAlertRequestedV1> = {},
): EventEnvelope<NotificationAlertRequestedV1> {
  const refs: NotificationAlertRequestedV1['refs'] =
    kind === 'threat_detected'
      ? { webhookEventId: threatStored().eventId, messageId: '501', receivedAt: RECEIVED }
      : kind === 'domain_dns_failed'
        ? { webhookEventId: dnsStored().eventId, domainId: '31' }
        : { subscriptionId: SUBSCRIPTION };
  return {
    eventId: EVENT_ID,
    eventType: 'notification.alert_requested.v1',
    occurredAt: '2026-11-13T09:14:03.000Z',
    correlationId: 'corr-12345678',
    organizationId: '7',
    payload: {
      kind,
      severity: kind === 'webhook_disabled' ? 'medium' : 'high',
      refs,
      window: WINDOW,
      counts: { suppressedBefore: 3 },
      requestedAt: '2026-11-13T09:14:03.000Z',
      ...over,
    },
  };
}

function threatStored(): StoredAlertEvent {
  const built = buildEnvelope({
    type: 'email.threat.detected',
    occurredAt: '2026-11-13T09:14:03.000Z',
    organizationPublicId: ORG_PUBLIC,
    sourceEventId: SOURCE_EVENT,
    data: WEBHOOK_EXAMPLE_DATA['email.threat.detected'],
  });
  return {
    eventId: built.envelope.id,
    eventType: 'email.threat.detected',
    occurredAt: new Date('2026-11-13T09:14:03.000Z'),
    severity: 'high',
    messageId: 501n,
    messageReceivedAt: new Date(RECEIVED),
    domainId: null,
    envelope: built.envelope,
  };
}

function dnsStored(): StoredAlertEvent {
  const built = buildEnvelope({
    type: 'domain.dns.failed',
    occurredAt: '2026-11-13T09:05:00.000Z',
    organizationPublicId: ORG_PUBLIC,
    sourceEventId: SOURCE_EVENT,
    data: WEBHOOK_EXAMPLE_DATA['domain.dns.failed'],
  });
  return {
    eventId: built.envelope.id,
    eventType: 'domain.dns.failed',
    occurredAt: new Date('2026-11-13T09:05:00.000Z'),
    severity: 'high',
    messageId: null,
    messageReceivedAt: null,
    domainId: 31n,
    envelope: built.envelope,
  };
}

interface SetupOptions {
  configured?: boolean;
  fail?: boolean;
  settings?: unknown;
  contact?: string | null;
  holders?: Record<string, Array<{ id: bigint; email: string }>>;
  maxRecipients?: number;
}

const HOLDERS: Record<string, Array<{ id: bigint; email: string }>> = {
  'quarantine:approve': [
    { id: 11n, email: 'ann@acme.example' },
    { id: 12n, email: 'bob@acme.example' },
  ],
  'domain:manage': [{ id: 13n, email: 'dom@acme.example' }],
  'webhook:manage': [{ id: 14n, email: 'hook@acme.example' }],
};

function setup(options: SetupOptions = {}) {
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
  const holders = options.holders ?? HOLDERS;
  const reads = {
    organization: vi.fn(() =>
      Promise.resolve({
        id: 7n,
        publicId: ORG_PUBLIC,
        name: 'Acme',
        notificationEmail: options.contact === undefined ? 'SecOps@Acme.example' : options.contact,
      }),
    ),
    settings: vi.fn(() =>
      Promise.resolve({ settings: resolve(options.settings), invalidStored: false }),
    ),
    holders: vi.fn(
      (_tx: unknown, _org: bigint, permission: string, take: number, afterId: bigint | null) =>
        Promise.resolve(
          (holders[permission] ?? [])
            .filter((h) => afterId === null || h.id > afterId)
            .slice(0, take),
        ),
    ),
    windowEventCount: vi.fn(() => Promise.resolve(5)),
    webhookEvent: vi.fn((_tx: unknown, _org: bigint, eventId: string) => {
      const threat = threatStored();
      const dns = dnsStored();
      return Promise.resolve(
        eventId === threat.eventId ? threat : eventId === dns.eventId ? dns : null,
      );
    }),
    messageIdentity: vi.fn(() =>
      Promise.resolve({ publicId: MESSAGE_PUBLIC, receivedAt: new Date(RECEIVED) }),
    ),
    domain: vi.fn(() =>
      Promise.resolve({ id: 31n, publicId: DOMAIN_PUBLIC, name: 'acme.example', status: 'active' }),
    ),
    failingRecordPurposes: vi.fn(() => Promise.resolve(['spf'])),
    subscription: vi.fn(() =>
      Promise.resolve({
        publicId: SUBSCRIPTION,
        name: 'SIEM feed',
        status: 'disabled',
        consecutiveFailures: 50,
        failingSince: new Date('2026-11-12T09:00:00.000Z'),
        disabledAt: new Date('2026-11-13T09:00:00.000Z'),
        disabledReason: 'sustained_failure',
      }),
    ),
  };
  const counts: Array<Record<string, string>> = [];
  const suppressed: Array<[Record<string, string>, number | undefined]> = [];
  const metrics = {
    alertMessages: { inc: (labels: Record<string, string>) => counts.push(labels) },
    alertsSuppressed: {
      inc: (labels: Record<string, string>, n?: number) => suppressed.push([labels, n]),
    },
    sendDuration: { startTimer: () => () => 0 },
  } as unknown as NotificationMetrics;
  preferenceRows = [];
  const handler = new AlertNotificationHandler(
    reads,
    mailer,
    metrics,
    logger,
    { maxRecipients: options.maxRecipients ?? 50, portalUrl: 'https://portal.example' },
    new PreferenceFilter(metrics),
  );
  return { handler, reads, sent, counts, suppressed };
}

// resolveNotificationSettings is pure; the reads fake returns it like the real reads do.
const resolve = (stored: unknown) => resolveNotificationSettings(stored ?? null).settings;

describe('AlertNotificationHandler (step 6.2 N3, N4)', () => {
  it('threat_detected: one mail to quarantine:approve holders + the organization contact, Bcc', async () => {
    const s = setup();
    expect(await s.handler.handle(alert('threat_detected'), tx)).toBe('sent');
    expect(s.reads.holders).toHaveBeenCalledWith(tx, 7n, 'quarantine:approve', 50, null);
    expect(s.sent).toHaveLength(1);
    const mail = s.sent[0]!;
    expect(mail.recipients).toEqual([
      'ann@acme.example',
      'bob@acme.example',
      'secops@acme.example',
    ]);
    expect(mail.messageId).toBe(`<security-alert.${EVENT_ID}@gw.example>`);
    expect(mail.subject).toBe('[Email Gateway] Security alert (high): threat detected');
    expect(mail.text).toContain('Verdict: malicious');
    expect(mail.text).toContain(`First message of the window: ${MESSAGE_PUBLIC}`);
    expect(mail.text).toContain(`https://portal.example/messages/${MESSAGE_PUBLIC}`);
    expect(mail.text).toContain('Events in this window so far: 5');
    expect(mail.text).toContain('Suppressed before this alert: 3');
    // The stored envelope carries the Internet-Message-ID and sender domains: never rendered.
    expect(mail.text).not.toContain('@');
    expect(mail.text).not.toContain('partner.example');
    expect(s.reads.windowEventCount).toHaveBeenCalledWith(
      tx,
      7n,
      'threat_detected',
      '-',
      new Date(WINDOW.from),
    );
    expect(s.counts).toEqual([{ kind: 'threat_detected', result: 'sent' }]);
  });

  it('domain_dns_failed: domain:manage holders, the domain name, purposes and link', async () => {
    const s = setup();
    expect(await s.handler.handle(alert('domain_dns_failed'), tx)).toBe('sent');
    expect(s.reads.holders).toHaveBeenCalledWith(tx, 7n, 'domain:manage', 50, null);
    expect(s.reads.domain).toHaveBeenCalledWith(tx, 7n, 31n);
    const mail = s.sent[0]!;
    expect(mail.recipients).toEqual(['dom@acme.example', 'secops@acme.example']);
    expect(mail.text).toContain('Domain: acme.example');
    expect(mail.text).toContain('Failed records: spf');
    expect(mail.text).toContain(`https://portal.example/domains/${DOMAIN_PUBLIC}`);
    expect(s.reads.windowEventCount).toHaveBeenCalledWith(
      tx,
      7n,
      'domain_dns_failed',
      DOMAIN_PUBLIC,
      new Date(WINDOW.from),
    );
  });

  it('webhook_disabled: webhook:manage holders, name and counters, never the endpoint', async () => {
    const s = setup();
    expect(await s.handler.handle(alert('webhook_disabled'), tx)).toBe('sent');
    expect(s.reads.holders).toHaveBeenCalledWith(tx, 7n, 'webhook:manage', 50, null);
    expect(s.reads.subscription).toHaveBeenCalledWith(tx, 7n, SUBSCRIPTION);
    const mail = s.sent[0]!;
    expect(mail.recipients).toEqual(['hook@acme.example', 'secops@acme.example']);
    expect(mail.subject).toBe('[Email Gateway] Security alert (medium): webhook endpoint disabled');
    expect(mail.text).toContain(`Subscription: SIEM feed (${SUBSCRIPTION})`);
    expect(mail.text).toContain('Consecutive failed deliveries: 50');
    expect(mail.text).toContain(`https://portal.example/webhooks/${SUBSCRIPTION}`);
    expect(s.reads.windowEventCount).toHaveBeenCalledWith(
      tx,
      7n,
      'webhook_disabled',
      SUBSCRIPTION,
      new Date(WINDOW.from),
    );
  });

  it('removes users who opted out of the kind before the cap and counts them', async () => {
    const s = setup({
      maxRecipients: 1,
      contact: null,
      holders: {
        'quarantine:approve': [
          { id: 11n, email: 'ann@acme.example' },
          { id: 12n, email: 'bob@acme.example' },
          { id: 15n, email: 'cat@acme.example' },
        ],
      },
    });
    preferenceRows = [
      { organizationId: 7n, userId: 11n, preferences: { optOut: ['threat_detected'] } },
      { organizationId: 7n, userId: 12n, preferences: { optOut: ['domain_dns_failed'] } },
    ];
    expect(await s.handler.handle(alert('threat_detected'), tx)).toBe('sent');
    // ann opted out; bob fills the cap of 1 from the second page.
    expect(s.sent[0]!.recipients).toEqual(['bob@acme.example']);
    expect(s.suppressed).toEqual([[{ kind: 'threat_detected', reason: 'opt_out' }, 1]]);
  });

  it('organization contact: only with includeOrganizationContact, de-duplicated, invalid counted', async () => {
    const off = setup({ settings: { alerts: { includeOrganizationContact: false } } });
    await off.handler.handle(alert('threat_detected'), tx);
    expect(off.sent[0]!.recipients).toEqual(['ann@acme.example', 'bob@acme.example']);

    const dup = setup({ contact: 'ANN@acme.example' });
    await dup.handler.handle(alert('threat_detected'), tx);
    expect(dup.sent[0]!.recipients).toEqual(['ann@acme.example', 'bob@acme.example']);

    const invalid = setup({ contact: 'not an address' });
    await invalid.handler.handle(alert('threat_detected'), tx);
    expect(invalid.sent[0]!.recipients).toEqual(['ann@acme.example', 'bob@acme.example']);
    expect(invalid.suppressed).toEqual([
      [{ kind: 'threat_detected', reason: 'invalid_contact' }, undefined],
    ]);

    // Only the contact: still one mail.
    const contactOnly = setup({ holders: {} });
    expect(await contactOnly.handler.handle(alert('webhook_disabled'), tx)).toBe('sent');
    expect(contactOnly.sent[0]!.recipients).toEqual(['secops@acme.example']);
  });

  it.each([
    [
      'threat alerts switched off',
      'threat_detected',
      { alerts: { threatDetected: { enabled: false } } },
      {},
    ],
    [
      'DNS alerts switched off',
      'domain_dns_failed',
      { alerts: { domainDnsFailed: { enabled: false } } },
      {},
    ],
    [
      'webhook alerts switched off',
      'webhook_disabled',
      { alerts: { webhookDisabled: { enabled: false } } },
      {},
    ],
    ['minSeverity raised above the alert', 'threat_detected', {}, { severity: 'medium' }],
  ] as const)(
    '%s since the request → disabled, nothing read or sent',
    async (_l, kind, settings, over) => {
      const s = setup({ settings });
      expect(await s.handler.handle(alert(kind, over as never), tx)).toBe('disabled');
      expect(s.sent).toEqual([]);
      expect(s.reads.holders).not.toHaveBeenCalled();
      expect(s.counts).toEqual([{ kind, result: 'disabled' }]);
      expect(s.suppressed).toEqual([[{ kind, reason: 'disabled' }, undefined]]);
    },
  );

  it('a medium threat is sent when the tenant lowered minSeverity to medium', async () => {
    const s = setup({ settings: { alerts: { threatDetected: { minSeverity: 'medium' } } } });
    expect(await s.handler.handle(alert('threat_detected', { severity: 'medium' }), tx)).toBe(
      'sent',
    );
  });

  it('no holder and no contact → no_recipients; everyone opted out → no_recipients', async () => {
    const none = setup({ holders: {}, contact: null });
    expect(await none.handler.handle(alert('domain_dns_failed'), tx)).toBe('no_recipients');
    expect(none.sent).toEqual([]);
    expect(none.counts).toEqual([{ kind: 'domain_dns_failed', result: 'no_recipients' }]);

    const opted = setup({ contact: null });
    preferenceRows = [
      { organizationId: 7n, userId: 13n, preferences: { optOut: ['domain_dns_failed'] } },
    ];
    expect(await opted.handler.handle(alert('domain_dns_failed'), tx)).toBe('no_recipients');
    // Another organization's preference row never applies.
    const foreign = setup({ contact: null });
    preferenceRows = [
      { organizationId: 8n, userId: 13n, preferences: { optOut: ['domain_dns_failed'] } },
    ];
    expect(await foreign.handler.handle(alert('domain_dns_failed'), tx)).toBe('sent');
  });

  it('no relay → disabled (as the existing handlers); a relay failure is counted and thrown', async () => {
    const off = setup({ configured: false });
    expect(await off.handler.handle(alert('threat_detected'), tx)).toBe('disabled');
    expect(off.suppressed).toEqual([]);
    const failing = setup({ fail: true });
    await expect(failing.handler.handle(alert('threat_detected'), tx)).rejects.toBeInstanceOf(
      NoticeSendError,
    );
    expect(failing.counts).toEqual([{ kind: 'threat_detected', result: 'failed' }]);
  });

  it('dead-letters missing or mismatching references without a send', async () => {
    const cases: Array<[string, (s: ReturnType<typeof setup>) => void, ReturnType<typeof alert>]> =
      [
        [
          'organization_not_found',
          (s) => s.reads.organization.mockResolvedValue(null as never),
          alert('threat_detected'),
        ],
        [
          'webhook_event_not_found',
          (s) => s.reads.webhookEvent.mockResolvedValue(null),
          alert('threat_detected'),
        ],
        [
          'webhook_event_mismatch',
          (s) => s.reads.webhookEvent.mockResolvedValue(dnsStored()),
          alert('threat_detected', {
            refs: { webhookEventId: dnsStored().eventId, messageId: '501', receivedAt: RECEIVED },
          }),
        ],
        [
          'webhook_event_mismatch',
          () => undefined,
          alert('threat_detected', {
            refs: {
              webhookEventId: threatStored().eventId,
              messageId: '999',
              receivedAt: RECEIVED,
            },
          }),
        ],
        [
          'message_not_found',
          (s) => s.reads.messageIdentity.mockResolvedValue(null as never),
          alert('threat_detected'),
        ],
        [
          'message_mismatch',
          () => undefined,
          alert('threat_detected', {
            refs: {
              webhookEventId: threatStored().eventId,
              messageId: '501',
              receivedAt: '2026-11-13T09:14:02.000Z',
            },
          }),
        ],
        [
          'webhook_event_mismatch',
          (s) =>
            s.reads.organization.mockResolvedValue({
              id: 7n,
              publicId: '0192f0c4-0000-7000-8000-00000000b002',
              name: 'Other',
              notificationEmail: null,
            }),
          alert('threat_detected'),
        ],
        [
          'domain_not_found',
          (s) => s.reads.domain.mockResolvedValue(null as never),
          alert('domain_dns_failed'),
        ],
        [
          'webhook_event_mismatch',
          () => undefined,
          alert('domain_dns_failed', {
            refs: { webhookEventId: dnsStored().eventId, domainId: '32' },
          }),
        ],
        [
          'subscription_not_found',
          (s) => s.reads.subscription.mockResolvedValue(null as never),
          alert('webhook_disabled'),
        ],
      ];
    for (const [code, arrange, e] of cases) {
      const s = setup();
      arrange(s);
      const error = await s.handler.handle(e, tx).then(
        () => null,
        (err: unknown) => err,
      );
      expect(error, code).toBeInstanceOf(NonRetryableError);
      expect((error as NonRetryableError).code, code).toBe(code);
      expect(s.sent, code).toEqual([]);
      expect(s.counts, code).toEqual([{ kind: e.payload.kind, result: 'failed' }]);
    }
  });

  it('reads only within the envelope organization', async () => {
    const s = setup();
    await s.handler.handle(alert('threat_detected'), tx);
    for (const fn of [
      s.reads.organization,
      s.reads.settings,
      s.reads.webhookEvent,
      s.reads.messageIdentity,
    ]) {
      for (const call of fn.mock.calls as unknown[][]) expect(call[1]).toBe(7n);
    }
  });
});
