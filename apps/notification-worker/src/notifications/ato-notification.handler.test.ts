import { NonRetryableError } from '@email-gateway/common';
import type { AtoNotificationRequestedV1, EventEnvelope } from '@email-gateway/event-contracts';
import { describe, expect, it, vi } from 'vitest';
import { AtoNotificationHandler, type AtoNotificationOptions } from './ato-notification.handler';
import {
  type AtoNotificationReads,
  type AtoNotificationSettings,
  resolveAtoNotificationSettings,
} from './ato-reads';
import type { NoticeMail, NoticeMailer } from './mailer';
import type { NotificationMetrics } from './notification-metrics';
import { PreferenceFilter } from './preference-filter';

const logger = { child: () => logger, info: vi.fn(), warn: vi.fn() } as never;
const INCIDENT = '0193a1b2-1c2d-7e3f-8a4b-5c6d7e8f9012';
const ACTION = '0193a1b2-2d3e-7f40-8b5c-6d7e8f901234';
const ACCOUNT = '0193a1b2-0a1b-7c2d-9e3f-4a5b6c7d8e9f';
const INTEGRATION = '0193a1b2-3e4f-7a50-9c6d-7e8f90123456';
const WINDOW = { from: '2026-11-18T08:00:00.000Z', to: '2026-11-18T08:15:00.000Z' };

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

function event(
  over: Partial<AtoNotificationRequestedV1> = {},
): EventEnvelope<AtoNotificationRequestedV1> {
  return {
    eventId: '0190f0f0-0000-7000-8000-00000000a701',
    eventType: 'ato.notification.requested.v1',
    occurredAt: '2026-11-18T08:01:01.000Z',
    correlationId: 'corr-ato-0001',
    organizationId: '7',
    payload: {
      kind: 'incident_alert',
      audience: 'tenant',
      severity: 'high',
      refs: { incidentPublicId: INCIDENT, accountPublicId: ACCOUNT },
      window: WINDOW,
      counts: { suppressedBefore: 2 },
      digestPeriod: null,
      requestedAt: '2026-11-18T08:01:01.000Z',
      ...over,
    },
  };
}

interface World {
  featureEnabled: boolean;
  settings: AtoNotificationSettings;
  incidentSeverity: 'low' | 'medium' | 'high' | 'critical';
  actionStatus: string;
  holders: Array<{ id: bigint; email: string }>;
  contact: string | null;
  orgId: bigint;
  integrationHealth: string;
}

function setup(world: Partial<World> = {}, options: Partial<AtoNotificationOptions> = {}) {
  const w: World = {
    featureEnabled: true,
    settings: resolveAtoNotificationSettings(null),
    incidentSeverity: 'high',
    actionStatus: 'pending_approval',
    holders: [
      { id: 1n, email: 'responder1@acme.example' },
      { id: 2n, email: 'responder2@acme.example' },
    ],
    contact: 'security@acme.example',
    orgId: 7n,
    integrationHealth: 'unhealthy',
    ...world,
  };
  const holders = vi.fn(
    (_tx: unknown, _org: bigint, _perm: string, take: number, afterId: bigint | null) =>
      Promise.resolve(w.holders.filter((h) => afterId === null || h.id > afterId).slice(0, take)),
  );
  const reads = {
    organization: vi.fn((_tx: unknown, id: bigint) =>
      Promise.resolve(
        id === w.orgId
          ? {
              id,
              publicId: '0192f0c4-0000-7000-8000-00000000a001',
              slug: 'acme-corp',
              name: 'Acme Corp',
              notificationEmail: w.contact,
            }
          : null,
      ),
    ),
    state: vi.fn(() => Promise.resolve({ featureEnabled: w.featureEnabled, settings: w.settings })),
    incident: vi.fn((_tx: unknown, _org: bigint, publicId: string) =>
      Promise.resolve(
        publicId === INCIDENT
          ? {
              id: 301n,
              publicId: INCIDENT,
              status: 'open',
              severity: w.incidentSeverity,
              titleCode: 'ato.geo.impossible_travel',
              reasonCodes: ['ato.geo.impossible_travel'],
              subjectRefId: 11n,
              detectedAt: new Date('2026-11-18T08:01:00.000Z'),
            }
          : null,
      ),
    ),
    account: vi.fn(() =>
      Promise.resolve({
        publicId: ACCOUNT,
        kind: 'mailbox' as const,
        address: 'jane.doe@acme.example',
        name: null,
      }),
    ),
    action: vi.fn((_tx: unknown, _org: bigint, publicId: string) =>
      Promise.resolve(
        publicId === ACTION
          ? {
              publicId: ACTION,
              actionType: 'restrict_smtp_sending',
              status: w.actionStatus,
              impact: 'high',
              provider: 'gateway',
              resultCode: w.actionStatus === 'failed' ? 'restriction_cap_reached' : null,
              approvalExpiresAt: new Date('2026-11-19T08:00:00.000Z'),
              incidentId: 301n,
              accountId: 11n,
            }
          : null,
      ),
    ),
    holders,
    integration: vi.fn((_tx: unknown, _org: bigint, publicId: string) =>
      Promise.resolve(
        publicId === INTEGRATION
          ? {
              publicId: INTEGRATION,
              provider: 'microsoft_entra',
              displayName: 'Contoso IT (example)',
              status: 'active',
              healthStatus: w.integrationHealth,
              failingStreams: ['risk_events', 'sign_ins'],
              missingPermissions: ['AuditLog.Read.All', 'IdentityRiskEvent.Read.All'],
            }
          : null,
      ),
    ),
    windowEventCount: vi.fn(() => Promise.resolve(4)),
    digest: vi.fn(() =>
      Promise.resolve({
        openedBySeverity: { low: 0, medium: 0, high: 1, critical: 0 },
        resolvedByResolution: { remediated: 0, false_positive: 1 },
        falsePositives: 1,
        activeCritical: 0,
        pendingApprovals: 1,
        restrictedAccounts: 0,
        topRuleCodes: [],
      }),
    ),
  } as unknown as AtoNotificationReads;
  const sent: NoticeMail[] = [];
  const mailer: NoticeMailer = {
    configured: true,
    from: 'Email Gateway <no-reply@gateway.example>',
    send: vi.fn((mail: NoticeMail) => {
      sent.push(mail);
      return Promise.resolve();
    }),
    close: vi.fn(),
  };
  const inc = vi.fn();
  const metrics = {
    atoMessages: { inc },
    alertsSuppressed: { inc: vi.fn() },
    sendDuration: { startTimer: () => () => 0 },
  } as unknown as NotificationMetrics;
  const handler = new AtoNotificationHandler(
    reads,
    mailer,
    metrics,
    logger,
    {
      maxRecipients: 50,
      portalUrl: 'https://portal.example',
      platformSocEmail: '',
      ...options,
    },
    new PreferenceFilter(metrics),
  );
  return { handler, reads, sent, inc, holders };
}

describe('AtoNotificationHandler (step 8.4 D16)', () => {
  it('sends a tenant incident alert to the ato:respond holders plus the contact, masked', async () => {
    preferenceRows = [];
    const { handler, sent, holders, inc } = setup();
    await expect(handler.handle(event(), tx)).resolves.toBe('sent');
    expect(holders.mock.calls[0]![2]).toBe('ato:respond');
    expect(sent).toHaveLength(1);
    expect(sent[0]!.recipients).toEqual([
      'responder1@acme.example',
      'responder2@acme.example',
      'security@acme.example',
    ]);
    expect(sent[0]!.text).toContain('j***@acme.example');
    expect(sent[0]!.text).not.toContain('jane.doe@');
    expect(sent[0]!.messageId).toBe(
      '<ato-notice.0190f0f0-0000-7000-8000-00000000a701.tenant@gateway.example>',
    );
    expect(inc).toHaveBeenCalledWith({
      kind: 'incident_alert',
      audience: 'tenant',
      result: 'sent',
    });
  });

  it('removes users who opted out of ato_incident before the cap', async () => {
    preferenceRows = [
      { organizationId: 7n, userId: 1n, preferences: { optOut: ['ato_incident'] } },
    ];
    const { handler, sent } = setup({ contact: null });
    await handler.handle(event(), tx);
    expect(sent[0]!.recipients).toEqual(['responder2@acme.example']);
    preferenceRows = [];
  });

  it('digests go to ato:read holders minus ato_digest opt-outs; a period switched off is disabled', async () => {
    preferenceRows = [{ organizationId: 7n, userId: 2n, preferences: { optOut: ['ato_digest'] } }];
    const digest = event({
      kind: 'digest',
      severity: null,
      refs: {},
      digestPeriod: 'daily',
      window: { from: '2026-11-17T00:00:00.000Z', to: '2026-11-18T00:00:00.000Z' },
    });
    const { handler, sent, holders, reads } = setup({ contact: null });
    await expect(handler.handle(digest, tx)).resolves.toBe('sent');
    expect(holders.mock.calls[0]![2]).toBe('ato:read');
    expect(sent[0]!.recipients).toEqual(['responder1@acme.example']);
    expect((reads.digest as ReturnType<typeof vi.fn>).mock.calls[0]!.slice(2)).toEqual([
      new Date('2026-11-17T00:00:00.000Z'),
      new Date('2026-11-18T00:00:00.000Z'),
    ]);
    preferenceRows = [];
    const off = setup({
      settings: { ...resolveAtoNotificationSettings(null), digest: { daily: false, weekly: true } },
    });
    await expect(off.handler.handle(digest, tx)).resolves.toBe('disabled');
    expect(off.sent).toHaveLength(0);
  });

  it('approval requests and failures go out only while the action is in that state', async () => {
    const approval = event({
      kind: 'approval_requested',
      severity: null,
      refs: { actionPublicId: ACTION, accountPublicId: ACCOUNT },
    });
    const pending = setup();
    await expect(pending.handler.handle(approval, tx)).resolves.toBe('sent');
    expect(pending.sent[0]!.text).toContain('/ato/responses?status=pending_approval');
    const decided = setup({ actionStatus: 'approved' });
    await expect(decided.handler.handle(approval, tx)).resolves.toBe('not_applicable');
    const failure = event({
      kind: 'response_failed',
      severity: null,
      refs: { actionPublicId: ACTION, incidentPublicId: INCIDENT },
    });
    const failed = setup({ actionStatus: 'failed' });
    await expect(failed.handler.handle(failure, tx)).resolves.toBe('sent');
    expect(failed.sent[0]!.text).toContain('Result: restriction_cap_reached');
  });

  it('SOC audience goes to the tenant socEmails only', async () => {
    const settings = {
      ...resolveAtoNotificationSettings(null),
      socEmails: ['soc@acme.example', 'SOC@acme.example', 'soc2@acme.example'],
    };
    const { handler, sent, holders } = setup({ settings });
    await handler.handle(event({ audience: 'soc' }), tx);
    expect(holders).not.toHaveBeenCalled();
    expect(sent[0]!.recipients).toEqual(['soc@acme.example', 'soc2@acme.example']);
  });

  it('platform SOC: off when the key is empty; critical only; slug and id only', async () => {
    const critical = event({ audience: 'platform_soc', severity: 'critical' });
    const off = setup({ incidentSeverity: 'critical' });
    await expect(off.handler.handle(critical, tx)).resolves.toBe('disabled');
    const on = setup(
      { incidentSeverity: 'critical' },
      { platformSocEmail: 'platform-soc@gateway.example' },
    );
    await expect(on.handler.handle(critical, tx)).resolves.toBe('sent');
    expect(on.sent[0]!.recipients).toEqual(['platform-soc@gateway.example']);
    expect(on.sent[0]!.text).toContain('Organization: acme-corp');
    expect(on.sent[0]!.text).not.toContain('***@');
    const deescalated = setup(
      { incidentSeverity: 'high' },
      { platformSocEmail: 'platform-soc@gateway.example' },
    );
    await expect(deescalated.handler.handle(critical, tx)).resolves.toBe('not_applicable');
  });

  it('feature off, mode off, a raised minimum severity or no relay send nothing', async () => {
    await expect(setup({ featureEnabled: false }).handler.handle(event(), tx)).resolves.toBe(
      'disabled',
    );
    const modeOff = { ...resolveAtoNotificationSettings(null), mode: 'off' as const };
    await expect(setup({ settings: modeOff }).handler.handle(event(), tx)).resolves.toBe(
      'disabled',
    );
    const raised = {
      ...resolveAtoNotificationSettings(null),
      incidentMinSeverity: 'critical' as const,
    };
    await expect(setup({ settings: raised }).handler.handle(event(), tx)).resolves.toBe('disabled');
    await expect(setup({ holders: [], contact: null }).handler.handle(event(), tx)).resolves.toBe(
      'no_recipients',
    );
  });

  it('dead-letters missing or foreign references', async () => {
    const { handler } = setup();
    await expect(
      handler.handle(event({ refs: { incidentPublicId: ACTION } }), tx),
    ).rejects.toBeInstanceOf(NonRetryableError);
    await expect(handler.handle(event({ refs: {} }), tx)).rejects.toBeInstanceOf(NonRetryableError);
    await expect(setup({ orgId: 8n }).handler.handle(event(), tx)).rejects.toBeInstanceOf(
      NonRetryableError,
    );
  });

  it('step 8.5 provider_unhealthy: ato:configure holders minus ato_provider_health opt-outs, no contact', async () => {
    preferenceRows = [
      { organizationId: 7n, userId: 2n, preferences: { optOut: ['ato_provider_health'] } },
    ];
    const { handler, sent, holders, inc } = setup();
    const request = event({
      kind: 'provider_unhealthy',
      severity: null,
      refs: { integrationPublicId: INTEGRATION },
    });
    await expect(handler.handle(request, tx)).resolves.toBe('sent');
    expect(holders.mock.calls[0]![2]).toBe('ato:configure');
    // The organization contact is not an integration administrator (D11).
    expect(sent[0]!.recipients).toEqual(['responder1@acme.example']);
    expect(sent[0]!.subject).toContain('identity provider unhealthy');
    expect(sent[0]!.text).toContain('Microsoft Entra ID / Microsoft 365');
    expect(sent[0]!.text).toContain('Contoso IT (example)');
    expect(sent[0]!.text).toContain('risk events, sign ins');
    expect(sent[0]!.text).toContain('AuditLog.Read.All, IdentityRiskEvent.Read.All');
    expect(sent[0]!.text).toContain(`https://portal.example/ato/providers/${INTEGRATION}`);
    expect(inc).toHaveBeenCalledWith({
      kind: 'provider_unhealthy',
      audience: 'tenant',
      result: 'sent',
    });
    preferenceRows = [];
  });

  it('step 8.5 provider_unhealthy: recovered before sending ⇒ not_applicable; unknown ⇒ dead letter', async () => {
    const recovered = setup({ integrationHealth: 'healthy' });
    const request = event({
      kind: 'provider_unhealthy',
      severity: null,
      refs: { integrationPublicId: INTEGRATION },
    });
    await expect(recovered.handler.handle(request, tx)).resolves.toBe('not_applicable');
    expect(recovered.sent).toHaveLength(0);
    const { handler, sent } = setup();
    await expect(
      handler.handle(
        event({
          kind: 'provider_unhealthy',
          severity: null,
          refs: { integrationPublicId: ACTION },
        }),
        tx,
      ),
    ).rejects.toBeInstanceOf(NonRetryableError);
    expect(sent).toHaveLength(0);
  });
});

describe('resolveAtoNotificationSettings', () => {
  it('reads the stored notifications block leniently with the documented defaults', () => {
    expect(resolveAtoNotificationSettings(null)).toEqual({
      mode: 'monitor',
      incidentMinSeverity: 'high',
      socEmails: [],
      includeOrganizationContact: true,
      digest: { daily: true, weekly: true },
    });
    expect(
      resolveAtoNotificationSettings({
        mode: 'enforce',
        notifications: {
          incidentMinSeverity: 'critical',
          socEmails: ['A@x.example'],
          includeOrganizationContact: false,
          digest: { weekly: false },
        },
      }),
    ).toEqual({
      mode: 'enforce',
      incidentMinSeverity: 'critical',
      socEmails: ['a@x.example'],
      includeOrganizationContact: false,
      digest: { daily: true, weekly: false },
    });
    expect(
      resolveAtoNotificationSettings({ mode: 7, notifications: { incidentMinSeverity: 'x' } }),
    ).toMatchObject({ mode: 'monitor', incidentMinSeverity: 'high' });
  });
});
