import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AtoAccount, PrismaClient } from '@email-gateway/database';
import { EventTypes } from '@email-gateway/event-contracts';
import { atoMailboxSha256, atoSubjectHash } from '@email-gateway/security-contracts';
import {
  IncidentActiveConflictError,
  IncidentCategoryRegistry,
  IncidentStore,
  type IncidentActor,
  type IncidentRow,
} from '@email-gateway/security-incidents';
import { fakeCategoryHandler } from '@email-gateway/security-incidents/testing';
import { atoIncidentHandler } from '../src/incident-handler';
import { AtoStore, isAtoStoreError, type AtoStoreConfig, type LoadedSettings } from '../src/store';
import { candidate, Fixtures, hex64 } from './support/fixtures';

const fx = new Fixtures();
let prisma: PrismaClient;
const T0 = new Date('2026-11-18T10:00:00.000Z');
let clock = T0;
const at = () => clock;
const advance = (ms: number) => {
  clock = new Date(clock.getTime() + ms);
};
const MIN = 60_000;

const config: AtoStoreConfig = {
  approvalTtlHours: 24,
  automatedResponsesEnabled: true,
  maxAutomatedPerOrgPerHour: 10,
  maxActiveRestrictionsPerOrg: 500,
};
// eslint-disable-next-line prefer-const -- assigned after the registry that needs it lazily
let store: AtoStore;
const registry = new IncidentCategoryRegistry([
  atoIncidentHandler({ store: () => store }),
  fakeCategoryHandler(),
]);
const incidents = new IncidentStore({ registry, now: at });
store = new AtoStore({ now: at, incidents, config });

const system: IncidentActor = { type: 'system', id: null };
let orgA: bigint;
let orgB: bigint;
let analyst1: IncidentActor;
let analyst2: IncidentActor;

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error, `expected ${code}`).not.toBeNull();
  const actual = isAtoStoreError(error) ? error.code : (error as { code?: string }).code;
  expect(actual).toBe(code);
}

const outbox = (organizationId: bigint, eventType: string) =>
  prisma.messageOutbox.findMany({
    where: { organizationId, eventType },
    orderBy: { id: 'asc' },
  });

const payloadOf = (row: { payload: unknown }) => row.payload as Record<string, unknown>;

async function mailbox(organizationId: bigint, label: string): Promise<AtoAccount> {
  return fx.tx((t) =>
    store.ensureAccount(t, {
      organizationId,
      subject: { kind: 'mailbox', address: fx.address(label) },
      at: clock,
    }),
  );
}

/** Signals → rescore → incident policy in one transaction, as the detect role does. */
async function detect(
  organizationId: bigint,
  account: AtoAccount,
  codes: Array<string | ReturnType<typeof candidate>>,
  options: { hasAtoPolicyRule?: boolean; newStrongSignal?: boolean } = {},
) {
  return fx.tx(async (t) => {
    const settings = await store.ensureSettings(t, organizationId);
    const [locked] = await store.lockAccounts(t, organizationId, [account.id]);
    const recorded = await store.recordSignals(t, {
      organizationId,
      account: locked!,
      candidates: codes.map((c) => (typeof c === 'string' ? candidate(c) : c)),
      settingsVersion: settings.version,
      at: clock,
    });
    const rescore = await store.rescore(t, {
      organizationId,
      accountId: account.id,
      trigger: 'signal',
      settings,
    });
    const policy = await store.applyIncidentPolicy(t, {
      organizationId,
      accountId: account.id,
      rescore,
      settings,
      evidence: {
        signals: recorded.created.map((s) => ({ id: s.id, detectedAt: s.detectedAt })),
        authEvents: [],
        messages: recorded.created
          .filter((s) => s.messageId !== null)
          .map((s) => ({ id: s.messageId!, receivedAt: s.messageReceivedAt! })),
        codes: recorded.created.map((s) => s.ruleCode),
      },
      newStrongSignal:
        options.newStrongSignal ?? recorded.created.some((s) => s.strength === 'strong'),
      context: {
        hasAtoPolicyRule: options.hasAtoPolicyRule ?? false,
        providerActions: new Set<string>(),
      },
    });
    return { recorded, rescore, policy, settings };
  });
}

beforeAll(async () => {
  prisma = fx.prisma;
  orgA = await fx.organization('a');
  orgB = await fx.organization('b');
  const u1 = await fx.user(orgA, 'analyst1');
  const u2 = await fx.user(orgA, 'analyst2');
  analyst1 = { type: 'user', id: u1.publicId, userId: u1.id };
  analyst2 = { type: 'user', id: u2.publicId, userId: u2.id };
});

afterAll(async () => {
  await fx.cleanup();
});

describe('settings (§4.3)', () => {
  let orgS: bigint;
  beforeAll(async () => {
    orgS = await fx.organization('settings');
  });

  it('ensureSettings creates the defaults once (version 1, learning, a versions row)', async () => {
    const first = await fx.tx((t) => store.ensureSettings(t, orgS));
    const again = await fx.tx((t) => store.ensureSettings(t, orgS));
    expect(first).toMatchObject({ version: 1, rowVersion: 1, invalid: false, learning: true });
    expect(first.settings.mode).toBe('monitor');
    expect(again.version).toBe(1);
    expect(await prisma.atoSettingsVersion.count({ where: { organizationId: orgS } })).toBe(1);
  });

  it('refuses invalid settings and stale row versions', async () => {
    await expectCode(
      fx.tx((t) =>
        store.saveSettings(t, {
          organizationId: orgS,
          settings: { mode: 'sometimes' },
          expectedRowVersion: 1,
          actor: analyst1,
        }),
      ),
      'ato_settings_invalid',
    );
    await expectCode(
      fx.tx((t) =>
        store.saveSettings(t, {
          organizationId: orgS,
          settings: { scoring: { bands: { medium: 60, high: 50, critical: 75 } } },
          expectedRowVersion: 1,
          actor: analyst1,
        }),
      ),
      'ato_settings_invalid',
    );
    await expectCode(
      fx.tx((t) =>
        store.saveSettings(t, {
          organizationId: orgS,
          settings: { mode: 'enforce' },
          expectedRowVersion: 7,
          actor: analyst1,
        }),
      ),
      'ato_settings_conflict',
    );
  });

  it('saves a change by CAS: new version, versions row and an audit row with the changed paths', async () => {
    const saved = await fx.tx((t) =>
      store.saveSettings(t, {
        organizationId: orgS,
        settings: { mode: 'enforce', learningDays: 0 },
        expectedRowVersion: 1,
        actor: analyst1,
        sourceIp: '198.51.100.20',
      }),
    );
    expect(saved).toMatchObject({ version: 2, rowVersion: 2, learning: false });
    expect(saved.settings.mode).toBe('enforce');
    const versions = await prisma.atoSettingsVersion.findMany({
      where: { organizationId: orgS },
      orderBy: { version: 'asc' },
    });
    expect(versions.map((v) => v.version)).toEqual([1, 2]);
    expect(versions[1]!.settingsSha256).toMatch(/^[0-9a-f]{64}$/);
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { organizationId: orgS, action: 'ato.settings_updated' },
    });
    expect(audit.actorId).toBe(analyst1.id);
    expect(audit.metadata).toMatchObject({ version: 2 });
    expect((audit.metadata as { changedPaths: string[] }).changedPaths).toEqual(
      expect.arrayContaining(['mode', 'learningDays']),
    );
    const unchanged = await fx.tx((t) =>
      store.saveSettings(t, {
        organizationId: orgS,
        settings: { mode: 'enforce', learningDays: 0 },
        expectedRowVersion: 2,
        actor: analyst1,
      }),
    );
    expect(unchanged.version).toBe(2);
  });
});

describe('accounts (D1)', () => {
  it('ensureAccount is idempotent, lower-cases the address and moves last_seen_at forward', async () => {
    const label = 'Mixed';
    const upper = fx.address(label).toUpperCase();
    const a = await fx.tx((t) =>
      store.ensureAccount(t, {
        organizationId: orgA,
        subject: { kind: 'mailbox', address: upper },
        at: clock,
      }),
    );
    expect(a.address).toBe(fx.address(label).toLowerCase());
    expect(a.subjectHash).toBe(atoSubjectHash('mailbox', fx.address(label).toLowerCase()));
    const later = new Date(clock.getTime() + 5 * MIN);
    const b = await fx.tx((t) =>
      store.ensureAccount(t, {
        organizationId: orgA,
        subject: { kind: 'mailbox', address: fx.address(label) },
        at: later,
      }),
    );
    expect(b.id).toBe(a.id);
    expect(b.lastSeenAt.getTime()).toBe(later.getTime());
    expect(b.firstSeenAt.getTime()).toBe(a.firstSeenAt.getTime());
  });

  it('creates user and connector accounts by their ids', async () => {
    const user = await fx.tx((t) =>
      store.ensureAccount(t, {
        organizationId: orgA,
        subject: {
          kind: 'gateway_user',
          userId: analyst1.userId!,
          address: fx.address('analyst1'),
        },
        at: clock,
      }),
    );
    expect(user).toMatchObject({ kind: 'gateway_user', userId: analyst1.userId });
    expect(user.subjectHash).toBe(atoSubjectHash('user', analyst1.userId!));
    const connector = await fx.tx((t) =>
      store.ensureAccount(t, {
        organizationId: orgA,
        subject: { kind: 'smtp_connector', connectorId: 424242n },
        at: clock,
      }),
    );
    expect(connector).toMatchObject({
      kind: 'smtp_connector',
      connectorId: 424242n,
      address: null,
    });
  });

  it('isolates tenants: same address, separate accounts; foreign ids look missing', async () => {
    const a = await mailbox(orgA, 'shared');
    const b = await mailbox(orgB, 'shared');
    expect(b.id).not.toBe(a.id);
    expect(await fx.tx((t) => store.findAccount(t, orgB, a.publicId))).toBeNull();
    await expectCode(
      fx.tx((t) => store.lockAccounts(t, orgB, [a.id])),
      'ato_account_not_found',
    );
  });
});

describe('auth events and activity (D7, D9)', () => {
  it('records an enriched auth event once; an aggregate row counts attempts', async () => {
    const account = await mailbox(orgA, 'auth');
    const input = {
      organizationId: orgA,
      accountId: account.id,
      source: 'smtp_auth' as const,
      channel: 'smtp' as const,
      outcome: 'success' as const,
      failureCode: null,
      occurredAt: new Date('2026-11-18T10:00:00.000Z'),
      ip: '198.51.100.7',
      ipPrefix: '198.51.100.0/24',
      geo: {
        status: 'located' as const,
        country: 'GB',
        region: null,
        city: 'London',
        latitude: 51.5074,
        longitude: -0.1278,
        accuracyKm: 10,
        asn: 64501,
        asnOrg: 'Synthetic Documentation AS64501',
        anonymizerFlags: 0,
      },
      reputation: {
        status: 'clear',
        severity: null,
        category: null,
        confidence: null,
        providers: [],
      },
      device: null,
      mechanism: 'plain',
      sourceRef: 'evt-1:0',
      dedupeKey: hex64('auth-agg'),
      aggregate: true,
    };
    const first = await fx.tx((t) => store.recordAuthEvent(t, input));
    const second = await fx.tx((t) =>
      store.recordAuthEvent(t, { ...input, lastOccurredAt: new Date('2026-11-18T10:42:00.000Z') }),
    );
    expect(first.created).toBe(true);
    expect(second).toMatchObject({ id: first.id, created: false });
    const row = await prisma.atoAuthEvent.findFirstOrThrow({ where: { id: first.id } });
    expect(row).toMatchObject({
      attemptCount: 2,
      countryCode: 'GB',
      city: 'London',
      geoStatus: 'located',
      asn: 64501,
      accuracyKm: 10,
    });
    expect(row.lastOccurredAt.toISOString()).toBe('2026-11-18T10:42:00.000Z');
    expect(row.reputation).toMatchObject({ status: 'clear' });
    const single = { ...input, aggregate: false, dedupeKey: hex64('auth-single') };
    await fx.tx((t) => store.recordAuthEvent(t, single));
    const dup = await fx.tx((t) => store.recordAuthEvent(t, single));
    expect(dup.created).toBe(false);
    expect(
      (await prisma.atoAuthEvent.findFirstOrThrow({ where: { id: dup.id } })).attemptCount,
    ).toBe(1);
    await expectCode(
      fx.tx((t) => store.recordAuthEvent(t, { ...input, dedupeKey: 'nothex' })),
      'ato_inconsistent_read',
    );
  });

  it('merges activity deltas into one day row with bounded lists', async () => {
    const account = await mailbox(orgA, 'activity');
    for (let i = 0; i < 3; i++) {
      await fx.tx((t) =>
        store.upsertActivityDay(t, {
          organizationId: orgA,
          accountId: account.id,
          delta: {
            at: new Date(T0.getTime() + i * MIN),
            messages: 1,
            recipients: 2,
            externalRecipients: 2,
            recipientDomains: ['partner.example', `d${i}.example`],
            ipPrefix: { p: '198.51.100.0/24', cc: 'GB', asn: 64501 },
          },
        }),
      );
    }
    const rows = await prisma.atoAccountActivityDaily.findMany({
      where: { organizationId: orgA, accountId: account.id },
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ messages: 3, recipients: 6, externalRecipients: 6 });
    expect(rows[0]!.dayStart.toISOString()).toBe('2026-11-18T00:00:00.000Z');
    const domains = rows[0]!.recipientDomains as Array<{ d: string; n: number }>;
    expect(domains.find((d) => d.d === 'partner.example')?.n).toBe(3);
    expect(domains).toHaveLength(4);
  });
});

describe('signals, scoring and the ATO incident (D8, D11, D12)', () => {
  let account: AtoAccount;
  let incident: IncidentRow;

  beforeAll(async () => {
    clock = T0;
    account = await mailbox(orgA, 'victim');
  });

  it('a strong signal raises the score to the strong floor and opens an incident', async () => {
    const p1 = candidate('ato.content.phishing_sent', {
      subject: 'msg-1',
      sourceKind: 'message',
      messageRef: { id: 900001n, receivedAt: T0 },
      evidence: { messageId: '01890000-0000-7000-8000-00000000abcd', codes: ['url.phishing'] },
    });
    const { recorded, rescore, policy } = await detect(orgA, account, [p1]);
    expect(recorded.created).toHaveLength(1);
    expect(rescore.result.score).toBe(60);
    expect(rescore.result.level).toBe('high');
    expect(rescore).toMatchObject({
      previousScore: 0,
      previousLevel: 'low',
      levelChanged: true,
      rowWritten: true,
    });
    expect(policy.opened).toBe(true);
    incident = policy.incident!;
    expect(incident).toMatchObject({
      category: 'account_takeover',
      subjectType: 'ato_account',
      subjectRefId: account.id,
      subjectPublicId: account.publicId,
      origin: 'detection',
      severity: 'high',
      status: 'open',
      titleCode: 'ato.content.phishing_sent',
      detectorVersion: 'ato-rules/1',
    });
    expect(incident.reasonCodes).toEqual(['ato.content.phishing_sent']);

    const detail = await prisma.atoIncidentDetail.findUniqueOrThrow({
      where: { incidentId: incident.id },
    });
    expect(detail).toMatchObject({
      accountId: account.id,
      riskScoreAtOpen: 60,
      peakRiskScore: 60,
      signalCount: 1,
      messageCount: 1,
    });
    const recs = detail.recommendedActions as Array<{ actionType: string; availability: string }>;
    expect(recs.map((r) => r.actionType)).toEqual(
      expect.arrayContaining([
        'restrict_smtp_sending',
        'policy_hold_outbound',
        'alert_tenant_admins',
      ]),
    );
    expect((detail.detectionReason as { versions: unknown }).versions).toMatchObject({
      rules: 'ato-rules/1',
      scorer: 'ato-score/1',
    });

    const stored = await prisma.atoAccount.findUniqueOrThrow({ where: { id: account.id } });
    expect(stored).toMatchObject({
      riskScore: 60,
      riskLevel: 'high',
      activeIncidentId: incident.id,
    });
    expect(stored.riskExplanation).toMatchObject({ version: 'ato-score/1' });
    const signal = await prisma.atoRiskSignal.findFirstOrThrow({
      where: { accountId: account.id },
    });
    expect(signal).toMatchObject({
      incidentId: incident.id,
      status: 'active',
      weight: 45,
      occurrences: 1,
    });

    const links = await prisma.securityIncidentLink.findMany({
      where: { incidentId: incident.id },
    });
    expect(links.map((l) => l.linkType).sort()).toEqual(['ato_signal', 'message']);
    const scores = await prisma.atoRiskScore.findMany({ where: { accountId: account.id } });
    expect(scores).toHaveLength(1);
    expect(scores[0]).toMatchObject({
      score: 60,
      level: 'high',
      trigger: 'signal',
      previousScore: 0,
    });

    const risk = await outbox(orgA, EventTypes.AtoAccountRiskUpdated);
    expect(risk.map(payloadOf).filter((p) => p.accountPublicId === account.publicId)).toEqual([
      expect.objectContaining({
        score: 60,
        level: 'high',
        previousLevel: 'low',
        trigger: 'signal',
      }),
    ]);
    const created = await outbox(orgA, EventTypes.SecurityIncidentCreated);
    expect(created.map(payloadOf)).toEqual([
      expect.objectContaining({
        incidentPublicId: incident.publicId,
        category: 'account_takeover',
        severity: 'high',
        reasonCodes: ['ato.content.phishing_sent'],
      }),
    ]);
    const alerts = await outbox(orgA, EventTypes.AtoNotificationRequested);
    expect(alerts.map(payloadOf)).toEqual([
      expect.objectContaining({
        kind: 'incident_alert',
        audience: 'tenant',
        severity: 'high',
        refs: { incidentPublicId: incident.publicId, accountPublicId: account.publicId },
      }),
    ]);
  });

  it('a duplicate signal increments occurrences and never raises the score', async () => {
    advance(5 * MIN);
    const p1 = candidate('ato.content.phishing_sent', { subject: 'msg-1' });
    const { recorded, rescore, policy } = await detect(orgA, account, [p1]);
    expect(recorded.created).toHaveLength(0);
    expect(recorded.duplicates).toHaveLength(1);
    expect(recorded.duplicates[0]!.occurrences).toBe(2);
    expect(rescore.result.score).toBe(60);
    expect(rescore.rowWritten).toBe(false);
    expect(policy).toMatchObject({ opened: false, escalated: false });
    expect(policy.incident!.id).toBe(incident.id);
    expect(await prisma.atoRiskScore.count({ where: { accountId: account.id } })).toBe(1);
  });

  it('new evidence escalates severity (never de-escalates) and links within one incident', async () => {
    advance(5 * MIN);
    const { rescore, policy } = await detect(orgA, account, [
      'ato.outbound.volume_spike',
      'ato.correlation.login_then_outbound',
    ]);
    expect(rescore.result.score).toBe(100);
    expect(rescore.result.level).toBe('critical');
    expect(policy).toMatchObject({ opened: false, escalated: true });
    expect(policy.incident).toMatchObject({ id: incident.id, severity: 'critical' });
    const detail = await prisma.atoIncidentDetail.findUniqueOrThrow({
      where: { incidentId: incident.id },
    });
    expect(detail).toMatchObject({ peakRiskScore: 100, signalCount: 3 });
    const recs = (detail.recommendedActions as Array<{ actionType: string }>).map(
      (r) => r.actionType,
    );
    expect(recs).toEqual(expect.arrayContaining(['escalate_investigation', 'notify_soc']));
    const events = await prisma.securityIncidentEvent.findMany({
      where: { incidentId: incident.id },
      orderBy: { id: 'asc' },
    });
    expect(events.map((e) => e.eventType)).toEqual(
      expect.arrayContaining(['created', 'evidence_linked', 'severity_changed']),
    );
    expect(await prisma.securityIncident.count({ where: { subjectRefId: account.id } })).toBe(1);

    // A later lower score never lowers the incident's severity.
    await prisma.atoRiskSignal.updateMany({
      where: { accountId: account.id, ruleCode: { not: 'ato.content.phishing_sent' } },
      data: { status: 'dismissed' },
    });
    advance(MIN);
    const lower = await detect(orgA, account, [
      candidate('ato.access.new_device', { subject: 'dev-1' }),
    ]);
    expect(lower.rescore.result.level).toBe('high');
    expect(lower.policy.incident!.severity).toBe('critical');
    expect(lower.policy.escalated).toBe(false);
  });

  it('runs low-impact automation and leaves recommend-only actions as recommendations', async () => {
    const result = await fx.tx(async (t) => {
      const settings = await store.ensureSettings(t, orgA);
      const locked = (await incidents.lockForUpdate(t, orgA, incident.id))!;
      const detail = await t.atoIncidentDetail.findUniqueOrThrow({
        where: { incidentId: incident.id },
      });
      return store.runAutomation(t, {
        organizationId: orgA,
        accountId: account.id,
        incident: locked,
        recommendations: detail.recommendedActions as never,
        contributors: [
          { code: 'ato.content.phishing_sent', category: 'outbound_content', strength: 'strong' },
          {
            code: 'ato.outbound.volume_spike',
            category: 'outbound_behaviour',
            strength: 'moderate',
          },
        ],
        settings,
        platformOrganization: false,
      });
    });
    const byType = Object.fromEntries(result.map((r) => [r.actionType, r]));
    expect(Object.keys(byType).sort()).toEqual(
      ['alert_tenant_admins', 'escalate_investigation', 'notify_soc'].sort(),
    );
    for (const r of result) {
      expect(r.action).toMatchObject({
        status: 'succeeded',
        authorization: 'low_impact_default',
        requestedByType: 'system',
        requiresApproval: false,
      });
    }
    expect(byType.alert_tenant_admins!.action).toMatchObject({
      providerStatus: 'unconfirmed',
      resultCode: 'queued_for_delivery',
    });
    expect(byType.escalate_investigation!.action).toMatchObject({
      providerStatus: 'applied',
      resultCode: 'escalated',
    });
    const completed = await outbox(orgA, EventTypes.AtoResponseCompleted);
    expect(completed.length).toBe(3);
    const notifications = (await outbox(orgA, EventTypes.AtoNotificationRequested)).map(payloadOf);
    expect(notifications.map((n) => n.audience)).toEqual(
      expect.arrayContaining(['soc', 'platform_soc']),
    );
    // Running again creates nothing new for completed low-impact actions of the same incident.
    expect(await prisma.atoResponseAction.count({ where: { incidentId: incident.id } })).toBe(3);
  });

  it('a medium/high response needs a four-eyes approval and applies a restriction', async () => {
    const target = {
      scope: 'mailbox' as const,
      accountPublicId: account.publicId,
      mailboxSha256: atoMailboxSha256(account.address!),
    };
    const pending = await fx.tx((t) =>
      store.requestResponse(t, {
        organizationId: orgA,
        accountId: account.id,
        incidentId: incident.id,
        actionType: 'restrict_smtp_sending',
        target,
        actor: analyst1,
        reason: 'stop the phishing run',
        authorization: 'manual',
      }),
    );
    expect(pending).toMatchObject({
      status: 'pending_approval',
      requiresApproval: true,
      impact: 'high',
      provider: 'gateway',
    });
    expect(pending.params).toMatchObject({ durationMinutes: 240, mode: 'reject' });
    expect(pending.approvalExpiresAt!.getTime()).toBe(clock.getTime() + 24 * 3_600_000);
    await expectCode(
      fx.tx((t) =>
        store.requestResponse(t, {
          organizationId: orgA,
          accountId: account.id,
          incidentId: incident.id,
          actionType: 'restrict_smtp_sending',
          target,
          actor: analyst2,
          authorization: 'manual',
        }),
      ),
      'ato_response_active',
    );
    const approvals = (await outbox(orgA, EventTypes.AtoNotificationRequested))
      .map(payloadOf)
      .filter((p) => p.kind === 'approval_requested');
    expect(approvals).toHaveLength(1);

    await expectCode(
      fx.tx((t) =>
        store.decideResponse(t, {
          organizationId: orgA,
          actionId: pending.id,
          decision: 'approve',
          actor: { type: 'api_key', id: 'key-public-id' },
        }),
      ),
      'ato_approver_invalid',
    );
    await expectCode(
      fx.tx((t) =>
        store.decideResponse(t, {
          organizationId: orgA,
          actionId: pending.id,
          decision: 'approve',
          actor: analyst1,
        }),
      ),
      'ato_self_approval',
    );
    await expectCode(
      fx.tx((t) =>
        store.decideResponse(t, {
          organizationId: orgB,
          actionId: pending.id,
          decision: 'approve',
          actor: analyst2,
        }),
      ),
      'ato_response_not_found',
    );
    const done = await fx.tx((t) =>
      store.decideResponse(t, {
        organizationId: orgA,
        actionId: pending.id,
        decision: 'approve',
        actor: analyst2,
        reason: 'confirmed phishing',
      }),
    );
    expect(done).toMatchObject({
      status: 'succeeded',
      providerStatus: 'applied',
      resultCode: 'restriction_applied',
      approvedByUserId: analyst2.userId,
    });
    const restriction = await prisma.atoSmtpRestriction.findUniqueOrThrow({
      where: { id: done.restrictionId! },
    });
    expect(restriction).toMatchObject({
      organizationId: orgA,
      kind: 'send_block',
      scope: 'mailbox',
      mailboxSha256: target.mailboxSha256,
      mode: 'reject',
      status: 'active',
      activeMarker: 1,
    });
    expect(restriction.expiresAt.getTime()).toBe(clock.getTime() + 240 * MIN);
    const changed = (await outbox(orgA, EventTypes.AtoRestrictionChanged)).map(payloadOf);
    expect(changed).toEqual([
      expect.objectContaining({
        restrictionId: restriction.id.toString(),
        status: 'active',
        kind: 'send_block',
      }),
    ]);
    expect(JSON.stringify(changed)).not.toContain(account.address!);
    const timeline = await prisma.securityIncidentEvent.findMany({
      where: { incidentId: incident.id, eventType: { startsWith: 'ato.response_' } },
    });
    expect(timeline.map((e) => e.eventType)).toEqual(
      expect.arrayContaining([
        'ato.response_requested',
        'ato.response_approved',
        'ato.response_succeeded',
      ]),
    );
    const audit = await prisma.auditLog.findMany({
      where: { organizationId: orgA, resourceType: 'ato_response', resourceId: done.publicId },
      orderBy: { id: 'asc' },
    });
    expect(audit.map((a) => a.action)).toEqual([
      'ato.response_requested',
      'ato.response_approved',
      'ato.response_succeeded',
    ]);
    expect(audit[2]!.metadata).toMatchObject({ resultCode: 'restriction_applied' });

    // Rollback: users only, lifts in the same transaction.
    await expectCode(
      fx.tx((t) =>
        store.requestRollback(t, {
          organizationId: orgA,
          actionId: done.id,
          actor: { type: 'api_key', id: 'k' },
          reason: 'x',
        }),
      ),
      'ato_approver_invalid',
    );
    const rolled = await fx.tx((t) =>
      store.requestRollback(t, {
        organizationId: orgA,
        actionId: done.id,
        actor: analyst1,
        reason: 'false alarm',
      }),
    );
    expect(rolled.status).toBe('rolled_back');
    expect(
      await prisma.atoSmtpRestriction.findUniqueOrThrow({ where: { id: restriction.id } }),
    ).toMatchObject({
      status: 'lifted',
      liftedByType: 'user',
      activeMarker: null,
    });
    const statuses = (await outbox(orgA, EventTypes.AtoRestrictionChanged)).map(
      (r) => payloadOf(r).status,
    );
    expect(statuses).toEqual(['active', 'lifted']);
    await expectCode(
      fx.tx((t) =>
        store.requestRollback(t, {
          organizationId: orgA,
          actionId: done.id,
          actor: analyst1,
          reason: 'again',
        }),
      ),
      'ato_response_state',
    );
  });

  it('provider actions: unsupported without an integration; requested, pending and confirmed with one', async () => {
    const target = { scope: 'account' as const, accountPublicId: account.publicId };
    const unbound = await fx.tx((t) =>
      store.requestResponse(t, {
        organizationId: orgA,
        accountId: account.id,
        incidentId: incident.id,
        actionType: 'revoke_sessions',
        target,
        actor: analyst1,
        authorization: 'manual',
      }),
    );
    expect(unbound.status).toBe('pending_approval');
    const unsupported = await fx.tx((t) =>
      store.decideResponse(t, {
        organizationId: orgA,
        actionId: unbound.id,
        decision: 'approve',
        actor: analyst2,
      }),
    );
    expect(unsupported).toMatchObject({
      status: 'unsupported',
      providerStatus: 'unsupported',
      resultCode: 'no_provider_integration',
    });

    const withProvider = await fx.tx((t) =>
      store.requestResponse(t, {
        organizationId: orgA,
        accountId: account.id,
        incidentId: incident.id,
        actionType: 'require_mfa',
        target,
        actor: analyst1,
        authorization: 'manual',
        providerKind: 'fake',
      }),
    );
    const approved = await fx.tx((t) =>
      store.decideResponse(t, {
        organizationId: orgA,
        actionId: withProvider.id,
        decision: 'approve',
        actor: analyst2,
      }),
    );
    expect(approved).toMatchObject({ status: 'approved', provider: 'fake' });
    const requested = (await outbox(orgA, EventTypes.AtoResponseRequested)).map(payloadOf);
    expect(requested).toEqual([
      expect.objectContaining({
        actionPublicId: approved.publicId,
        phase: 'execute',
        provider: 'fake',
      }),
    ]);
    const pending = await fx.tx((t) =>
      store.completeProviderAction(t, {
        organizationId: orgA,
        actionId: approved.id,
        phase: 'execute',
        result: { status: 'pending', providerReference: 'fake-ref-1', pollAfterMs: 5000 },
      }),
    );
    expect(pending).toMatchObject({
      status: 'executing',
      providerStatus: 'pending',
      providerReference: 'fake-ref-1',
    });
    expect(pending.nextCheckAt!.getTime()).toBe(clock.getTime() + 5000);
    const confirmed = await fx.tx((t) =>
      store.completeProviderAction(t, {
        organizationId: orgA,
        actionId: approved.id,
        phase: 'execute',
        result: {
          status: 'confirmed',
          providerReference: 'fake-ref-1',
          confirmedAt: clock.toISOString(),
        },
      }),
    );
    expect(confirmed).toMatchObject({
      status: 'succeeded',
      providerStatus: 'confirmed',
      nextCheckAt: null,
    });
    const replay = await fx.tx((t) =>
      store.completeProviderAction(t, {
        organizationId: orgA,
        actionId: approved.id,
        phase: 'execute',
        result: { status: 'failed', code: 'late', retryable: false },
      }),
    );
    expect(replay.status).toBe('succeeded');

    const rb = await fx.tx((t) =>
      store.requestRollback(t, {
        organizationId: orgA,
        actionId: confirmed.id,
        actor: analyst1,
        reason: 'recovered',
      }),
    );
    expect(rb.status).toBe('rollback_requested');
    const retry = await fx.tx((t) =>
      store.completeProviderAction(t, {
        organizationId: orgA,
        actionId: rb.id,
        phase: 'rollback',
        result: { status: 'failed', code: 'throttled', retryable: true },
      }),
    );
    expect(retry).toMatchObject({ status: 'rollback_requested' });
    const failed = await fx.tx((t) =>
      store.completeProviderAction(t, {
        organizationId: orgA,
        actionId: rb.id,
        phase: 'rollback',
        result: { status: 'failed', code: 'throttled', retryable: true },
        final: true,
      }),
    );
    expect(failed).toMatchObject({
      status: 'rollback_failed',
      providerStatus: 'failed',
      resultCode: 'throttled',
    });
    const logs = await prisma.atoResponseActionLog.findMany({
      where: { actionId: rb.id },
      orderBy: { id: 'asc' },
    });
    expect(logs.map((l) => `${l.phase}:${l.outcome}`)).toEqual(
      expect.arrayContaining([
        'execute:pending',
        'confirm:succeeded',
        'rollback:retry_scheduled',
        'rollback:failed',
      ]),
    );
    const failures = (await outbox(orgA, EventTypes.AtoNotificationRequested))
      .map(payloadOf)
      .filter((p) => p.kind === 'response_failed');
    expect(failures).toHaveLength(1);
  });

  it('record_manual_action is attested, never succeeded', async () => {
    const attested = await fx.tx((t) =>
      store.requestResponse(t, {
        organizationId: orgA,
        accountId: account.id,
        incidentId: incident.id,
        actionType: 'record_manual_action',
        target: { scope: 'account', accountPublicId: account.publicId },
        actor: analyst1,
        reason: 'revoked the portal sessions on the Users page',
        authorization: 'manual',
      }),
    );
    expect(attested).toMatchObject({
      status: 'attested',
      providerStatus: 'unconfirmed',
      requiresApproval: false,
    });
  });

  it('refuses targets that do not name the account and cross-tenant incidents', async () => {
    const other = await mailbox(orgA, 'other-target');
    await expectCode(
      fx.tx((t) =>
        store.requestResponse(t, {
          organizationId: orgA,
          accountId: account.id,
          incidentId: incident.id,
          actionType: 'restrict_smtp_sending',
          target: {
            scope: 'mailbox',
            accountPublicId: other.publicId,
            mailboxSha256: 'f'.repeat(64),
          },
          actor: analyst1,
          authorization: 'manual',
        }),
      ),
      'ato_response_invalid',
    );
    await expectCode(
      fx.tx((t) =>
        store.requestResponse(t, {
          organizationId: orgA,
          accountId: other.id,
          incidentId: incident.id,
          actionType: 'alert_tenant_admins',
          target: { scope: 'account', accountPublicId: other.publicId },
          actor: analyst1,
          authorization: 'manual',
        }),
      ),
      'ato_incident_not_found',
    );
  });

  it('overrides: benign caps below medium, a later strong signal contradicts it; compromised floors at 90', async () => {
    const victim2 = await mailbox(orgA, 'override');
    await detect(orgA, victim2, [candidate('ato.account.refresh_token_reuse', { subject: 'o1' })]);
    const benign = await fx.tx((t) =>
      store.setOverride(t, {
        organizationId: orgA,
        accountId: victim2.id,
        verdict: 'benign',
        reason: 'known traveller',
        expiresAt: new Date(clock.getTime() + 7 * 86_400_000),
        actor: analyst1,
      }),
    );
    expect(benign.rescore.result.score).toBe(29);
    expect(benign.rescore.result.override).toMatchObject({ verdict: 'benign', outcome: 'applied' });
    advance(MIN);
    const after = await detect(orgA, victim2, [
      candidate('ato.content.malware_sent', { subject: 'o2' }),
    ]);
    expect(after.rescore.overrideContradicted).toBe(true);
    expect(after.rescore.result.score).toBeGreaterThanOrEqual(60);
    const override = await prisma.atoRiskOverride.findUniqueOrThrow({
      where: { publicId: benign.overridePublicId },
    });
    expect(override.contradictedAt).not.toBeNull();
    expect(
      await prisma.auditLog.count({
        where: { organizationId: orgA, action: 'ato.override_contradicted' },
      }),
    ).toBe(1);
    const active = await prisma.atoAccount.findUniqueOrThrow({ where: { id: victim2.id } });
    expect(active.overrideId).toBeNull();
    const timeline = await prisma.securityIncidentEvent.findMany({
      where: { incidentId: active.activeIncidentId! },
    });
    expect(timeline.map((e) => e.eventType)).toEqual(expect.arrayContaining(['created']));

    const compromised = await fx.tx((t) =>
      store.setOverride(t, {
        organizationId: orgA,
        accountId: victim2.id,
        verdict: 'compromised',
        reason: 'user reported',
        expiresAt: new Date(clock.getTime() + 86_400_000),
        actor: analyst1,
      }),
    );
    expect(compromised.rescore.result.score).toBeGreaterThanOrEqual(90);
    expect(compromised.rescore.result.level).toBe('critical');
    const cleared = await fx.tx((t) =>
      store.clearOverride(t, {
        organizationId: orgA,
        accountId: victim2.id,
        reason: 'done',
        actor: analyst1,
      }),
    );
    expect(cleared!.result.override.outcome).toBe('none');
    await expectCode(
      fx.tx((t) =>
        store.setOverride(t, {
          organizationId: orgA,
          accountId: victim2.id,
          verdict: 'benign',
          reason: 'too long',
          expiresAt: new Date(clock.getTime() + 91 * 86_400_000),
          actor: analyst1,
        }),
      ),
      'ato_override_invalid',
    );
  });

  it('false positive: dismisses signals, adds trusted contexts, rescores, then honours the cooldown', async () => {
    const fpAccount = await mailbox(orgA, 'fp');
    const opened = await detect(orgA, fpAccount, [
      candidate('ato.ti.attack_source_success', { subject: 'fp1' }),
      candidate('ato.access.new_ip_prefix', { subject: 'fp2' }),
    ]);
    expect(opened.policy.opened).toBe(true);
    const fpIncident = opened.policy.incident!;
    await expectCode(
      fx.tx((t) =>
        incidents.transition(t, {
          organizationId: orgA,
          incidentId: fpIncident.id,
          to: 'false_positive',
          actor: analyst1,
          resolutionCode: 'false_positive',
          note: 'office VPN egress',
          feedback: {
            trustedContexts: [{ kind: 'user', value: 'x', expiresInDays: 1, reason: 'r' }],
          },
        }),
      ),
      'incident_feedback_invalid',
    );
    const resolved = await fx.tx((t) =>
      incidents.transition(t, {
        organizationId: orgA,
        incidentId: fpIncident.id,
        to: 'false_positive',
        actor: analyst1,
        resolutionCode: 'false_positive',
        note: 'office VPN egress, verified with the user',
        feedback: {
          trustedContexts: [
            { kind: 'ip_cidr', value: '203.0.113.0/25', expiresInDays: 30, reason: 'office VPN' },
          ],
        },
      }),
    );
    expect(resolved.status).toBe('false_positive');
    const signals = await prisma.atoRiskSignal.findMany({ where: { accountId: fpAccount.id } });
    expect(
      signals.every((s) => s.status === 'dismissed' && s.dismissedByUserId === analyst1.userId),
    ).toBe(true);
    const account = await prisma.atoAccount.findUniqueOrThrow({ where: { id: fpAccount.id } });
    expect(account).toMatchObject({ riskScore: 0, riskLevel: 'low', activeIncidentId: null });
    const contexts = await prisma.atoTrustedContext.findMany({
      where: { accountId: fpAccount.id },
    });
    expect(contexts).toEqual([
      expect.objectContaining({
        kind: 'ip_cidr',
        value: '203.0.113.0/25',
        source: 'false_positive_feedback',
        incidentId: fpIncident.id,
      }),
    ]);
    const lastScore = await prisma.atoRiskScore.findFirstOrThrow({
      where: { accountId: fpAccount.id },
      orderBy: { id: 'desc' },
    });
    expect(lastScore).toMatchObject({ trigger: 'feedback', score: 0 });
    const events = await prisma.securityIncidentEvent.findMany({
      where: { incidentId: fpIncident.id },
    });
    expect(events.map((e) => e.eventType)).toEqual(
      expect.arrayContaining(['status_changed', 'ato.feedback_applied']),
    );

    // Within the cooldown, moderate evidence does not reopen; a strong signal would.
    advance(10 * MIN);
    const moderate = await detect(orgA, fpAccount, [
      candidate('ato.auth.success_after_failures', { subject: 'c1' }),
      candidate('ato.auth.bruteforce', { subject: 'c2' }),
      candidate('ato.geo.impossible_travel', { subject: 'c3' }),
    ]);
    expect(moderate.rescore.result.score).toBeGreaterThanOrEqual(50);
    expect(moderate.policy).toMatchObject({ opened: false, skipped: 'cooldown', incident: null });
    advance(61 * MIN);
    const reopened = await detect(orgA, fpAccount, [
      candidate('ato.access.concurrent_ips', { subject: 'c4' }),
    ]);
    expect(reopened.policy.opened).toBe(true);
    expect(reopened.policy.incident!.id).not.toBe(fpIncident.id);
    expect(
      await prisma.securityIncident.count({
        where: { organizationId: orgA, subjectRefId: fpAccount.id },
      }),
    ).toBe(2);
  });

  it('manual incidents: one active incident per account, foreign accounts look missing', async () => {
    const manualAccount = await mailbox(orgA, 'manual');
    const manual = await fx.tx((t) =>
      store.createManualIncident(t, {
        organizationId: orgA,
        accountPublicId: manualAccount.publicId,
        severity: 'medium',
        note: 'user reported odd sent items',
        actor: analyst1,
      }),
    );
    expect(manual).toMatchObject({
      origin: 'manual',
      severity: 'medium',
      status: 'open',
      createdByType: 'user',
    });
    expect(await prisma.atoIncidentDetail.count({ where: { incidentId: manual.id } })).toBe(1);
    const err = await fx
      .tx((t) =>
        store.createManualIncident(t, {
          organizationId: orgA,
          accountPublicId: manualAccount.publicId,
          severity: 'high',
          actor: analyst1,
        }),
      )
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(IncidentActiveConflictError);
    await expectCode(
      fx.tx((t) =>
        store.createManualIncident(t, {
          organizationId: orgB,
          accountPublicId: manualAccount.publicId,
          severity: 'high',
          actor: analyst1,
        }),
      ),
      'ato_account_not_found',
    );
    const handler = registry.get('account_takeover');
    const detail = await fx.tx((t) => handler.loadDetail(t, manual));
    expect(detail).toMatchObject({
      account: { id: manualAccount.publicId, kind: 'mailbox' },
      riskScoreAtOpen: 0,
    });
    const sections = await fx.tx((t) => handler.reportSections(t, manual));
    expect(sections.map((s) => s.id)).toEqual([
      'ato.detection',
      'ato.signals',
      'ato.context',
      'ato.responses',
    ]);
    expect(
      await fx.tx((t) =>
        handler.resolveSubject(t, orgB, { type: 'ato_account', publicId: manualAccount.publicId }),
      ),
    ).toBeNull();
    expect(
      await fx.tx((t) =>
        handler.resolveSubject(t, orgA, { type: 'ato_account', publicId: manualAccount.publicId }),
      ),
    ).toMatchObject({ refId: manualAccount.id });
    // A terminal resolution clears the account's active incident.
    await fx.tx((t) =>
      incidents.transition(t, {
        organizationId: orgA,
        incidentId: manual.id,
        to: 'resolved',
        actor: analyst2,
        resolutionCode: 'benign_activity',
        note: 'the user sent them on purpose',
      }),
    );
    expect(
      (await prisma.atoAccount.findUniqueOrThrow({ where: { id: manualAccount.id } }))
        .activeIncidentId,
    ).toBeNull();
  });
});

describe('trusted contexts and protection', () => {
  it('validates, renews and removes trusted contexts with audit rows', async () => {
    clock = T0;
    const account = await mailbox(orgA, 'trusted');
    const expiresAt = new Date(clock.getTime() + 30 * 86_400_000);
    const base = {
      organizationId: orgA,
      accountId: account.id,
      reason: 'office',
      expiresAt,
      source: 'analyst' as const,
      actor: analyst1,
    };
    await expectCode(
      fx.tx((t) => store.addTrustedContext(t, { ...base, kind: 'ip_cidr', value: '10.0.0.0/4' })),
      'ato_trusted_context_invalid',
    );
    await expectCode(
      fx.tx((t) => store.addTrustedContext(t, { ...base, kind: 'country', value: 'GBR' })),
      'ato_trusted_context_invalid',
    );
    await expectCode(
      fx.tx((t) =>
        store.addTrustedContext(t, {
          ...base,
          kind: 'asn',
          value: 'AS64501',
          expiresAt: new Date(clock.getTime() + 366 * 86_400_000),
        }),
      ),
      'ato_trusted_context_invalid',
    );
    const a = await fx.tx((t) =>
      store.addTrustedContext(t, { ...base, kind: 'asn', value: 'AS64501' }),
    );
    const b = await fx.tx((t) =>
      store.addTrustedContext(t, { ...base, kind: 'asn', value: '64501' }),
    );
    expect(b.publicId).toBe(a.publicId);
    await fx.tx((t) =>
      store.addTrustedContext(t, { ...base, kind: 'ip_cidr', value: '198.51.100.9/24' }),
    );
    const list = await fx.tx((t) => store.trustedContexts(t, orgA, account.id));
    expect(list.map((c) => `${c.kind}:${c.value}`).sort()).toEqual([
      'asn:64501',
      'ip_cidr:198.51.100.0/24',
    ]);
    await expectCode(
      fx.tx((t) =>
        store.removeTrustedContext(t, {
          organizationId: orgB,
          publicId: a.publicId,
          actor: analyst1,
        }),
      ),
      'ato_trusted_context_not_found',
    );
    await fx.tx((t) =>
      store.removeTrustedContext(t, {
        organizationId: orgA,
        publicId: a.publicId,
        actor: analyst1,
      }),
    );
    expect(
      (await fx.tx((t) => store.trustedContexts(t, orgA, account.id))).map((c) => c.kind),
    ).toEqual(['ip_cidr']);
    const actions = (
      await prisma.auditLog.findMany({
        where: { organizationId: orgA, resourceId: account.publicId },
      })
    ).map((r) => r.action);
    expect(actions.filter((x) => x === 'ato.trusted_context_added')).toHaveLength(3);
    expect(actions).toContain('ato.trusted_context_removed');
  });

  it('protects an account (never automated) and records it', async () => {
    const account = await mailbox(orgA, 'protected');
    const updated = await fx.tx((t) =>
      store.setProtected(t, {
        organizationId: orgA,
        accountId: account.id,
        protected: true,
        reason: 'CEO mailbox',
        actor: analyst1,
      }),
    );
    expect(updated).toMatchObject({
      protected: true,
      protectedReason: 'CEO mailbox',
      protectedByUserId: analyst1.userId,
    });
    expect(
      await prisma.auditLog.count({
        where: {
          organizationId: orgA,
          action: 'ato.account_protected',
          resourceId: account.publicId,
        },
      }),
    ).toBe(1);
  });
});

describe('automation of medium/high actions (D13 guards)', () => {
  let orgE: bigint;
  let settings: LoadedSettings;

  beforeAll(async () => {
    clock = T0;
    orgE = await fx.organization('enforce');
    settings = await fx.tx(async (t) => {
      await store.ensureSettings(t, orgE);
      return store.saveSettings(t, {
        organizationId: orgE,
        settings: {
          mode: 'enforce',
          automation: {
            restrict_smtp_sending: { mode: 'automatic', minLevel: 'high', durationMinutes: 60 },
          },
        },
        expectedRowVersion: 1,
        actor: system,
      });
    });
  });

  async function automate(label: string, options: { protect?: boolean; platform?: boolean } = {}) {
    const account = await mailbox(orgE, label);
    if (options.protect) {
      await fx.tx((t) =>
        store.setProtected(t, {
          organizationId: orgE,
          accountId: account.id,
          protected: true,
          reason: 'vip',
          actor: system,
        }),
      );
    }
    const { policy } = await detect(orgE, account, [
      candidate('ato.content.phishing_sent', { subject: `${label}-1` }),
      candidate('ato.access.new_ip_prefix', { subject: `${label}-2` }),
    ]);
    return fx.tx(async (t) => {
      const s = await store.ensureSettings(t, orgE);
      return store.runAutomation(t, {
        organizationId: orgE,
        accountId: account.id,
        incident: policy.incident!,
        recommendations: policy.recommendations,
        contributors: policy.contributors,
        settings: s,
        platformOrganization: options.platform ?? false,
      });
    });
  }

  it('executes the restriction automatically when every condition holds', async () => {
    expect(settings.settings.automation.restrict_smtp_sending.mode).toBe('automatic');
    const out = await automate('auto');
    const restrict = out.find((o) => o.actionType === 'restrict_smtp_sending')!;
    expect(restrict.guard).toBeNull();
    expect(restrict.action).toMatchObject({
      status: 'succeeded',
      authorization: 'automation_policy',
      requiresApproval: false,
      providerStatus: 'applied',
    });
    expect(restrict.action!.params).toMatchObject({ durationMinutes: 60 });
  });

  it('a protected account gets a pending approval with the guard reason recorded', async () => {
    const out = await automate('vip', { protect: true });
    const restrict = out.find((o) => o.actionType === 'restrict_smtp_sending')!;
    expect(restrict.guard).toBe('account_protected');
    expect(restrict.action).toMatchObject({
      status: 'pending_approval',
      requestedByType: 'system',
    });
    expect(restrict.action!.requestReason).toContain('automation guard: account_protected');
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: {
        organizationId: orgE,
        resourceId: restrict.action!.publicId,
        action: 'ato.response_requested',
      },
    });
    expect(audit.metadata).toMatchObject({ automation: { reason: 'account_protected' } });
    // A system request may be approved by any user.
    const approver = await fx.user(orgE, 'approver');
    const done = await fx.tx((t) =>
      store.decideResponse(t, {
        organizationId: orgE,
        actionId: restrict.action!.id,
        decision: 'approve',
        actor: { type: 'user', id: approver.publicId, userId: approver.id },
      }),
    );
    expect(done.status).toBe('succeeded');
  });

  it('the platform organization is never automated', async () => {
    const out = await automate('platform', { platform: true });
    expect(out.find((o) => o.actionType === 'restrict_smtp_sending')!.guard).toBe(
      'platform_organization',
    );
  });

  it('refuses a restriction beyond the active-restriction limit (failed, response_failed queued)', async () => {
    const limited = new AtoStore({
      now: at,
      incidents,
      config: { ...config, maxActiveRestrictionsPerOrg: 0 },
    });
    const account = await mailbox(orgE, 'limit');
    const action = await fx.tx((t) =>
      limited.requestResponse(t, {
        organizationId: orgE,
        accountId: account.id,
        incidentId: null,
        actionType: 'restrict_smtp_sending',
        target: {
          scope: 'mailbox',
          accountPublicId: account.publicId,
          mailboxSha256: atoMailboxSha256(account.address!),
        },
        actor: system,
        authorization: 'automation_policy',
      }),
    );
    expect(action).toMatchObject({
      status: 'failed',
      providerStatus: 'failed',
      resultCode: 'restriction_limit',
    });
    const failed = (await outbox(orgE, EventTypes.AtoNotificationRequested))
      .map(payloadOf)
      .filter((p) => p.kind === 'response_failed');
    expect(failed).toHaveLength(1);
  });
});

describe('platform-wide sweeps (run on a 2020 clock so they can only match rows of this test)', () => {
  const OLD = new Date('2020-01-01T00:00:00.000Z');

  it('expires pending approvals, active restrictions and purges closed incidents', async () => {
    clock = OLD;
    const orgP = await fx.organization('sweeps');
    const u = await fx.user(orgP, 'requester');
    const requester: IncidentActor = { type: 'user', id: u.publicId, userId: u.id };
    const connectorAccount = await fx.tx((t) =>
      store.ensureAccount(t, {
        organizationId: orgP,
        subject: { kind: 'smtp_connector', connectorId: 777n },
        at: clock,
      }),
    );
    const pending = await fx.tx((t) =>
      store.requestResponse(t, {
        organizationId: orgP,
        accountId: connectorAccount.id,
        incidentId: null,
        actionType: 'block_smtp_auth',
        target: {
          scope: 'connector_ip',
          accountPublicId: connectorAccount.publicId,
          connectorId: '777',
          cidr: '198.51.100.0/24',
        },
        actor: requester,
        authorization: 'manual',
      }),
    );
    expect(pending).toMatchObject({ status: 'pending_approval', impact: 'medium' });
    const applied = await fx.tx((t) =>
      store.requestResponse(t, {
        organizationId: orgP,
        accountId: connectorAccount.id,
        incidentId: null,
        actionType: 'block_smtp_auth',
        target: {
          scope: 'connector',
          accountPublicId: connectorAccount.publicId,
          connectorId: '777',
        },
        params: { durationMinutes: 15, mode: 'reject' },
        actor: system,
        authorization: 'automation_policy',
      }),
    );
    expect(applied.status).toBe('succeeded');
    const restriction = await prisma.atoSmtpRestriction.findUniqueOrThrow({
      where: { id: applied.restrictionId! },
    });
    expect(restriction).toMatchObject({
      kind: 'auth_block',
      scope: 'connector',
      connectorId: 777n,
    });

    const manual = await fx.tx((t) =>
      store.createManualIncident(t, {
        organizationId: orgP,
        accountPublicId: connectorAccount.publicId,
        severity: 'low',
        actor: requester,
      }),
    );
    await fx.tx((t) =>
      incidents.transition(t, {
        organizationId: orgP,
        incidentId: manual.id,
        to: 'resolved',
        actor: requester,
        resolutionCode: 'other',
        note: 'test incident for retention',
      }),
    );

    clock = new Date(OLD.getTime() + 25 * 3_600_000);
    // An approval past its window is refused (the sweeper records the expiry).
    await expectCode(
      fx.tx((t) =>
        store.decideResponse(t, {
          organizationId: orgP,
          actionId: pending.id,
          decision: 'approve',
          actor: analyst2,
        }),
      ),
      'ato_response_expired',
    );
    const expiredApprovals = await fx.tx((t) => store.expireApprovals(t, { limit: 50 }));
    expect(expiredApprovals).toBeGreaterThanOrEqual(1);
    expect(
      (await prisma.atoResponseAction.findUniqueOrThrow({ where: { id: pending.id } })).status,
    ).toBe('expired');
    const expiredRestrictions = await fx.tx((t) => store.expireRestrictions(t, { limit: 50 }));
    expect(expiredRestrictions).toBeGreaterThanOrEqual(1);
    expect(
      await prisma.atoSmtpRestriction.findUniqueOrThrow({ where: { id: restriction.id } }),
    ).toMatchObject({
      status: 'expired',
      activeMarker: null,
    });
    const changed = (await outbox(orgP, EventTypes.AtoRestrictionChanged)).map(
      (r) => payloadOf(r).status,
    );
    expect(changed).toEqual(['active', 'expired']);

    const purged = await fx.tx((t) =>
      store.purgeClosedIncidents(t, { before: new Date(OLD.getTime() + 2 * 3_600_000), limit: 50 }),
    );
    expect(purged).toBe(1);
    expect(await prisma.securityIncident.count({ where: { id: manual.id } })).toBe(0);
    expect(await prisma.atoIncidentDetail.count({ where: { incidentId: manual.id } })).toBe(0);
    expect(await prisma.securityIncidentEvent.count({ where: { incidentId: manual.id } })).toBe(0);
    clock = T0;
  });
});

describe('notifications (D16 throttle windows)', () => {
  it('requests the first notification of a window and only counts the rest; digests once per period', async () => {
    clock = T0;
    const orgN = await fx.organization('notify');
    const input = {
      organizationId: orgN,
      kind: 'incident_alert' as const,
      audience: 'tenant' as const,
      severity: 'high' as const,
      refs: { incidentPublicId: '01890000-0000-7000-8000-0000000000aa' },
      throttle: { kind: 'ato_incident', scope: '-', minutes: 15 },
    };
    const first = await fx.tx((t) => store.requestNotification(t, input));
    const second = await fx.tx((t) => store.requestNotification(t, input));
    expect(first).toMatch(/^[0-9a-f-]{36}$/);
    expect(second).toBeNull();
    advance(15 * MIN);
    await fx.tx((t) => store.requestNotification(t, input));
    const rows = (await outbox(orgN, EventTypes.AtoNotificationRequested)).map(payloadOf);
    expect(rows).toHaveLength(2);
    expect(rows[1]!.counts).toMatchObject({ suppressedBefore: 1 });
    const digest = {
      organizationId: orgN,
      kind: 'digest' as const,
      audience: 'tenant' as const,
      severity: null,
      refs: {},
      throttle: {
        kind: 'ato_digest',
        scope: 'daily',
        minutes: 1440,
        windowStart: new Date('2026-11-17T00:00:00.000Z'),
      },
      counts: { incidents: 2, criticalIncidents: 0, pendingApprovals: 1, restrictedAccounts: 0 },
      digestPeriod: 'daily' as const,
    };
    expect(await fx.tx((t) => store.requestNotification(t, digest))).not.toBeNull();
    expect(await fx.tx((t) => store.requestNotification(t, digest))).toBeNull();
  });
});
