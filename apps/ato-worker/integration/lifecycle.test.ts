import { rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EventTypes } from '@email-gateway/event-contracts';
import { runBreachImport } from '../src/cli/breach-import';
import { CAPABILITIES_KEY } from '../src/maintenance/jobs';
import { Fixtures, ips } from './support/fixtures';
import { Clock, harness, type Harness } from './support/harness';
import { accountOf, codes, configure, deliver, matureAccount } from './support/scenario';

/**
 * Step 8.4 §10.3 lifecycle scenarios on a 2021 clock (platform-wide sweeps only match this suite's
 * rows): (11) risk escalation and decay over time, (12) false-positive handling and analyst
 * override (dismissal, trusted contexts, cooldown, contradiction), learning and monitor modes,
 * the platform organization never automated, incident purge by retention, digests once per
 * period, baseline rebuild, account retirement, the status gauges and the capabilities row, and
 * the breach importer (T4).
 */
const fx = new Fixtures();
const MIN = 60_000;
const HOUR = 3_600_000;
const clock = new Clock(new Date('2021-05-03T09:00:00.000Z')); // a Monday
let h: Harness;
let platform: { id: bigint; domain: string; domainId: bigint };

beforeAll(async () => {
  platform = await fx.organization('lc-platform', { kind: 'platform' });
  h = await harness(fx, { clock, platformOrganizationId: platform.id });
});

afterAll(async () => {
  await h?.close();
  await fx.cleanup();
});

async function listedSuccess(
  orgId: bigint,
  user: { id: bigint; email: string },
  severity: 'high' | 'critical' = 'high',
) {
  const ip = ips.london();
  await fx.indicator('ip', ip, severity);
  clock.advance(MIN);
  await deliver(
    h,
    await fx.login({
      organizationId: orgId,
      userId: user.id,
      email: user.email,
      outcome: 'success',
      ip,
      at: clock.now(),
    }),
  );
  return ip;
}

describe('escalation and decay (scenario 11)', () => {
  it('escalates the incident to critical, then decay lowers the score (history rows, level events)', async () => {
    const org = await fx.organization('decay');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'd', org.domain);
    await listedSuccess(org.id, user);
    let account = (await accountOf(fx, org.id, 'gateway_user', user.id))!;
    expect(account.riskLevel).toBe('high');
    const incident = await fx.prisma.securityIncident.findUniqueOrThrow({
      where: { id: account.activeIncidentId! },
    });
    expect(incident.severity).toBe('high');
    clock.advance(MIN);
    await deliver(
      h,
      await fx.accountChange({
        organizationId: org.id,
        action: 'auth.refresh_token_reused',
        actorPublicId: user.publicId,
        at: clock.now(),
      }),
    );
    account = (await accountOf(fx, org.id, 'gateway_user', user.id))!;
    expect(account.riskLevel).toBe('critical');
    expect(
      (await fx.prisma.securityIncident.findUniqueOrThrow({ where: { id: incident.id } })).severity,
    ).toBe('critical');
    const updated = await fx.prisma.messageOutbox.count({
      where: { organizationId: org.id, eventType: EventTypes.SecurityIncidentUpdated },
    });
    expect(updated).toBeGreaterThan(0);
    // Ten days later the threat-intel and account-change signals have decayed (half-life 3 days).
    clock.advance(10 * 24 * HOUR);
    await h.comps.maintenance.decaySweep();
    const decayed = (await accountOf(fx, org.id, 'gateway_user', user.id))!;
    expect(decayed.riskScore).toBeLessThan(account.riskScore);
    const rows = await fx.prisma.atoRiskScore.findMany({
      where: { organizationId: org.id, accountId: account.id, trigger: 'decay' },
    });
    expect(rows.length).toBe(1);
    const levelEvents = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: org.id, eventType: EventTypes.AtoAccountRiskUpdated },
    });
    expect(levelEvents.some((e) => (e.payload as { trigger: string }).trigger === 'decay')).toBe(
      true,
    );
    // Incidents never de-escalate automatically.
    expect(
      (await fx.prisma.securityIncident.findUniqueOrThrow({ where: { id: incident.id } })).severity,
    ).toBe('critical');
  });
});

describe('false positives and overrides (scenario 12)', () => {
  it('false positive: signals dismissed, trusted context added, cooldown; benign override contradicted', async () => {
    const org = await fx.organization('fp');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'fp', org.domain);
    const ip = await listedSuccess(org.id, user);
    const account = (await accountOf(fx, org.id, 'gateway_user', user.id))!;
    const analyst = await fx.user(org.id, 'analyst', org.domain);
    await h.comps.db.transaction((tx) =>
      h.comps.incidents.transition(tx, {
        organizationId: org.id,
        incidentId: account.activeIncidentId!,
        to: 'false_positive',
        resolutionCode: 'false_positive',
        note: 'The IP is our new office egress, verified.',
        actor: { type: 'user', id: analyst.publicId, userId: analyst.id },
        feedback: {
          trustedContexts: [
            { kind: 'ip_cidr', value: `${ip}/32`, expiresInDays: 30, reason: 'office' },
          ],
          dismissSignals: true,
        },
      }),
    );
    const after = (await accountOf(fx, org.id, 'gateway_user', user.id))!;
    expect(after.activeIncidentId).toBeNull();
    expect(after.riskScore).toBe(0);
    const statuses = await fx.prisma.atoRiskSignal.findMany({
      where: { organizationId: org.id, accountId: account.id },
    });
    expect(statuses.every((s) => s.status === 'dismissed')).toBe(true);
    expect(
      await fx.prisma.atoTrustedContext.count({
        where: { organizationId: org.id, accountId: account.id },
      }),
    ).toBe(1);
    // Within the cooldown a weak/moderate return does not open a new incident.
    clock.advance(10 * MIN);
    for (let i = 0; i < 10; i++) {
      clock.advance(10_000);
      await deliver(
        h,
        await fx.login({
          organizationId: org.id,
          userId: user.id,
          email: user.email,
          outcome: 'failure',
          ip: ips.pune(),
          at: clock.now(),
        }),
      );
    }
    expect((await accountOf(fx, org.id, 'gateway_user', user.id))!.activeIncidentId).toBeNull();
    // A benign override caps the score; a later strong signal contradicts it.
    const expiresAt = new Date(clock.now().getTime() + 24 * HOUR);
    await h.comps.db.transaction((tx) =>
      h.comps.store.setOverride(tx, {
        organizationId: org.id,
        accountId: account.id,
        verdict: 'benign',
        reason: 'travelling executive',
        expiresAt,
        actor: { type: 'user', id: analyst.publicId, userId: analyst.id },
      }),
    );
    await listedSuccess(org.id, user, 'critical');
    const override = await fx.prisma.atoRiskOverride.findFirstOrThrow({
      where: { organizationId: org.id, accountId: account.id },
    });
    expect(override.contradictedAt).not.toBeNull();
    const audit = await fx.prisma.auditLog.count({
      where: { organizationId: org.id, action: 'ato.override_contradicted' },
    });
    expect(audit).toBe(1);
  });
});

describe('modes and guards', () => {
  it('learning period: baseline-relative signals are informational (weight 0, never scored)', async () => {
    const org = await fx.organization('learn');
    await configure(h, org.id, { learningDays: 14 });
    const user = await fx.user(org.id, 'l', org.domain);
    await matureAccount(
      h,
      fx,
      org.id,
      { kind: 'gateway_user', userId: user.id, address: user.email },
      {
        prefix: '192.0.2.0/24',
        country: 'IN',
        asn: 64500,
      },
    );
    clock.advance(MIN);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip: ips.sydney(),
        at: clock.now(),
      }),
    );
    const account = (await accountOf(fx, org.id, 'gateway_user', user.id))!;
    const signals = await fx.prisma.atoRiskSignal.findMany({
      where: { organizationId: org.id, accountId: account.id },
    });
    const relative = signals.filter((s) =>
      ['ato.geo.new_country', 'ato.access.new_ip_prefix', 'ato.access.new_asn'].includes(
        s.ruleCode,
      ),
    );
    expect(relative.length).toBe(3);
    expect(relative.every((s) => s.status === 'informational' && s.weight === 0)).toBe(true);
    expect(account.riskScore).toBe(0);
  });

  it('the platform organization is never acted on automatically (guard), even in enforce mode', async () => {
    await configure(h, platform.id, {
      mode: 'enforce',
      automation: { restrict_smtp_sending: { mode: 'automatic', minLevel: 'high' } },
    });
    const sender = `ops@${platform.domain}`;
    const user = await fx.prisma.user.create({
      data: { organizationId: platform.id, email: sender, displayName: 'ops', status: 'active' },
    });
    await listedSuccess(platform.id, { id: user.id, email: sender }, 'critical');
    const [m] = await fx.messages(platform.id, [
      {
        sender,
        receivedAt: clock.now(),
        recipients: ['v@target.example'],
        verdict: 'malicious',
        reasonCodes: ['url.phishing_high_confidence'],
        domainId: platform.domainId,
      },
    ]);
    const before = await h.metric('ato_automation_guard_total', {
      reason: 'platform_organization',
    });
    await h.comps.mailConsumer.handle(fx.scanned(m!));
    expect(await h.metric('ato_automation_guard_total', { reason: 'platform_organization' })).toBe(
      before + 1,
    );
    const action = await fx.prisma.atoResponseAction.findFirstOrThrow({
      where: { organizationId: platform.id, actionType: 'restrict_smtp_sending' },
    });
    expect(action.status).toBe('pending_approval');
    expect(
      await fx.prisma.atoSmtpRestriction.count({ where: { organizationId: platform.id } }),
    ).toBe(0);
  });
});

describe('maintenance jobs', () => {
  it('baseline rebuild selects accounts after the rebuild hour and matures them from their days', async () => {
    const org = await fx.organization('base');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'b', org.domain);
    for (let d = 0; d < 8; d++) {
      clock.advance(24 * HOUR);
      for (let i = 0; i < 5; i++) {
        clock.advance(MIN);
        await deliver(
          h,
          await fx.login({
            organizationId: org.id,
            userId: user.id,
            email: user.email,
            outcome: 'success',
            ip: ips.mumbai(),
            at: clock.now(),
          }),
        );
      }
    }
    const account = (await accountOf(fx, org.id, 'gateway_user', user.id))!;
    clock.advance(24 * HOUR);
    await h.comps.maintenance.baselineRebuild();
    const baseline = await fx.prisma.atoAccountBaseline.findUniqueOrThrow({
      where: { accountId: account.id },
    });
    expect(baseline).toMatchObject({ mature: true, version: 'ato-baseline/1' });
    expect(baseline.activeDays).toBeGreaterThanOrEqual(7);
    expect((baseline.baseline as { countries: { c: string }[] }).countries.map((c) => c.c)).toEqual(
      ['IN'],
    );
    // Rebuilt today: not selected again before tomorrow's rebuild hour.
    const rebuiltAt = baseline.rebuiltAt;
    await h.comps.maintenance.baselineRebuild();
    expect(
      (await fx.prisma.atoAccountBaseline.findUniqueOrThrow({ where: { accountId: account.id } }))
        .rebuiltAt,
    ).toEqual(rebuiltAt);
  });

  it('digests: daily (and weekly on Mondays) once per period at the local hour', async () => {
    const org = await fx.organization('digest', { timeZone: 'Asia/Kolkata' });
    await configure(h, org.id);
    clock.set(new Date('2021-05-10T03:00:00.000Z')); // Monday 08:30 in Kolkata
    await h.comps.maintenance.digests();
    await h.comps.maintenance.digests();
    const rows = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: org.id, eventType: EventTypes.AtoNotificationRequested },
    });
    const periods = rows.map((r) => (r.payload as { digestPeriod: string }).digestPeriod).sort();
    expect(periods).toEqual(['daily', 'weekly']);
    const daily = rows.find(
      (r) => (r.payload as { digestPeriod: string }).digestPeriod === 'daily',
    )!;
    expect((daily.payload as { window: { from: string; to: string } }).window).toEqual({
      from: '2021-05-08T18:30:00.000Z',
      to: '2021-05-09T18:30:00.000Z',
    });
  });

  it('retention purges closed incidents after ATO_RETENTION_INCIDENT_DAYS; status gauges and resolutions', async () => {
    const org = await fx.organization('purge');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'p', org.domain);
    clock.set(new Date('2021-06-01T09:00:00.000Z'));
    await listedSuccess(org.id, user);
    const account = (await accountOf(fx, org.id, 'gateway_user', user.id))!;
    const incidentId = account.activeIncidentId!;
    await h.comps.maintenance.status(); // initialises the resolution high-water mark
    clock.advance(MIN);
    const analyst = await fx.user(org.id, 'pa', org.domain);
    await h.comps.db.transaction((tx) =>
      h.comps.incidents.transition(tx, {
        organizationId: org.id,
        incidentId,
        to: 'resolved',
        resolutionCode: 'remediated',
        note: 'Password reset and sessions revoked.',
        actor: { type: 'user', id: analyst.publicId, userId: analyst.id },
      }),
    );
    clock.advance(MIN);
    const resolvedBefore = await h.metric('ato_incidents_resolved_total', {
      resolution: 'remediated',
    });
    await h.comps.maintenance.status();
    expect(await h.metric('ato_incidents_resolved_total', { resolution: 'remediated' })).toBe(
      resolvedBefore + 1,
    );
    clock.advance(731 * 24 * HOUR);
    await h.comps.maintenance.retention();
    expect(await fx.prisma.securityIncident.count({ where: { id: incidentId } })).toBe(0);
    expect(await fx.prisma.atoIncidentDetail.count({ where: { incidentId } })).toBe(0);
    const row = await fx.prisma.systemSetting.findUnique({ where: { key: CAPABILITIES_KEY } });
    expect(row?.value).toMatchObject({ geoipCity: { loaded: true }, providers: ['fake'] });
  });

  it('retirement: accounts of deleted users are retired, then deleted without history references', async () => {
    const org = await fx.organization('retire');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'r', org.domain);
    clock.advance(MIN);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'failure',
        ip: ips.pune(),
        at: clock.now(),
      }),
    );
    const account = (await accountOf(fx, org.id, 'gateway_user', user.id))!;
    await fx.prisma.loginAuditLog.deleteMany({ where: { userId: user.id } });
    await fx.prisma.user.delete({ where: { id: user.id } });
    await h.comps.maintenance.retirement();
    expect(await fx.prisma.atoAccount.count({ where: { id: account.id } })).toBe(0);
  });

  it('breach importer: only active tenant domains, counts only, one audit row; T4 on the next event', async () => {
    const org = await fx.organization('breach');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'leaked', org.domain);
    const file = join(tmpdir(), `it-ato-breach-${fx.suffix}.txt`);
    await writeFile(
      file,
      [
        '# operator file',
        user.email.toUpperCase(),
        `someone@not-a-tenant-${fx.suffix}.example`,
        'garbage',
        user.email,
      ].join('\n'),
    );
    // The synthetic operator file is scratch data: removed as soon as the import has read it.
    const counts = await runBreachImport(
      fx.prisma,
      {
        source: `it-ato-${fx.suffix}-breach`,
        file,
        severity: 'medium',
        expiresDays: 30,
      },
      clock.now(),
    ).finally(() => rm(file, { force: true }));
    expect(counts).toEqual({
      read: 4,
      invalid: 1,
      outsideTenantDomains: 1,
      duplicatesInFile: 1,
      imported: 1,
      updated: 0,
    });
    const audit = await fx.prisma.auditLog.findFirstOrThrow({
      where: {
        action: 'threat_intel.breach_imported',
        resourceId: `feed:it-ato-${fx.suffix}-breach`,
      },
    });
    expect(JSON.stringify(audit.metadata)).not.toContain(user.email);
    h.comps.capabilities.breachIndicators = await h.comps.maintenance.breachIndicatorCount(
      clock.now(),
    );
    clock.advance(MIN);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip: ips.mumbai(),
        at: clock.now(),
      }),
    );
    const account = (await accountOf(fx, org.id, 'gateway_user', user.id))!;
    expect(await codes(fx, org.id, account.id)).toContain('ato.ti.breach_listed');
  });
});
