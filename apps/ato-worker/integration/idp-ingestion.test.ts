import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  gsActivity,
  GS_DOMAIN,
  GS_EXTERNAL_DOMAIN,
  GS_IPS,
  GS_USERS,
  googleCustomer,
  microsoftDirectory,
  msConsentAudit,
  msRiskDetection,
  msSignIn,
  MS_DOMAIN,
  MS_EXTERNAL_DOMAIN,
  MS_IPS,
  MS_SERVICE_PRINCIPALS,
  MS_USERS,
} from '@email-gateway/idp-adapters/testing';
import { Fixtures } from './support/fixtures';
import { Clock } from './support/harness';
import { DAY, IdpWorld, MIN, msDirectoryAs } from './support/idp';
import { accountOf, codes, configure } from './support/scenario';

/**
 * Step 8.5 §11.3 ingestion end to end on the real MySQL writer and Redis, with the in-process
 * Graph / Office 365 Management / Google Admin SDK / Gmail simulators and the in-memory 8.2
 * connection port (synthetic directories `contoso-it.example` and `fabrikam-it.example`, synthetic
 * organizations `it-ato-*`, documentation IP ranges with the synthetic GeoIP databases). No real
 * provider endpoint and no Internet address is ever called.
 */
const fx = new Fixtures();
const clock = new Clock(new Date(Math.floor(Date.now() / MIN) * MIN));
const w = new IdpWorld(fx, clock);
/** A second synthetic directory (own tenant and domain) for the backfill replay scenario. */
const BACKFILL_TENANT = '44444444-5555-4666-8777-888888888888';
const BACKFILL_DOMAIN = 'contoso-bf.example';

beforeAll(async () => {
  const now = clock.now();
  const backfillDir = msDirectoryAs(now, BACKFILL_TENANT, BACKFILL_DOMAIN);
  backfillDir.signIns = [];
  await w.start({
    microsoft: [microsoftDirectory(now), backfillDir],
    google: [googleCustomer(now)],
  });
});

afterAll(async () => {
  await w.stop();
  await fx.cleanup();
});

describe('Microsoft Entra ID / Microsoft 365 ingestion (D3, §3.2)', () => {
  it('probes, polls the primaries only, maps identities and feeds the 8.4 rules', async () => {
    const org = await fx.organization('msin');
    await configure(w.h, org.id);
    const connection = w.connect(org.id, 'microsoft_entra');
    const integration = await w.bind(connection);
    // Before the probe nothing is polled (no linked domain is known yet).
    await w.poll(2);
    expect(await fx.prisma.atoAuthEvent.count({ where: { organizationId: org.id } })).toBe(0);
    await w.due();
    await w.probe();
    const probed = await fx.prisma.atoProviderIntegration.findUniqueOrThrow({
      where: { id: integration.id },
    });
    expect(probed.healthStatus).toBe('healthy');
    expect(probed.directoryDomains).toEqual([MS_DOMAIN]);
    expect(probed.displayName).toBe('IT microsoft_entra (example)');
    expect(
      (probed.capabilities as { actions: Record<string, { supported: boolean }> }).actions
        .revoke_sessions?.supported,
    ).toBe(true);

    // A credential-stuffing burst on blake (10 failures), then a risky consent and a high risk.
    const dir = w.sims.script.dataset.microsoft!.directories[0]!;
    const now = clock.now();
    for (let i = 0; i < 10; i++) {
      dir.signIns.push(
        msSignIn(now, {
          minutesAgo: 5,
          userId: MS_USERS.blake,
          userPrincipalName: `blake@${MS_DOMAIN}`,
          ipAddress: MS_IPS.attacker,
          status: { errorCode: 50126 },
          deviceDetail: null,
        }),
      );
    }
    dir.riskDetections.push(msRiskDetection(now, { minutesAgo: 4, riskLevel: 'high' }));
    dir.directoryAudits.push(
      msConsentAudit(now, {
        minutesAgo: 6,
        userKey: 'alex',
        servicePrincipalId: MS_SERVICE_PRINCIPALS.unverified,
        scopes: 'Mail.Read Mail.Send offline_access',
      }),
    );
    // An identity of a domain of the tenant that is not a linked, provider-verified domain of
    // the connection must be dropped (inv. 4), counted `foreign_domain`.
    dir.signIns.push(
      msSignIn(now, {
        minutesAgo: 5,
        userId: 'aaaaaaaa-0000-4000-8000-0000000000ff',
        userPrincipalName: 'zoe@unlinked-it.example',
      }),
    );
    w.sims.script.clearCalls();
    await w.due(integration.id);
    await w.poll();

    // Companions are never polled.
    const companions = await fx.prisma.atoProviderStream.findMany({
      where: { integrationId: integration.id, role: 'companion' },
    });
    expect(companions.length).toBeGreaterThan(0);
    for (const c of companions) expect(c.lastAttemptAt).toBeNull();
    const primaries = await fx.prisma.atoProviderStream.findMany({
      where: { integrationId: integration.id, role: 'primary' },
    });
    for (const p of primaries) {
      expect(p.cursor).not.toBeNull();
      expect(p.lastSuccessAt).not.toBeNull();
      expect(p.consecutiveFailures).toBe(0);
    }

    const blake = await accountOf(fx, org.id, 'mailbox', `blake@${MS_DOMAIN}`);
    expect(blake).not.toBeNull();
    expect(await codes(fx, org.id, blake!.id)).toContain('ato.auth.bruteforce');
    const failures = await fx.prisma.atoAuthEvent.count({
      where: {
        organizationId: org.id,
        accountId: blake!.id,
        source: 'idp_sign_in',
        outcome: 'failure',
      },
    });
    expect(failures).toBeGreaterThanOrEqual(10);

    const alex = await accountOf(fx, org.id, 'mailbox', `alex@${MS_DOMAIN}`);
    const alexCodes = await codes(fx, org.id, alex!.id);
    // R1 (high risk detection), Q1 (consent to an unverified app with mail scopes), M1/M2 (the
    // external forwarding inbox rule and mailbox forwarding from Audit.Exchange), M3 (delegates),
    // then X5 (configuration change after a risky sign-in).
    expect(alexCodes).toEqual(
      expect.arrayContaining([
        'ato.oauth.risky_consent',
        'ato.provider.risk_event',
        'ato.mailbox.external_forwarding',
        'ato.mailbox.suspicious_inbox_rule',
        'ato.mailbox.delegation_added',
      ]),
    );
    const q1 = await fx.prisma.atoRiskSignal.findFirst({
      where: { organizationId: org.id, accountId: alex!.id, ruleCode: 'ato.oauth.risky_consent' },
    });
    expect(q1!.strength).toBe('strong');
    // Q2: the token risk detection (session_events companion of risk_events).
    expect(await codes(fx, org.id)).toContain('ato.oauth.token_anomaly');
    // M4: non-owner (delegate) mailbox access by blake's session on alex's mailbox.
    expect(await codes(fx, org.id)).toContain('ato.mailbox.unusual_access');
    // Mailbox state items: hashes, kinds, target domains and traits only; linked to the account.
    const items = await fx.prisma.atoProviderMailboxItem.findMany({
      where: { integrationId: integration.id, accountId: alex!.id },
    });
    expect(items.map((i) => i.itemKind)).toEqual(
      expect.arrayContaining(['forwarding', 'inbox_rule']),
    );
    expect(items.find((i) => i.itemKind === 'forwarding')?.targetDomain).toBe(MS_EXTERNAL_DOMAIN);
    expect(
      JSON.stringify(items, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)),
    ).not.toContain(`collector@${MS_EXTERNAL_DOMAIN}`);
    // PX1: the structured device label and hash of an Entra sign-in.
    const success = await fx.prisma.atoAuthEvent.findFirst({
      where: { organizationId: org.id, accountId: alex!.id, outcome: 'success' },
    });
    expect(success?.deviceLabel).toMatch(/Edge/);
    expect(success?.deviceHash).toMatch(/^[0-9a-f]{16}$/);
    // Identities carry their integration and primary e-mail domain.
    const identity = await fx.prisma.atoAccountIdentity.findFirst({
      where: { organizationId: org.id, accountId: alex!.id },
    });
    expect(identity).toMatchObject({
      integrationId: integration.id,
      primaryEmailDomain: MS_DOMAIN,
      provider: 'microsoft_entra',
    });
    // The identity of the unlinked domain was not attributed.
    expect(await accountOf(fx, org.id, 'mailbox', 'zoe@unlinked-it.example')).toBeNull();
    expect(
      await w.h.metric('ato_idp_events_total', {
        provider: 'microsoft_entra',
        result: 'foreign_domain',
      }),
    ).toBeGreaterThan(0);

    // A second pass re-reads the overlap and processes nothing twice.
    const before = {
      signals: await fx.prisma.atoRiskSignal.count({ where: { organizationId: org.id } }),
      auth: await fx.prisma.atoAuthEvent.count({ where: { organizationId: org.id } }),
    };
    clock.advance(MIN);
    await w.due(integration.id);
    await w.poll();
    expect(await fx.prisma.atoRiskSignal.count({ where: { organizationId: org.id } })).toBe(
      before.signals,
    );
    expect(await fx.prisma.atoAuthEvent.count({ where: { organizationId: org.id } })).toBe(
      before.auth,
    );
  });
});

describe('Google Workspace ingestion (D3, §3.2)', () => {
  it('login failures and success, suspicious login risk, token authorize, Gmail settings sweep', async () => {
    const org = await fx.organization('gsin');
    await configure(w.h, org.id);
    const connection = w.connect(org.id, 'google_workspace');
    const integration = await w.bind(connection);
    await w.probe();
    const probed = await fx.prisma.atoProviderIntegration.findUniqueOrThrow({
      where: { id: integration.id },
    });
    expect(probed.healthStatus).toBe('healthy');
    expect(probed.directoryDomains).toEqual([GS_DOMAIN]);
    const customer = w.sims.script.dataset.google!.customers[0]!;
    const now = clock.now();
    for (let i = 0; i < 10; i++) {
      customer.activities.push(
        gsActivity(now, {
          application: 'login',
          // Google Reports settle 5 minutes (D7.2): older than that to be read on this poll.
          minutesAgo: 8,
          user: 'blake',
          ip: GS_IPS.attacker,
          events: [
            {
              name: 'login_failure',
              parameters: [{ name: 'login_failure_type', value: 'login_failure_invalid_password' }],
            },
          ],
        }),
      );
    }
    await w.due(integration.id);
    await w.poll();
    const blake = await accountOf(fx, org.id, 'mailbox', `blake@${GS_DOMAIN}`);
    expect(blake).not.toBeNull();
    expect(await codes(fx, org.id, blake!.id)).toContain('ato.auth.bruteforce');
    // Reports `login`: suspicious login (alex) and hijack warning (erin) are risk events (R1);
    // Reports `token` authorize of a full-mail client: Q1.
    const alex = await accountOf(fx, org.id, 'mailbox', `alex@${GS_DOMAIN}`);
    const erin = await accountOf(fx, org.id, 'mailbox', `erin@${GS_DOMAIN}`);
    expect(await codes(fx, org.id, alex!.id)).toEqual(
      expect.arrayContaining(['ato.provider.risk_event', 'ato.oauth.risky_consent']),
    );
    expect(await codes(fx, org.id, erin!.id)).toContain('ato.provider.risk_event');
    // The settings sweep found alex's external forwarding filter and blake's auto-forwarding
    // (state, not "who changed it"): domains and traits only, never the address.
    const items = await fx.prisma.atoProviderMailboxItem.findMany({
      where: { integrationId: integration.id },
    });
    expect(
      items.some((i) => i.targetDomain === GS_EXTERNAL_DOMAIN && i.itemKind === 'forwarding'),
    ).toBe(true);
    expect(items.some((i) => i.itemKind === 'inbox_rule' && i.accountId === alex!.id)).toBe(true);
    expect(items.some((i) => i.itemKind === 'delegate' && i.accountId === erin!.id)).toBe(true);
    // PX3: the first full sweep of a new binding is historical — existing forwarding is recorded
    // as informational signals, no incident.
    const sweepSignals = await fx.prisma.atoRiskSignal.findMany({
      where: {
        organizationId: org.id,
        ruleCode: { in: ['ato.mailbox.external_forwarding', 'ato.mailbox.suspicious_inbox_rule'] },
      },
    });
    expect(sweepSignals.length).toBeGreaterThan(0);
    expect(sweepSignals.every((s) => s.status === 'informational' && s.weight === 0)).toBe(true);
    const forwarding = await fx.prisma.atoProviderStream.findFirstOrThrow({
      where: { integrationId: integration.id, stream: 'forwarding_changes' },
    });
    expect(forwarding.backfillCompletedAt).not.toBeNull();

    // A change after the initial sweep is live: blake's new external filter on the next sweep.
    const blakeGmail = customer.gmail[GS_USERS.blake]!;
    blakeGmail.filters.push({
      id: 'ANe1BmgBlake002',
      criteria: { subject: 'wire transfer' },
      action: { forward: `wire@${GS_EXTERNAL_DOMAIN}`, removeLabelIds: ['INBOX', 'UNREAD'] },
    });
    await fx.prisma.atoAccountIdentity.updateMany({
      where: { organizationId: org.id, accountId: blake!.id },
      data: { mailboxRefreshRequestedAt: clock.now() },
    });
    clock.advance(10 * MIN);
    await w.due(integration.id);
    await w.poll();
    const live = await fx.prisma.atoRiskSignal.findMany({
      where: {
        organizationId: org.id,
        accountId: blake!.id,
        ruleCode: 'ato.mailbox.suspicious_inbox_rule',
        status: 'active',
      },
    });
    expect(live.length).toBe(1);
    // The priority refresh flag is cleared once the page that refreshed it was committed.
    await w.due(integration.id);
    await w.poll();
    const flagged = await fx.prisma.atoAccountIdentity.count({
      where: { organizationId: org.id, mailboxRefreshRequestedAt: { not: null } },
    });
    expect(flagged).toBe(0);
  });
});

describe('backfill over an already ingested range (review fix)', () => {
  it('skips events an earlier ingestion processed, even after the seen-set expired', async () => {
    const org = await fx.organization('msbf');
    await configure(w.h, org.id);
    const dir = w.sims.script.dataset.microsoft!.directories.find(
      (d) => d.tenantId === BACKFILL_TENANT,
    )!;
    const now = clock.now();
    const failure = (key: 'alex' | 'blake', minutesAgo: number) =>
      msSignIn(now, {
        minutesAgo,
        userId: MS_USERS[key],
        userPrincipalName: `${key}@${BACKFILL_DOMAIN}`,
        ipAddress: MS_IPS.attacker,
        status: { errorCode: 50126 },
        deviceDetail: null,
      });
    // Inside the binding's 2-day backfill: a failure and a success one day ago.
    dir.signIns.push(failure('blake', 24 * 60));
    dir.signIns.push(
      msSignIn(now, { minutesAgo: 24 * 60, userPrincipalName: `alex@${BACKFILL_DOMAIN}` }),
    );
    // Older than the binding's backfill, inside the later 5-day one.
    dir.signIns.push(failure('alex', 3 * 24 * 60));

    const connection = w.connect(org.id, 'microsoft_entra', {
      tenantId: BACKFILL_TENANT,
      domain: BACKFILL_DOMAIN,
    });
    const integration = await w.bind(connection, { backfillDays: 2 });
    await w.due(integration.id);
    await w.probe();
    await w.poll();

    const signIns = () =>
      fx.prisma.atoProviderStream.findUniqueOrThrow({
        where: { integrationId_stream: { integrationId: integration.id, stream: 'sign_ins' } },
      });
    const first = await signIns();
    expect(first.status).toBe('active');
    // Completion records the covered range and leaves no replay window.
    expect(first.coveredFrom).toEqual(first.backfillFrom);
    expect(first.replayFrom).toBeNull();
    const totals = async () => {
      const events = await fx.prisma.atoAuthEvent.findMany({
        where: { organizationId: org.id, source: 'idp_sign_in' },
        select: { attemptCount: true },
      });
      const days = await fx.prisma.atoAccountActivityDaily.findMany({
        where: { organizationId: org.id },
        select: { authSuccess: true, authFailure: true },
      });
      return {
        rows: events.length,
        attempts: events.reduce((n, e) => n + e.attemptCount, 0),
        success: days.reduce((n, d) => n + d.authSuccess, 0),
        failure: days.reduce((n, d) => n + d.authFailure, 0),
      };
    };
    const before = await totals();
    expect(before).toEqual({ rows: 2, attempts: 2, success: 1, failure: 1 });

    // Days later the seen-set has expired; an administrator backfills 5 days.
    await w.expireSeen(integration);
    clock.advance(MIN);
    const replayedBefore = await w.h.metric('ato_idp_events_total', {
      provider: 'microsoft_entra',
      result: 'replayed',
    });
    const from = new Date(clock.now().getTime() - 5 * DAY);
    await w.backfill(integration, 'sign_ins', from);
    const requested = await signIns();
    expect(requested.replayFrom).toEqual(first.coveredFrom);
    expect(requested.replayUntil!.getTime()).toBe(first.watermarkAt!.getTime() - 3_600_000);
    await w.due(integration.id);
    await w.poll();

    // Only the 3-day-old failure is new: nothing of the earlier range is counted again.
    expect(await totals()).toEqual({ rows: 3, attempts: 3, success: 1, failure: 2 });
    expect(
      await w.h.metric('ato_idp_events_total', { provider: 'microsoft_entra', result: 'replayed' }),
    ).toBe(replayedBefore + 2);
    const done = await signIns();
    expect(done).toMatchObject({ status: 'active', replayFrom: null, replayUntil: null });
    expect(done.coveredFrom).toEqual(from);
  });
});
