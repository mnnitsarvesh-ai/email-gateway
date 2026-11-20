import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  msAuditBlob,
  msExchangeRecord,
  msSignIn,
  type MsDirectory,
} from '@email-gateway/idp-adapters/testing';
import { Fixtures } from './support/fixtures';
import { Clock } from './support/harness';
import { DAY, IdpWorld, MIN, msDirectoryAs } from './support/idp';
import { configure } from './support/scenario';

/**
 * Step 8.5 §11.3 volume run (laptop baseline, recorded in docs/performance/ato.md): synthetic
 * identity-provider traffic across several integrations (each its own directory and organization)
 * ingested by one in-process `provider` role (`IdpStreamRunner`, claim batch and page sizes of
 * §4.2) on the real MySQL writer and Redis. Defaults: 10 integrations, 100 000 Entra sign-ins
 * (90 % successes, aggregated per account/IP/device/hour) over the last 20 hours and 10 000
 * mailbox items (Exchange `Set-Mailbox` forwarding audits 26–30 hours ago, historical mode).
 * Provider rate budgets are raised for the local simulators (the run measures the worker, not the
 * providers' limits). Scale with IT_ATO_IDP_VOLUME_INTEGRATIONS, IT_ATO_IDP_VOLUME_SIGNINS,
 * IT_ATO_IDP_VOLUME_ITEMS. Prints one `ATO-IDP-PERF {…}` line.
 */
const INTEGRATIONS = Number(process.env.IT_ATO_IDP_VOLUME_INTEGRATIONS ?? 10);
const SIGNINS = Number(process.env.IT_ATO_IDP_VOLUME_SIGNINS ?? 100_000);
const ITEMS = Number(process.env.IT_ATO_IDP_VOLUME_ITEMS ?? 10_000);
const USERS_PER_DIRECTORY = Math.max(10, Math.ceil(ITEMS / INTEGRATIONS));

const fx = new Fixtures();
const clock = new Clock(new Date(Math.floor(Date.now() / MIN) * MIN));
const w = new IdpWorld(fx, clock);

const tenant = (n: number) => `77777777-0000-4000-8000-${n.toString().padStart(12, '0')}`;
const domain = (n: number) => `vol-${n}.example`;
const userId = (n: number, u: number) =>
  `aaaaaaaa-${n.toString(16).padStart(4, '0')}-4000-8000-${u.toString(16).padStart(12, '0')}`;

function directory(n: number, now: Date): MsDirectory {
  const d = msDirectoryAs(now, tenant(n), domain(n));
  d.signIns = [];
  d.riskDetections = [];
  d.directoryAudits = [];
  d.messageRules = {};
  d.oauth2PermissionGrants = [];
  for (let u = 0; u < USERS_PER_DIRECTORY; u++) {
    d.users.push({
      id: userId(n, u),
      userPrincipalName: `u${u}@${domain(n)}`,
      mail: `u${u}@${domain(n)}`,
      displayName: `User ${u}`,
      accountEnabled: true,
      onPremisesSyncEnabled: null,
      proxyAddresses: [`SMTP:u${u}@${domain(n)}`],
    });
  }
  const perDirectory = Math.floor(SIGNINS / INTEGRATIONS);
  for (let i = 0; i < perDirectory; i++) {
    // Sessions of five sign-ins per user (one hour, same IP and device): successes aggregate.
    const u = Math.floor(i / 5) % USERS_PER_DIRECTORY;
    const failure = i % 10 === 9;
    d.signIns.push(
      msSignIn(now, {
        minutesAgo: 30 + Math.floor(((Math.floor(i / 5) * 5) / perDirectory) * 20 * 60),
        userId: userId(n, u),
        userPrincipalName: `u${u}@${domain(n)}`,
        ipAddress: failure ? `203.0.113.${70 + (u % 50)}` : `192.0.2.${2 + (u % 60)}`,
        status: failure ? { errorCode: 50126 } : { errorCode: 0 },
        deviceDetail: failure
          ? null
          : {
              deviceId: `EXAMPLE-device-${n}-${u}`,
              operatingSystem: 'Windows 11',
              browser: 'Edge 120.0',
            },
        riskLevelDuringSignIn: 'none',
      }),
    );
  }
  const perItems = Math.floor(ITEMS / INTEGRATIONS);
  const records = [];
  for (let u = 0; u < perItems; u++) {
    records.push(
      msExchangeRecord(now, {
        minutesAgo: 26 * 60 + (u % 240),
        Operation: 'Set-Mailbox',
        UserId: `admin@${domain(n)}`,
        MailboxOwnerUPN: `u${u % USERS_PER_DIRECTORY}@${domain(n)}`,
        ObjectId: `u${u % USERS_PER_DIRECTORY}@${domain(n)}`,
        Parameters: [
          { Name: 'Identity', Value: `u${u % USERS_PER_DIRECTORY}@${domain(n)}` },
          { Name: 'ForwardingSmtpAddress', Value: `smtp:sink${u}@exfil-${n}.example` },
        ],
      }),
    );
  }
  d.exchange = { subscribed: true, blobs: [] };
  for (let i = 0; i < records.length; i += 200) {
    d.exchange.blobs.push(msAuditBlob(now, records.slice(i, i + 200), { minutesAgo: 26 * 60 - 1 }));
  }
  return d;
}

beforeAll(async () => {
  const now = clock.now();
  await w.start(
    { microsoft: Array.from({ length: INTEGRATIONS }, (_, n) => directory(n + 1, now)) },
    {
      ATO_IDP_RATE_GRAPH_PER_SECOND: '1000',
      ATO_IDP_RATE_O365_PER_SECOND: '1000',
      ATO_IDP_HTTP_TIMEOUT_MS: '60000',
    },
  );
}, 600_000);

afterAll(async () => {
  await w.stop();
  await fx.cleanup();
}, 900_000);

describe('volume (§11.3, laptop baseline)', () => {
  it(`ingests ${SIGNINS} sign-ins and ${ITEMS} mailbox items across ${INTEGRATIONS} integrations`, async () => {
    const integrations = [];
    for (let n = 1; n <= INTEGRATIONS; n++) {
      const org = await fx.organization(`vol${n}`);
      await configure(w.h, org.id);
      const connection = w.connect(org.id, 'microsoft_entra', {
        tenantId: tenant(n),
        domain: domain(n),
      });
      integrations.push(
        await w.bind(connection, {
          backfillDays: 2,
          settings: (s) => ({
            ...s,
            streams: {
              ...s.streams,
              risk_events: { enabled: false },
              session_events: { enabled: false },
              oauth_consents: { enabled: false },
            },
          }),
        }),
      );
    }
    await w.probe();
    const started = Date.now();
    let passes = 0;
    for (;;) {
      passes += 1;
      const more = await w.h.comps.streamRunner!.runOnce();
      if (more) continue;
      const pending = await fx.prisma.atoProviderStream.count({
        where: {
          integrationId: { in: integrations.map((i) => i.id) },
          role: 'primary',
          enabled: true,
          OR: [{ status: 'backfilling' }, { nextPollAt: { lte: clock.now() } }],
        },
      });
      if (pending === 0) break;
      const failing = await fx.prisma.atoProviderStream.findFirst({
        where: {
          integrationId: { in: integrations.map((i) => i.id) },
          consecutiveFailures: { gt: 0 },
        },
      });
      if (failing)
        throw new Error(`stream failed: ${failing.stream} ${failing.lastErrorCode ?? ''}`);
      if (Date.now() - started > 3_600_000) throw new Error('volume run did not finish in 1 h');
    }
    const seconds = (Date.now() - started) / 1000;
    const orgIds = integrations.map((i) => i.organizationId);
    const [authRows, attempts, items, signals, informational, incidents] = await Promise.all([
      fx.prisma.atoAuthEvent.count({ where: { organizationId: { in: orgIds } } }),
      fx.prisma.atoAuthEvent.aggregate({
        where: { organizationId: { in: orgIds } },
        _sum: { attemptCount: true },
      }),
      fx.prisma.atoProviderMailboxItem.count({ where: { organizationId: { in: orgIds } } }),
      fx.prisma.atoRiskSignal.count({ where: { organizationId: { in: orgIds } } }),
      fx.prisma.atoRiskSignal.count({
        where: { organizationId: { in: orgIds }, status: 'informational' },
      }),
      fx.prisma.securityIncident.count({ where: { organizationId: { in: orgIds } } }),
    ]);
    const streams = await fx.prisma.atoProviderStream.findMany({
      where: {
        integrationId: { in: integrations.map((i) => i.id) },
        role: 'primary',
        enabled: true,
      },
    });
    const pages = streams.reduce((n, s) => n + Number(s.pagesTotal), 0);
    const lag = Math.max(
      ...streams
        .filter((s) => s.stream === 'sign_ins')
        .map((s) => (clock.now().getTime() - (s.watermarkAt?.getTime() ?? 0)) / 1000),
    );
    const perf = {
      integrations: INTEGRATIONS,
      signIns: SIGNINS,
      mailboxItemsExpected: ITEMS,
      seconds: Math.round(seconds),
      eventsPerSecond: Math.round((SIGNINS + ITEMS) / seconds),
      passes,
      pages,
      authEventRows: authRows,
      authAttempts: attempts._sum.attemptCount ?? 0,
      mailboxItems: items,
      signals,
      informationalSignals: informational,
      incidents,
      signInLagSecondsAfterRun: Math.round(lag),
    };
    process.stdout.write(`ATO-IDP-PERF ${JSON.stringify(perf)}\n`);
    // Every sign-in counted exactly once (successes aggregated per account/IP/device/hour).
    expect(attempts._sum.attemptCount).toBe(Math.floor(SIGNINS / INTEGRATIONS) * INTEGRATIONS);
    expect(authRows).toBeLessThan(SIGNINS);
    expect(items).toBe(Math.floor(ITEMS / INTEGRATIONS) * INTEGRATIONS);
    // The forwarding audits are older than 24 h: historical, never an incident from them.
    const m1 = await fx.prisma.atoRiskSignal.count({
      where: {
        organizationId: { in: orgIds },
        ruleCode: 'ato.mailbox.external_forwarding',
        status: 'active',
      },
    });
    expect(m1).toBe(0);
    expect(lag).toBeLessThan(DAY / 1000);
  }, 3_700_000);
});
