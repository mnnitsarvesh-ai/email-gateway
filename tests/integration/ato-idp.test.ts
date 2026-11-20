/* eslint-disable @typescript-eslint/no-unsafe-return -- predicates over the api's loose JSON */
import { defaultBindingSettings } from '@email-gateway/idp-adapters';
import {
  MS_DOMAIN,
  MS_TENANT_ID,
  MS_USERS,
  microsoftDirectory,
  msSignIn,
} from '@email-gateway/idp-adapters/testing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, idempotencyKey, type ApiSession } from './support/api-client';
import {
  atoOrganization,
  deleteAtoRows,
  purgeAtoQueues,
  requestAndApprove,
  saveAtoSettings,
  settleSettingsCache,
  waitForIncident,
  waitForMailboxAccount,
} from './support/ato';
import { ManagementApi } from './support/broker';
import { compose, waitFor } from './support/compose';
import { stack } from './support/env';
import {
  M365_PERMISSIONS,
  expectStatus,
  fake,
  fakeBaseUrl,
  guid,
  purgeProviderRows,
  runtimeSecret,
  waitForConnection,
  type Json,
} from './support/providers';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady, type SmtpStackGate } from './support/smtp-stack';

/**
 * Step 8.5 identity-provider adapters end to end on the live containers
 * (docs/plan/steps/26-ato-provider-adapters.md §11.5, ADR-0082–0086): a synthetic organization
 * with ATO enabled; its Microsoft 365 connection created through 8.2's api with a customer app
 * secret whose tokens the Compose `provider-fake` issues (mail-flow grant, then the ATO telemetry
 * and response grants, verified by 8.2's integration-worker); the ATO data endpoints served by
 * the TEST-ONLY `idp-simulator` (synthetic directory rewritten to this run's tenant and domain);
 * binding through the api; the ato-worker probing, polling and acting.
 *
 * Scenario: credential-stuffing burst then a successful sign-in from another country, a risky
 * consent and an external forwarding inbox rule → an incident with the mailbox signals;
 * `remove_forwarding_rule` (one mailbox item) and `suspend_account` requested by an analyst and
 * approved by a second MFA user → the simulator receives the writes, the actions end `succeeded`
 * with provider status `confirmed`; the suspension is rolled back; a backfill survives an
 * ato-worker restart without duplicates; simulator throttling shows as stream back-off and
 * `degraded` health; a revoked response permission makes the probe report the action unavailable
 * and a new request `unsupported`. Every organization, connection, integration and the simulator
 * state are removed afterwards. Nothing reaches Microsoft or the Internet.
 */
const simAdmin = () => `http://${stack.host}:${process.env.IDP_SIMULATOR_ADMIN_HOST_PORT ?? 18097}`;
const atoWorkerReady = () =>
  `http://${stack.host}:${process.env.ATO_WORKER_HOST_PORT ?? 3085}/health/ready`;

async function reachable(url: string): Promise<boolean> {
  try {
    return (await fetch(url, { signal: AbortSignal.timeout(3_000) })).ok;
  } catch {
    return false;
  }
}

/**
 * Gate of this suite: no mail is sent, so only the api, the ato-worker, the integration-worker,
 * the provider-fake (with its admin token) and the idp-simulator must run (apps + smtp-test
 * profiles). Missing pieces FAIL the suite; SMTP_STACK_TESTS=skip skips it like the stack suites.
 */
async function idpStackGate(): Promise<SmtpStackGate> {
  if (process.env.SMTP_STACK_TESTS === 'skip') {
    return { skip: true, problem: undefined, adapterHost: '' };
  }
  const problems: string[] = [];
  const checks: Array<[string, string]> = [
    [`http://${stack.host}:${stack.ports.services.api}/health/ready`, 'api'],
    [atoWorkerReady(), 'ato-worker'],
    [
      `http://${stack.host}:${process.env.INTEGRATION_WORKER_HOST_PORT || 3086}/health/ready`,
      'integration-worker',
    ],
    [`${fakeBaseUrl()}/health`, 'provider-fake'],
    [`${simAdmin()}/admin/calls`, 'idp-simulator'],
  ];
  for (const [url, service] of checks) {
    if (!(await reachable(url))) {
      problems.push(
        `${service} is not ready (pnpm --filter @email-gateway/idp-adapters build; docker compose --profile apps --profile smtp-test up -d --wait ${service})`,
      );
    }
  }
  if (!process.env.PROVIDER_FAKE_ADMIN_TOKEN) {
    problems.push('PROVIDER_FAKE_ADMIN_TOKEN is not set in .env (append the 8.2 keys)');
  }
  return {
    skip: false,
    problem: problems.length > 0 ? problems.join('\n') : undefined,
    adapterHost: '',
  };
}

const gate = await idpStackGate();
const fx = new SmtpFixtures();
const mgmt = new ManagementApi();
const vhost = stack.rabbitmqVhost();

async function sim(path: string, body?: unknown): Promise<Response> {
  return fetch(`${simAdmin()}${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

async function simOk(path: string, body: unknown): Promise<void> {
  const res = await sim(path, body);
  if (res.status !== 204) throw new Error(`idp-simulator ${path} answered ${res.status}`);
}

interface SimCall {
  simulator: string;
  method: string;
  path: string;
  status: number;
}

async function simCalls(): Promise<SimCall[]> {
  const res = await sim('/admin/calls');
  return ((await res.json()) as { calls: SimCall[] }).calls;
}

/** Consent of a customer app for one resource of the fake (8.2's R4: per resource). */
async function consentFor(tenantId: string, clientId: string, roles: string[], resource: string) {
  const res = await fetch(`${fakeBaseUrl()}/_fake/m365/consents`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${process.env.PROVIDER_FAKE_ADMIN_TOKEN ?? ''}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ tenantId, clientId, roles, resource }),
  });
  if (res.status !== 204) throw new Error(`provider-fake consent answered ${res.status}`);
}

const TELEMETRY_GRAPH = [
  'AuditLog.Read.All',
  'Directory.Read.All',
  'IdentityRiskEvent.Read.All',
  'User.Read.All',
  'MailboxSettings.Read',
];
const RESPONSE = [
  'User.Read.All',
  'User.RevokeSessions.All',
  'User.EnableDisableAccount.All',
  'User-PasswordProfile.ReadWrite.All',
  'MailboxSettings.ReadWrite',
];
const allRoles = (without: readonly string[] = []) =>
  [...new Set([...M365_PERMISSIONS, ...TELEMETRY_GRAPH, ...RESPONSE])].filter(
    (r) => !without.includes(r),
  );

let org: { id: bigint; slug: string };
let domain: FixtureDomain;
let admin: ApiSession | undefined;
let analyst: ApiSession | undefined;
let reader: ApiSession | undefined;
const tenantId = guid();
const app = { clientId: guid(), secret: runtimeSecret() };
let connectionId = '';
let integrationId = '';
let alexAccount: { id: bigint; publicId: string } | undefined;
let incidentId = '';
const ALEX = MS_USERS.alex;

/** The synthetic directory of `@email-gateway/idp-adapters/testing`, rewritten to this run. */
function directoryNow(now: Date) {
  const json = JSON.stringify(microsoftDirectory(now))
    .split(MS_TENANT_ID)
    .join(tenantId)
    .split(MS_DOMAIN)
    .join(domain.name);
  const dir = JSON.parse(json) as ReturnType<typeof microsoftDirectory>;
  // Credential stuffing on alex from the attacker network, then a success from there (BR).
  for (let i = 0; i < 8; i += 1) {
    dir.signIns.push(
      JSON.parse(
        JSON.stringify(
          msSignIn(now, {
            minutesAgo: 8,
            ipAddress: '203.0.113.30',
            status: { errorCode: 50126, failureReason: 'Invalid username or password.' },
            deviceDetail: null,
            location: { city: 'Elsewhere', countryOrRegion: 'BR' },
          }),
        )
          .split(MS_DOMAIN)
          .join(domain.name),
      ),
    );
  }
  dir.signIns.push(
    JSON.parse(
      JSON.stringify(
        msSignIn(now, {
          minutesAgo: 7,
          ipAddress: '203.0.113.30',
          deviceDetail: null,
          location: { city: 'Elsewhere', countryOrRegion: 'BR' },
        }),
      )
        .split(MS_DOMAIN)
        .join(domain.name),
    ),
  );
  return dir;
}

async function detail(): Promise<Json> {
  const res = await admin!.get(`/ato/providers/${integrationId}`);
  expectStatus(res, 200, 'GET /ato/providers/{id}');
  return res.body as Json;
}

function waitForProvider(what: string, predicate: (d: Json) => boolean, timeoutMs = 240_000) {
  return waitFor(
    `identity provider: ${what}`,
    async () => {
      const d = await detail();
      return predicate(d) ? d : undefined;
    },
    { timeoutMs, intervalMs: 3_000 },
  );
}

function waitForAction(id: string, predicate: (a: Json) => boolean, timeoutMs = 300_000) {
  return waitFor(
    `response ${id}`,
    async () => {
      const res = await admin!.get(`/ato/responses/${id}`);
      return res.status === 200 && predicate(res.body) ? (res.body as Json) : undefined;
    },
    { timeoutMs, intervalMs: 3_000 },
  );
}

/** Triggers a poll of every stream and a probe now (pause → resume, §6 #7/#8). */
async function pollNow(): Promise<void> {
  expectStatus(
    await admin!.post(
      `/ato/providers/${integrationId}/pause`,
      { reason: 'stack test: poll now' },
      idempotencyKey(),
    ),
    200,
    'pause',
  );
  expectStatus(
    await admin!.post(`/ato/providers/${integrationId}/resume`, {}, idempotencyKey()),
    200,
    'resume',
  );
}

async function ensureWorkerRunning(): Promise<void> {
  await waitFor(
    'ato-worker ready',
    async () => {
      try {
        return (await fetch(atoWorkerReady(), { signal: AbortSignal.timeout(2_000) })).ok;
      } catch {
        return false;
      }
    },
    { timeoutMs: 180_000, intervalMs: 2_000 },
  );
}

/** The restarted ato-worker consumes its queues again (the next suites read the consumers). */
async function workerConsuming(): Promise<void> {
  await ensureWorkerRunning();
  await waitFor(
    'ato-worker consumers on the ATO queues',
    async () => {
      for (const queue of ['ato.events', 'ato.mail', 'ato.responses']) {
        if ((await mgmt.queue(vhost, queue)).consumers < 1) return false;
      }
      return true;
    },
    { timeoutMs: 180_000, intervalMs: 2_000 },
  );
}

beforeAll(async () => {
  assertStackReady(gate);
  await ensureWorkerRunning();
  org = await atoOrganization(fx, 'idp');
  domain = await fx.domainNamed(org.id, `it-${fx.suffix}-idp.test`);
  admin = await apiSession(fx.prisma, org, 'organization_admin', { mfa: true });
  analyst = await apiSession(fx.prisma, org, 'security_analyst', { mfa: true });
  reader = await apiSession(fx.prisma, org, 'compliance_auditor');
  await saveAtoSettings(admin, {
    learningDays: 0,
    rules: {
      'ato.auth.bruteforce': { params: { failures: 3, windowMinutes: 15 } },
      'ato.auth.success_after_failures': { params: { failures: 2, windowMinutes: 30 } },
    },
  });
  await settleSettingsCache();

  // The provider side, generated now: tenant, customer app, consents (Graph and Management).
  await fake.addMicrosoftTenant({
    tenantId,
    displayName: `ATO tenant ${fx.suffix}`,
    domains: [{ name: domain.name, isVerified: true, isDefault: true, mxHost: null }],
  });
  await fake.addMicrosoftApp({
    clientId: app.clientId,
    secret: app.secret,
    homeTenantId: tenantId,
    requiredRoles: allRoles(),
  });
  await fake.consent(tenantId, app.clientId, allRoles());
  await consentFor(tenantId, app.clientId, ['ActivityFeed.Read'], 'https://manage.office.com');
  await simOk('/admin/reset', {});
  await simOk('/admin/dataset', { microsoft: { directories: [directoryNow(new Date())] } });
}, 600_000);

afterAll(async () => {
  if (gate.skip) return;
  if (integrationId && admin) {
    await admin
      .delete(`/ato/providers/${integrationId}`, idempotencyKey(), { reason: 'stack test end' })
      .catch(() => undefined);
  }
  await sim('/admin/reset', {}).catch(() => undefined);
  for (const session of [admin, analyst, reader]) await session?.remove();
  const ids = org ? [org.id] : [];
  if (ids.length > 0) {
    await fx.prisma.atoProviderMailboxItem.deleteMany({ where: { organizationId: { in: ids } } });
    await fx.prisma.atoProviderStream.deleteMany({ where: { organizationId: { in: ids } } });
  }
  await deleteAtoRows(fx.prisma, ids);
  await purgeProviderRows(fx.prisma, ids);
  await fx.cleanup();
  await purgeAtoQueues(mgmt, vhost);
  if (ids.length > 0) {
    expect(await fx.prisma.organization.count({ where: { id: { in: ids } } })).toBe(0);
    expect(
      await fx.prisma.atoProviderIntegration.count({ where: { organizationId: { in: ids } } }),
    ).toBe(0);
    expect(
      await fx.prisma.providerConnection.count({ where: { organizationId: { in: ids } } }),
    ).toBe(0);
  }
  await fx.prisma.$disconnect();
}, 600_000);

describe.skipIf(gate.skip)('ATO identity providers stack (step 8.5)', { timeout: 900_000 }, () => {
  it('8.2 connection with mail-flow and ATO grants (customer app, provider-fake tokens)', async () => {
    const created = await admin!.post(
      '/provider-connections',
      { provider: 'microsoft_365', displayName: `EXAMPLE ATO ${fx.suffix}` },
      idempotencyKey(),
    );
    expectStatus(created, 201, 'POST /provider-connections');
    connectionId = (created.body as Json).id as string;
    const credentials = { tenantId, clientId: app.clientId, clientSecret: app.secret };
    for (const profile of ['m365.mail_flow', 'm365.ato_telemetry', 'm365.ato_response']) {
      expectStatus(
        await admin!.post(
          `/provider-connections/${connectionId}/grants`,
          { profile, authMethod: 'customer_app_secret' },
          idempotencyKey(),
        ),
        201,
        `POST …/grants ${profile}`,
      );
      if (profile === 'm365.mail_flow') {
        expectStatus(
          await admin!.put(
            `/provider-connections/${connectionId}/grants/${profile}/credentials`,
            credentials,
            idempotencyKey(),
          ),
          200,
          `PUT …/credentials ${profile}`,
        );
        await waitForConnection(admin!, connectionId, 'mail-flow grant active', (c) =>
          c.grants.some((g: Json) => g.profile === 'm365.mail_flow' && g.status === 'active'),
        );
        expectStatus(
          await admin!.put(
            `/provider-connections/${connectionId}/domains`,
            { domainIds: [domain.publicId] },
            idempotencyKey(),
          ),
          200,
          'PUT …/domains',
        );
        await waitForConnection(
          admin!,
          connectionId,
          'status active',
          (c) => c.status === 'active',
        );
      }
    }
    // The ATO grants are verified on the bound tenant (step 8.5 WP6: no tenant read with the
    // ATO permission sets; ActivityFeed.Read is proven by the ato-worker's probe).
    for (const profile of ['m365.ato_telemetry', 'm365.ato_response']) {
      expectStatus(
        await admin!.put(
          `/provider-connections/${connectionId}/grants/${profile}/credentials`,
          credentials,
          idempotencyKey(),
        ),
        200,
        `PUT …/credentials ${profile}`,
      );
    }
    const ready = await waitForConnection(admin!, connectionId, 'ATO grants active', (c) =>
      ['m365.ato_telemetry', 'm365.ato_response'].every((p) =>
        c.grants.some((g: Json) => g.profile === p && g.status === 'active'),
      ),
    );
    expect(ready.status).toBe('active');
    expect(JSON.stringify(ready)).not.toContain(app.secret);
  });

  it('binds through the api (eligibility, RBAC), probes and polls the simulator', async () => {
    const forbidden = await reader!.post(
      '/ato/providers',
      { connectionId, settings: undefined },
      idempotencyKey(),
    );
    expect(forbidden.status).toBe(403);
    const candidates = await admin!.get('/ato/providers/connections');
    expectStatus(candidates, 200, 'GET /ato/providers/connections');
    const candidate = (candidates.body as Json).data.find((c: Json) => c.id === connectionId);
    expect(candidate).toMatchObject({ eligibility: 'eligible', kind: 'microsoft_entra' });
    expect((await admin!.get('/ato/providers/requirements')).status).toBe(200);
    // Live signals in this scenario: no historical backfill on binding, the fastest polling.
    const settings = { ...defaultBindingSettings(), backfillDays: 0, pollIntervalSeconds: 60 };
    const bound = await admin!.post('/ato/providers', { connectionId, settings }, idempotencyKey());
    expectStatus(bound, 201, 'POST /ato/providers');
    integrationId = (bound.body as Json).id as string;
    expect((bound.body as Json).settings.backfillDays).toBe(0);
    const healthy = await waitForProvider(
      'probed healthy and polled',
      (d) =>
        d.health.status === 'healthy' &&
        d.streamDetails
          .filter((s: Json) => s.role === 'primary')
          .every((s: Json) => s.lastSuccessAt !== null),
    );
    expect(healthy.capabilities.actions).toEqual(
      expect.arrayContaining(['suspend_account', 'remove_forwarding_rule', 'revoke_sessions']),
    );
    expect(healthy.directory.domainCount).toBe(1);
    // Read-only users see it; another organization would answer 404 (api isolation suites).
    expect((await reader!.get(`/ato/providers/${integrationId}`)).status).toBe(200);
    const calls = await simCalls();
    expect(
      calls.some((c) => c.simulator === 'graph' && c.path.startsWith('/v1.0/auditLogs/signIns')),
    ).toBe(true);
    expect(calls.some((c) => c.simulator === 'o365')).toBe(true);
    // The probe and the telemetry streams never write (invariant 7).
    expect(calls.filter((c) => c.method !== 'GET' && c.simulator === 'graph')).toEqual([]);
  });

  it('credential stuffing, a risky sign-in and an external forwarding rule open an incident', async () => {
    const alex = await waitForMailboxAccount(fx.prisma, org.id, `alex@${domain.name}`, 300_000);
    alexAccount = { id: alex.id, publicId: alex.publicId };
    const incident = await waitForIncident(fx.prisma, org.id, alex.id, 300_000);
    incidentId = incident.publicId;
    let lastCodes: string[] = [];
    const signals = await waitFor(
      'provider signals on alex',
      async () => {
        const rows = await fx.prisma.atoRiskSignal.findMany({
          where: { organizationId: org.id, accountId: alex.id },
          select: { ruleCode: true, status: true },
        });
        const codes = rows.map((r) => r.ruleCode);
        lastCodes = codes;
        return codes.includes('ato.mailbox.external_forwarding') &&
          codes.includes('ato.auth.bruteforce')
          ? codes
          : undefined;
      },
      { timeoutMs: 300_000, intervalMs: 3_000 },
    ).catch((error: unknown) => {
      throw new Error(`${String(error)}; codes so far: ${lastCodes.join(', ')}`);
    });
    expect(signals).toEqual(
      expect.arrayContaining([
        'ato.auth.bruteforce',
        'ato.mailbox.external_forwarding',
        'ato.mailbox.suspicious_inbox_rule',
        'ato.oauth.risky_consent',
      ]),
    );
    const state = await admin!.get(`/ato/accounts/${alex.publicId}/mailbox-state`);
    expectStatus(state, 200, 'GET mailbox-state');
    const rule = (state.body as Json).items.find(
      (i: Json) => i.kind === 'inbox_rule' && i.state === 'present' && i.targetDomain !== null,
    );
    expect(rule).toBeDefined();
    // Forwarding targets by domain only; never the address.
    expect(JSON.stringify(state.body)).not.toContain('collector@');
  });

  it('remove_forwarding_rule and suspend_account through approval: confirmed by the provider; rollback', async () => {
    const state = await admin!.get(`/ato/accounts/${alexAccount!.publicId}/mailbox-state`);
    const rule = (state.body as Json).items.find(
      (i: Json) => i.kind === 'inbox_rule' && i.state === 'present' && i.targetDomain !== null,
    );
    const removal = await requestAndApprove(analyst!, admin!, incidentId, {
      actionType: 'remove_forwarding_rule',
      reason: 'Stack test: forwarding rule to an external domain',
      params: { itemId: rule.id },
    });
    const removed = await waitForAction(removal.id, (a) => a.status === 'succeeded');
    expect(removed.providerStatus).toBe('confirmed');
    expect(removed.providerReference).toMatch(/^msgraph:remove_forwarding_rule:/);
    const suspend = await requestAndApprove(analyst!, admin!, incidentId, {
      actionType: 'suspend_account',
      reason: 'Stack test: suspend the compromised account',
    });
    const suspended = await waitForAction(suspend.id, (a) =>
      ['succeeded', 'failed', 'unsupported'].includes(a.status),
    );
    expect(suspended).toMatchObject({ status: 'succeeded', providerStatus: 'confirmed' });
    let calls = await simCalls();
    expect(
      calls.some(
        (c) => c.method === 'PATCH' && c.path.includes('/messageRules/') && c.status < 300,
      ),
    ).toBe(true);
    expect(
      calls.some((c) => c.method === 'PATCH' && c.path === `/v1.0/users/${ALEX}` && c.status < 300),
    ).toBe(true);
    // Roll back the suspension (MFA user): the account is enabled again.
    const before = calls.filter(
      (c) => c.method === 'PATCH' && c.path === `/v1.0/users/${ALEX}`,
    ).length;
    const rolled = await admin!.post(
      `/ato/responses/${suspend.id}/rollback`,
      { reason: 'Stack test: the user was verified by phone' },
      idempotencyKey(),
    );
    expectStatus(rolled, 200, 'rollback');
    await waitForAction(suspend.id, (a) => a.status === 'rolled_back');
    calls = await simCalls();
    expect(
      calls.filter((c) => c.method === 'PATCH' && c.path === `/v1.0/users/${ALEX}`).length,
    ).toBeGreaterThan(before);
  });

  it('a backfill survives an ato-worker restart without duplicates', async () => {
    const counts = async () => ({
      auth: await fx.prisma.atoAuthEvent.count({ where: { organizationId: org.id } }),
      signals: await fx.prisma.atoRiskSignal.findMany({
        where: { organizationId: org.id },
        select: { ruleCode: true, dedupeKey: true },
      }),
    });
    const before = await counts();
    // The first backfill page of the sign-ins is throttled (Retry-After 20 s): the backfill is
    // still running when the worker restarts.
    await simOk('/admin/inject', {
      simulator: 'graph',
      path: '/v1.0/auditLogs/signIns',
      status: 429,
      retryAfter: '20',
      times: 1,
    });
    const from = new Date(Date.now() - 2 * 86_400_000).toISOString();
    const res = await admin!.post(
      `/ato/providers/${integrationId}/backfill`,
      { from },
      idempotencyKey(),
    );
    expectStatus(res, 202, 'POST …/backfill');
    expect((res.body as Json).streams.backfilling).toBeGreaterThan(0);
    await waitForProvider(
      'sign-ins backfill throttled',
      (d) => {
        const signIns = d.streamDetails.find((s: Json) => s.stream === 'sign_ins');
        return signIns.backfill.active && signIns.throttledUntil !== null;
      },
      60_000,
    );
    const restarted = await compose(['restart', 'ato-worker'], { timeoutMs: 180_000 });
    expect(restarted.exitCode).toBe(0);
    await workerConsuming();
    await waitForProvider(
      'backfill completed',
      (d) => d.streamDetails.every((s: Json) => !s.backfill.active),
      600_000,
    );
    const after = await counts();
    expect(after.auth).toBe(before.auth);
    const keys = after.signals.map((s) => `${s.ruleCode}|${s.dedupeKey}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('simulator throttling: stream back-off and degraded health', async () => {
    await simOk('/admin/inject', {
      simulator: 'graph',
      path: '/v1.0/auditLogs/signIns',
      status: 429,
      retryAfter: '120',
      times: 4,
    });
    await pollNow();
    // A throttled page is not a failure: the stream backs off until `throttled_until`
    // (Retry-After 120 s) and the next poll is not before it.
    const throttled = await waitForProvider('sign-ins throttled', (d) => {
      const signIns = d.streamDetails.find((s: Json) => s.stream === 'sign_ins');
      return signIns.throttledUntil !== null;
    });
    const signIns = throttled.streamDetails.find((s: Json) => s.stream === 'sign_ins');
    expect(Date.parse(signIns.throttledUntil)).toBeGreaterThan(Date.now() + 30_000);
    expect(Date.parse(signIns.nextPollAt)).toBeGreaterThanOrEqual(
      Date.parse(signIns.throttledUntil) - 1_000,
    );
    // The probe meets the throttled read too: the integration reports `degraded`.
    const degraded = await waitForProvider('degraded', (d) => d.health.status === 'degraded');
    expect(degraded.healthDetail.status).toBe('degraded');
  });

  it('a revoked response permission: the probe reports the action unavailable; a request ends unsupported', async () => {
    await fake.consent(tenantId, app.clientId, allRoles(['User.EnableDisableAccount.All']));
    expectStatus(
      await admin!.post(
        `/provider-connections/${connectionId}/grants/m365.ato_response/verify`,
        {},
        idempotencyKey(),
      ),
      200,
      'POST …/verify',
    );
    await waitForConnection(admin!, connectionId, 'response grant error', (c) =>
      c.grants.some((g: Json) => g.profile === 'm365.ato_response' && g.status === 'error'),
    );
    expectStatus(
      await admin!.post(`/ato/providers/${integrationId}/health-check`, {}, idempotencyKey()),
      202,
      'health-check',
    );
    const probed = await waitForProvider('suspend unavailable', (d) =>
      d.actions.some((a: Json) => a.action === 'suspend_account' && a.capability !== 'available'),
    );
    expect(probed.capabilities.actions).not.toContain('suspend_account');
    const requested = await requestAndApprove(analyst!, admin!, incidentId, {
      actionType: 'suspend_account',
      reason: 'Stack test: suspend after the revocation',
    });
    const ended = await waitForAction(requested.id, (a) =>
      ['succeeded', 'failed', 'unsupported'].includes(a.status),
    );
    expect(ended.status).toBe('unsupported');
    expect(ended.providerStatus).toBe('unsupported');
    // Never "done" without a confirmation.
    expect(ended.providerStatus).not.toBe('confirmed');
  });
});
