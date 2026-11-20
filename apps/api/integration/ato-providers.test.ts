/**
 * Identity-provider integrations of step 8.5 (docs/plan/steps/26-ato-provider-adapters.md §6,
 * §11.4) against the real MySQL writer and replica, Redis and step 8.2's connection tables read
 * through the `connection-directory` binding: binding (D4 eligibility, the per-organization limit,
 * already bound, a directory monitored by another organization without disclosure), settings CAS
 * and validation (D10), pause/resume/health-check/backfill/removal effects on the rows, in-flight
 * provider actions ended through the 8.4 store, mailbox state and refresh, the 8.4 settings and
 * account responses with integration data, audit rows, the organization purge and export (§4.1)
 * and the EXPLAIN plans of the list and mailbox-state queries. Synthetic `it-ato-*` organizations
 * only; no provider endpoint is called (the api never calls one).
 */
// @covers get /api/v1/ato/providers
// @covers get /api/v1/ato/providers/requirements
// @covers get /api/v1/ato/providers/connections
// @covers post /api/v1/ato/providers
// @covers get /api/v1/ato/providers/:integrationId
// @covers patch /api/v1/ato/providers/:integrationId
// @covers post /api/v1/ato/providers/:integrationId/pause
// @covers post /api/v1/ato/providers/:integrationId/resume
// @covers post /api/v1/ato/providers/:integrationId/health-check
// @covers post /api/v1/ato/providers/:integrationId/backfill
// @covers delete /api/v1/ato/providers/:integrationId
// @covers get /api/v1/ato/accounts/:accountId/mailbox-state
// @covers post /api/v1/ato/accounts/:accountId/mailbox-state/refresh
import { randomUUID } from 'node:crypto';
import { defaultBindingSettings, directoryRefHash } from '@email-gateway/idp-adapters';
import type { Response, Test } from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { AtoProviderTenantDataRepository } from '../src/modules/tenant-data/ato-provider-tenant-data.repository';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { AtoSeeder, type AtoTenant } from './support/ato';
import { ProviderSeeder, type SeededConnection } from './support/ato-providers';
import { createFixtures, type Fixtures } from './support/fixtures';
import { idem, uniqueIp } from './support/http';

const BASE = '/api/v1/ato';
const P = `${BASE}/providers`;
const DAY = 86_400_000;
const POLL = { timeout: 10_000, interval: 100 };

let ctx: IntegrationApp;
let fx: Fixtures;
let seed: AtoSeeder;
let prov: ProviderSeeder;
let a: AtoTenant;
let b: AtoTenant;
let adminA: Record<string, string>;
let adminB: Record<string, string>;
let connA: SeededConnection;
let integrationA: string;

const json = (value: unknown): string =>
  JSON.stringify(value, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));

function call(
  who: Record<string, string>,
  method: 'get' | 'post' | 'patch' | 'delete',
  path: string,
  body?: object,
  key: string | null = method === 'get' ? null : `it-${randomUUID()}`,
): Test {
  let req = ctx.http[method](path).set(who).set('X-Forwarded-For', uniqueIp());
  if (key) req = req.set(idem(key));
  return body === undefined ? req : req.send(body);
}

/** A replica read that must observe a write just made on the writer. */
async function eventually(make: () => Test, accept: (res: Response) => boolean): Promise<Response> {
  let last: Response | undefined;
  await expect
    .poll(async () => {
      last = await make();
      return accept(last);
    }, POLL)
    .toBe(true);
  return last!;
}

const integrationRow = (publicId: string) =>
  ctx.prisma.atoProviderIntegration.findUniqueOrThrow({ where: { publicId } });
const streamRows = async (publicId: string) => {
  const row = await integrationRow(publicId);
  return ctx.prisma.atoProviderStream.findMany({
    where: { integrationId: row.id },
    orderBy: { id: 'asc' },
  });
};
const auditRows = (organizationId: bigint, action: string) =>
  ctx.prisma.auditLog.findMany({ where: { organizationId, action }, orderBy: { id: 'asc' } });

beforeAll(async () => {
  ctx = await createIntegrationApp({ ATO_IDP_MAX_INTEGRATIONS_PER_ORG: '2' });
  fx = createFixtures(ctx);
  seed = new AtoSeeder(ctx, fx);
  prov = new ProviderSeeder(ctx, fx);
  a = await seed.tenant();
  b = await seed.tenant();
  adminA = await prov.admin(a.org);
  adminB = await prov.admin(b.org);
  connA = await prov.connection(a.org);
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('binding (§6 #1–#5, D4)', () => {
  it('binds an eligible connection: integration and stream rows, audit row, replay', async () => {
    const key = `it-${randomUUID()}`;
    const res = await call(adminA, 'post', P, { connectionId: connA.publicId }, key);
    expect(res.status, json(res.body)).toBe(201);
    integrationA = res.body.id;
    const replay = await call(adminA, 'post', P, { connectionId: connA.publicId }, key);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body.id).toBe(integrationA);
    const row = await integrationRow(integrationA);
    expect(row).toMatchObject({
      organizationId: a.org.id,
      provider: 'microsoft_entra',
      connectorRef: connA.publicId,
      status: 'active',
      activeMarker: 1,
      healthStatus: 'unknown',
      directoryRefHash: directoryRefHash('microsoft_entra', connA.tenantId),
      directoryDomains: [connA.domain],
      settingsVersion: 1,
      rowVersion: 1,
    });
    expect(row.nextHealthAt).not.toBeNull();
    expect(row.grantedPermissions).toContain('AuditLog.Read.All');
    const streams = await streamRows(integrationA);
    expect(streams).toHaveLength(7);
    const byName = Object.fromEntries(streams.map((s) => [s.stream, s]));
    expect(byName.sign_ins).toMatchObject({
      role: 'primary',
      status: 'backfilling',
      enabled: true,
    });
    expect(byName.sign_ins!.cursor).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Date.now() - byName.mailbox_audit!.backfillFrom!.getTime()).toBeLessThan(7.01 * DAY);
    expect(byName.forwarding_changes).toMatchObject({ role: 'companion', status: 'active' });
    const audits = await auditRows(a.org.id, 'ato.provider.bound');
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({ resourceId: integrationA, actorType: 'user' });
    expect(audits[0]!.metadata).toMatchObject({
      provider: 'microsoft_entra',
      connectionId: connA.publicId,
    });
  });

  it('lists the integration, its detail and the connections with their eligibility', async () => {
    const list = await eventually(
      () => call(a.analystAuth, 'get', P),
      (r) => r.status === 200 && r.body.data.length === 1,
    );
    expect(list.body).toMatchObject({ featureEnabled: true, limit: { max: 2, used: 1 } });
    expect(list.body.data[0]).toMatchObject({
      id: integrationA,
      connection: { id: connA.publicId, status: 'active' },
      streams: { enabled: 4, backfilling: 4 },
    });
    const detail = await call(a.analystAuth, 'get', `${P}/${integrationA}`);
    expect(detail.status).toBe(200);
    expect(detail.body.permissions.profiles[0]).toMatchObject({
      profile: 'm365.ato_telemetry',
      grant: { status: 'active', missing: [] },
      notObservable: ['ActivityFeed.Read'],
    });
    const free = await prov.connection(a.org, { grant: 'verifying' });
    const connections = await eventually(
      () => call(adminA, 'get', `${P}/connections`),
      (r) => r.status === 200 && r.body.data.length === 2,
    );
    const byId = new Map(
      (connections.body.data as Array<{ id: string }>).map((c) => [c.id, c as object]),
    );
    expect(byId.get(connA.publicId)).toMatchObject({
      eligibility: 'already_bound',
      integrationId: integrationA,
    });
    expect(byId.get(free.publicId)).toMatchObject({
      eligibility: 'inactive',
      reasons: ['telemetry_grant_inactive'],
    });
    // `ato:read` sees the requirements but not the connections (ato:configure).
    expect((await call(a.analystAuth, 'get', `${P}/requirements`)).status).toBe(200);
    expect((await call(a.auditorAuth, 'get', `${P}/connections`)).status).toBe(403);
  });

  it('refuses unknown, foreign, ineligible and already bound connections and the third integration', async () => {
    const unknown = await call(adminA, 'post', P, { connectionId: randomUUID() });
    expect(unknown.body.code).toBe('ato_provider_connection_not_found');
    const foreign = await prov.connection(b.org);
    const crossed = await call(adminA, 'post', P, { connectionId: foreign.publicId });
    expect(crossed.status).toBe(404);
    expect(crossed.body.code).toBe('ato_provider_connection_not_found');
    const configuring = await prov.connection(a.org, { status: 'configuring', grant: null });
    const ineligible = await call(adminA, 'post', P, { connectionId: configuring.publicId });
    expect(ineligible.status).toBe(409);
    expect(ineligible.body).toMatchObject({
      code: 'ato_provider_connection_ineligible',
      reasons: [{ reason: 'connection_inactive' }, { reason: 'telemetry_grant_missing' }],
    });
    const bound = await call(adminA, 'post', P, { connectionId: connA.publicId });
    expect(bound.body).toMatchObject({
      code: 'ato_provider_already_bound',
      integrationId: integrationA,
    });
    const second = await prov.connection(a.org, { provider: 'google_workspace' });
    const ok = await call(adminA, 'post', P, {
      connectionId: second.publicId,
      settings: { ...defaultBindingSettings(), backfillDays: 0 },
    });
    expect(ok.status, json(ok.body)).toBe(201);
    expect(ok.body.provider).toBe('google_workspace');
    const sessionEvents = (ok.body.streamDetails as Array<{ stream: string }>).find(
      (s) => s.stream === 'session_events',
    );
    expect(sessionEvents).toMatchObject({ role: 'unsupported', status: 'unsupported' });
    const third = await prov.connection(a.org);
    const limited = await call(adminA, 'post', P, { connectionId: third.publicId });
    expect(limited.status).toBe(409);
    expect(limited.body).toMatchObject({ code: 'ato_provider_limit_reached', limit: 2 });
    // Free the slot for the later tests.
    const removed = await call(adminA, 'delete', `${P}/${ok.body.id}`, { reason: 'Limit test' });
    expect(removed.status).toBe(200);
  });

  it('refuses a directory still monitored by another organization without naming it', async () => {
    // Organization B connects the same provider tenant (A's binding is still active).
    const sameTenant = await prov.connection(b.org, { tenantId: connA.tenantId });
    const res = await call(adminB, 'post', P, { connectionId: sameTenant.publicId });
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('ato_provider_directory_in_use');
    const text = json(res.body);
    expect(text).not.toContain(integrationA);
    expect(text).not.toContain(a.org.publicId);
    expect(text).not.toContain(connA.publicId);
    expect(
      await ctx.prisma.atoProviderIntegration.count({ where: { organizationId: b.org.id } }),
    ).toBe(0);
  });
});

describe('settings, pause, resume, probe, backfill (§6 #6–#10, D8.1, D10)', () => {
  it('PATCH: CAS on rowVersion, whole-document validation, stream flags and the audited paths', async () => {
    const stale = await call(adminA, 'patch', `${P}/${integrationA}`, {
      rowVersion: 9,
      settings: defaultBindingSettings(),
    });
    expect(stale.status).toBe(409);
    expect(stale.body).toMatchObject({ code: 'ato_provider_conflict', currentRowVersion: 1 });
    const invalid = defaultBindingSettings();
    invalid.mfaEnforcement.orgUnitPath = '/Secure';
    const refused = await call(adminA, 'patch', `${P}/${integrationA}`, {
      rowVersion: 1,
      settings: invalid,
    });
    expect(refused.status).toBe(400);
    expect(refused.body.issues).toEqual([
      { path: 'mfaEnforcement.orgUnitPath', message: 'not_for_provider' },
    ]);
    const next = defaultBindingSettings();
    next.streams.oauth_consents.enabled = false;
    next.mfaEnforcement.groupId = '11111111-2222-4333-8444-555555555555';
    const ok = await call(adminA, 'patch', `${P}/${integrationA}`, {
      rowVersion: 1,
      settings: next,
    });
    expect(ok.status, json(ok.body)).toBe(200);
    const row = await integrationRow(integrationA);
    expect(row).toMatchObject({ rowVersion: 2, settingsVersion: 2 });
    expect(row.settings).toMatchObject({
      mfaEnforcement: { groupId: next.mfaEnforcement.groupId },
    });
    const consents = (await streamRows(integrationA)).find((s) => s.stream === 'oauth_consents');
    expect(consents?.enabled).toBe(false);
    const audits = await auditRows(a.org.id, 'ato.provider.updated');
    expect(audits.at(-1)!.metadata).toMatchObject({
      changedPaths: ['mfaEnforcement.groupId', 'streams.oauth_consents.enabled'],
    });
    // Values never reach the audit row.
    expect(json(audits.at(-1))).not.toContain('11111111-2222');
  });

  it('pause and resume change the row; resume needs an active connection; the probe request keeps the version', async () => {
    const paused = await call(adminA, 'post', `${P}/${integrationA}/pause`, {
      reason: 'Maintenance window',
    });
    expect(paused.status).toBe(200);
    expect(await integrationRow(integrationA)).toMatchObject({
      status: 'paused',
      pausedReason: 'user',
      rowVersion: 3,
    });
    await ctx.prisma.providerConnectionGrant.updateMany({
      where: { connectionId: connA.id },
      data: { status: 'error' },
    });
    const inactive = await call(adminA, 'post', `${P}/${integrationA}/resume`);
    expect(inactive.status).toBe(409);
    expect(inactive.body.code).toBe('ato_provider_connection_inactive');
    await ctx.prisma.providerConnectionGrant.updateMany({
      where: { connectionId: connA.id },
      data: { status: 'active' },
    });
    const resumed = await call(adminA, 'post', `${P}/${integrationA}/resume`);
    expect(resumed.status).toBe(200);
    expect(await integrationRow(integrationA)).toMatchObject({
      status: 'active',
      pausedReason: null,
      rowVersion: 4,
    });
    await ctx.prisma.atoProviderIntegration.update({
      where: { publicId: integrationA },
      data: { nextHealthAt: new Date(Date.now() + 3_600_000) },
    });
    const probe = await call(a.apiKey, 'post', `${P}/${integrationA}/health-check`);
    expect(probe.status).toBe(202);
    const row = await integrationRow(integrationA);
    expect(row.nextHealthAt!.getTime()).toBeLessThanOrEqual(Date.now());
    expect(row.rowVersion).toBe(4);
    expect(await auditRows(a.org.id, 'ato.provider.health_check_requested')).toHaveLength(1);
    expect((await auditRows(a.org.id, 'ato.provider.paused'))[0]!.metadata).toMatchObject({
      reason: 'Maintenance window',
    });
  });

  it('backfill rewinds the enabled primaries within the provider retention; one at a time; bounded', async () => {
    // The initial backfill is still marked running (the worker never ran here).
    const running = await call(adminA, 'post', `${P}/${integrationA}/backfill`, {
      from: new Date(Date.now() - 3 * DAY).toISOString(),
    });
    expect(running.status).toBe(409);
    expect(running.body.code).toBe('ato_provider_backfill_active');
    // What the worker writes when the backfill reached `now − settle`.
    const row = await integrationRow(integrationA);
    const coveredFrom = new Date(Date.now() - 2 * DAY);
    const watermark = new Date(Date.now() - 5 * 60_000);
    await ctx.prisma.atoProviderStream.updateMany({
      where: { integrationId: row.id, status: 'backfilling' },
      data: {
        status: 'active',
        backfillCompletedAt: new Date(),
        cursorSeq: 12n,
        coveredFrom,
        watermarkAt: watermark,
      },
    });
    const ok = await call(adminA, 'post', `${P}/${integrationA}/backfill`, {
      from: new Date(Date.now() - 20 * DAY).toISOString(),
    });
    expect(ok.status, json(ok.body)).toBe(202);
    const streams = Object.fromEntries((await streamRows(integrationA)).map((s) => [s.stream, s]));
    // oauth_consents was disabled by the PATCH above.
    expect(streams.oauth_consents!.status).toBe('active');
    expect(streams.sign_ins).toMatchObject({ status: 'backfilling', backfillCompletedAt: null });
    expect(Date.now() - streams.sign_ins!.backfillFrom!.getTime()).toBeGreaterThan(19.9 * DAY);
    expect(Date.now() - streams.mailbox_audit!.backfillFrom!.getTime()).toBeLessThan(7.01 * DAY);
    expect(streams.sign_ins!.rowVersion).toBeGreaterThan(1);
    // What the stream already ingested is replayed (skipped) by the runner (review fix).
    expect(streams.sign_ins).toMatchObject({
      replayFrom: coveredFrom,
      replayUntil: new Date(watermark.getTime() - 3_600_000),
    });
    for (const [body, reason] of [
      [{ from: new Date(Date.now() - 31 * DAY).toISOString() }, 'range'],
      [
        { from: new Date(Date.now() - DAY).toISOString(), streams: ['delegation_changes'] },
        'stream_not_backfillable',
      ],
      [
        { from: new Date(Date.now() - DAY).toISOString(), streams: ['oauth_consents'] },
        'stream_disabled',
      ],
    ] as const) {
      const res = await call(adminA, 'post', `${P}/${integrationA}/backfill`, body);
      expect(res.status, reason).toBe(422);
      expect(res.body).toMatchObject({ code: 'ato_provider_backfill_range_invalid', reason });
    }
    expect(
      (await auditRows(a.org.id, 'ato.provider.backfill_requested'))[0]!.metadata,
    ).toMatchObject({
      streams: ['sign_ins', 'risk_events', 'mailbox_audit'],
      days: 20,
    });
  });
});

describe('mailbox state and the 8.4 responses (§6 #12–#13)', () => {
  it('shows present and recently removed items, identities and the last sweep; refresh flags the identity', async () => {
    const account = await seed.mailbox(a.org.id);
    const row = await integrationRow(integrationA);
    await prov.identity(account, row);
    await prov.item(account, row);
    await prov.item(account, row, {
      kind: 'forwarding',
      state: 'removed',
      removedAt: new Date(Date.now() - 2 * DAY),
    });
    await prov.item(account, row, {
      kind: 'delegate',
      state: 'removed',
      removedAt: new Date(Date.now() - 45 * DAY),
    });
    // Before a probe proved the mailbox stream, a refresh is unavailable.
    const early = await call(
      a.analystAuth,
      'post',
      `${BASE}/accounts/${account.publicId}/mailbox-state/refresh`,
    );
    expect(early.status).toBe(409);
    expect(early.body.code).toBe('ato_provider_refresh_unavailable');
    await prov.probed(integrationA);
    const state = await eventually(
      () => call(a.analystAuth, 'get', `${BASE}/accounts/${account.publicId}/mailbox-state`),
      (r) =>
        r.status === 200 &&
        (r.body as { items: unknown[] }).items.length === 2 &&
        (r.body as { identities: Array<{ refreshSupported: boolean }> }).identities[0]
          ?.refreshSupported === true,
    );
    expect(state.body.items.map((i: { kind: string }) => i.kind).sort()).toEqual([
      'forwarding',
      'inbox_rule',
    ]);
    expect(state.body.items[0]).toMatchObject({
      integrationId: integrationA,
      targetDomain: 'external-example.net',
    });
    expect(json(state.body.items)).not.toContain('EXAMPLE-rule-id');
    const refresh = await call(
      a.apiKey,
      'post',
      `${BASE}/accounts/${account.publicId}/mailbox-state/refresh`,
    );
    expect(refresh.status, json(refresh.body)).toBe(202);
    expect(refresh.body).toMatchObject({ identities: 1, integrationIds: [integrationA] });
    const identity = await ctx.prisma.atoAccountIdentity.findFirstOrThrow({
      where: { accountId: account.id },
    });
    expect(identity.mailboxRefreshRequestedAt).not.toBeNull();
    expect(await auditRows(a.org.id, 'ato.mailbox_state.refresh_requested')).toHaveLength(1);
    // 8.4 account detail and settings carry the integration.
    const detail = await eventually(
      () => call(a.analystAuth, 'get', `${BASE}/accounts/${account.publicId}`),
      (r) => r.status === 200 && r.body.identities.length === 1,
    );
    expect(detail.body.identities[0]).toMatchObject({
      integrationId: integrationA,
      directoryStatus: 'active',
    });
    const settings = await eventually(
      () => call(a.analystAuth, 'get', `${BASE}/settings`),
      (r) => r.body.identityProviders?.[0]?.integrations?.[0]?.health === 'healthy',
    );
    expect(settings.body.identityProviders).toEqual([
      {
        provider: 'microsoft_entra',
        integrations: [{ id: integrationA, provider: 'microsoft_entra', health: 'healthy' }],
      },
      { provider: 'google_workspace', integrations: [] },
    ]);
  });
});

describe('removal (§6 #11)', () => {
  it('disables the integration and ends its in-flight provider actions through the 8.4 store; rebinding revives it', async () => {
    const account = await seed.mailbox(a.org.id);
    const row = await integrationRow(integrationA);
    const action = await prov.inFlightAction(account, row);
    const res = await call(adminA, 'delete', `${P}/${integrationA}`, { reason: 'Customer moved' });
    expect(res.status, json(res.body)).toBe(200);
    expect(await integrationRow(integrationA)).toMatchObject({
      status: 'disabled',
      disabledReason: 'user',
      activeMarker: null,
    });
    const ended = await ctx.prisma.atoResponseAction.findUniqueOrThrow({
      where: { id: action.id },
    });
    expect(ended).toMatchObject({
      status: 'failed',
      providerStatus: 'failed',
      resultCode: 'integration_disabled',
    });
    const logs = await ctx.prisma.atoResponseActionLog.findMany({ where: { actionId: action.id } });
    expect(logs.map((l) => l.errorCode)).toContain('integration_disabled');
    const unbound = async () =>
      (await auditRows(a.org.id, 'ato.provider.unbound')).filter(
        (r) => r.resourceId === integrationA,
      );
    expect((await unbound())[0]!.metadata).toMatchObject({
      endedActions: 1,
      connectionId: connA.publicId,
    });
    const again = await call(adminA, 'delete', `${P}/${integrationA}`, { reason: 'Again' });
    expect(again.status).toBe(200);
    expect(await unbound()).toHaveLength(1);
    // What the earlier binding had ingested before it was removed.
    const coveredFrom = new Date(Date.now() - 3 * DAY);
    const watermark = new Date(Date.now() - 10 * 60_000);
    await ctx.prisma.atoProviderStream.updateMany({
      where: { integrationId: row.id, stream: 'sign_ins' },
      data: {
        status: 'active',
        coveredFrom,
        watermarkAt: watermark,
        replayFrom: null,
        replayUntil: null,
      },
    });
    // The directory is free again: binding the same connection revives the row.
    const rebound = await call(adminA, 'post', P, { connectionId: connA.publicId });
    expect(rebound.status, json(rebound.body)).toBe(201);
    expect(rebound.body).toMatchObject({ id: integrationA, status: 'active' });
    expect((await integrationRow(integrationA)).activeMarker).toBe(1);
    // Its default 7-day backfill skips what the earlier stream rows had ingested (review fix).
    const revived = Object.fromEntries((await streamRows(integrationA)).map((s) => [s.stream, s]));
    expect(revived.sign_ins).toMatchObject({
      status: 'backfilling',
      replayFrom: coveredFrom,
      replayUntil: new Date(watermark.getTime() - 3_600_000),
      coveredFrom: null,
    });
    // A live (not backfilled) stream covers provider time from the binding on.
    expect(revived.forwarding_changes!.coveredFrom).not.toBeNull();
  });
});

describe('query plans (EXPLAIN)', () => {
  it('the list, the mailbox-state reads and the directory key use their indexes', async () => {
    const o = a.org.id.toString();
    const row = await integrationRow(integrationA);
    const account = await seed.mailbox(a.org.id);
    // EXPLAIN columns by position (id, select_type, table, partitions, type, possible_keys, key,
    // key_len, ref, rows, filtered, Extra), as the step 8.4 suite reads them.
    const explain = async (sql: string) => {
      const rows = await ctx.prisma.$queryRawUnsafe<Array<Record<string, unknown>>>(
        `EXPLAIN ${sql}`,
      );
      return rows.map((r) => {
        const v = Object.values(r);
        return {
          type: String((v[4] as string | null) ?? ''),
          key: String((v[6] as string | null) ?? ''),
          extra: String((v[11] as string | null) ?? ''),
        };
      });
    };
    const plans = {
      list: await explain(
        `SELECT id FROM ato_provider_integrations WHERE organization_id = ${o} AND status IN ('active','paused','error') ORDER BY id LIMIT 100`,
      ),
      streams: await explain(
        `SELECT id FROM ato_provider_streams WHERE organization_id = ${o} AND integration_id IN (${row.id}) ORDER BY integration_id, id LIMIT 7`,
      ),
      mailboxPresent: await explain(
        `SELECT id FROM ato_provider_mailbox_items WHERE organization_id = ${o} AND account_id = ${account.id} AND state = 'present' ORDER BY item_kind, id DESC LIMIT 501`,
      ),
      mailboxRemoved: await explain(
        `SELECT id FROM ato_provider_mailbox_items WHERE organization_id = ${o} AND account_id = ${account.id} AND state = 'removed' AND removed_at >= NOW(3) - INTERVAL 30 DAY ORDER BY item_kind, id DESC LIMIT 501`,
      ),
      directory: await explain(
        `SELECT COUNT(*) FROM ato_provider_integrations WHERE provider = 'microsoft_entra' AND directory_ref_hash = '${row.directoryRefHash}' AND active_marker = 1`,
      ),
    };
    // Every read is bounded by an index led by the organization (the list may use the
    // `(organization_id, binding_key)` key on small tables: both are organization-bounded), the
    // mailbox reads by `(organization_id, account_id, state, item_kind)` and the directory probe by
    // the unique directory key.
    expect(plans.list[0]!.key).toMatch(
      /^ato_provider_integrations_organization_id_(status_id_idx|binding_key_key)$/,
    );
    expect(plans.streams[0]!.key).toMatch(
      /^ato_provider_streams_(organization_id_integration_id_idx|integration_id_stream_key)$/,
    );
    expect(plans.mailboxPresent[0]!.key).toBe(
      'ato_provider_mailbox_items_organization_id_account_id_state__idx',
    );
    expect(plans.mailboxRemoved[0]!.key).toMatch(
      /^ato_provider_mailbox_items_(organization_id_account_id_state__idx|state_removed_at_idx)$/,
    );
    expect(plans.directory[0]!.key).toBe('ato_provider_integrations_directory_active_key');
    for (const plan of Object.values(plans)) expect(plan[0]!.type).not.toBe('ALL');
  });
});

describe('organization purge and export (§4.1)', () => {
  it('exports integrations, streams and items without tokens or addresses, then purges them in order', async () => {
    const c = await seed.tenant();
    const adminC = await prov.admin(c.org);
    const conn = await prov.connection(c.org);
    const bound = await call(adminC, 'post', P, { connectionId: conn.publicId });
    expect(bound.status, json(bound.body)).toBe(201);
    const row = await integrationRow(bound.body.id);
    const account = await seed.mailbox(c.org.id);
    await prov.identity(account, row);
    await prov.item(account, row);
    const repo = ctx.get(AtoProviderTenantDataRepository);
    const exported = await repo.exportOrganization(systemScope(c.org.id));
    expect(exported.integrations).toEqual([
      expect.objectContaining({ id: bound.body.id, connectionId: conn.publicId }),
    ]);
    expect(exported.streams).toHaveLength(7);
    expect(exported.mailboxItems).toEqual([
      expect.objectContaining({
        accountId: account.publicId,
        targetDomain: 'external-example.net',
      }),
    ]);
    const text = json(exported);
    expect(text).not.toContain('EXAMPLE-rule-id');
    expect(text).not.toContain(account.address!);
    for (const s of await ctx.prisma.atoProviderStream.findMany({
      where: { integrationId: row.id },
    })) {
      if (s.cursor) expect(text).not.toContain(s.cursor);
    }
    const counts = await repo.purgeOrganization(systemScope(c.org.id), 2);
    expect(counts).toEqual({
      ato_provider_mailbox_items: 1,
      ato_provider_streams: 7,
      ato_account_identities: 1,
      ato_provider_integrations: 1,
    });
    const where = { where: { organizationId: c.org.id } };
    expect(await ctx.prisma.atoProviderMailboxItem.count(where)).toBe(0);
    expect(await ctx.prisma.atoProviderStream.count(where)).toBe(0);
    expect(await ctx.prisma.atoAccountIdentity.count(where)).toBe(0);
    expect(await ctx.prisma.atoProviderIntegration.count(where)).toBe(0);
    // Idempotent re-run; the other organizations are untouched.
    expect(Object.values(await repo.purgeOrganization(systemScope(c.org.id)))).toEqual([
      0, 0, 0, 0,
    ]);
    expect(
      await ctx.prisma.atoProviderIntegration.count({ where: { organizationId: a.org.id } }),
    ).toBeGreaterThan(0);
  });
});
