/**
 * Tenant isolation of the step 8.5 identity-provider routes against the real writer and replica
 * and step 8.2's connection tables (docs/plan/steps/26-ato-provider-adapters.md §6, §11.4): two
 * `it-ato-*` organizations, each with a bound integration, a connection, a monitored account with
 * a provider identity and mailbox items. Every route called by organization A with organization
 * B's ids answers like an unknown id (404), A's lists never include B's integrations or
 * connections, B's connection cannot be bound by A, and nothing of B changes (integration, stream,
 * identity and item rows compared before and after).
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
import { defaultBindingSettings } from '@email-gateway/idp-adapters';
import type { Test } from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { AtoSeeder, type AtoTenant } from './support/ato';
import { ProviderSeeder, type SeededConnection } from './support/ato-providers';
import { createFixtures, type Fixtures } from './support/fixtures';
import { idem, uniqueIp } from './support/http';

const BASE = '/api/v1/ato';
const P = `${BASE}/providers`;
const DAY = 86_400_000;

let ctx: IntegrationApp;
let fx: Fixtures;
let seed: AtoSeeder;
let prov: ProviderSeeder;

interface Side {
  t: AtoTenant;
  admin: Record<string, string>;
  connection: SeededConnection;
  integration: string;
  account: string;
}
let a: Side;
let b: Side;

function call(
  who: Record<string, string>,
  method: 'get' | 'post' | 'patch' | 'delete',
  path: string,
  body?: object,
): Test {
  let req = ctx.http[method](path).set(who).set('X-Forwarded-For', uniqueIp());
  if (method !== 'get') req = req.set(idem());
  return body === undefined ? req : req.send(body);
}

async function side(): Promise<Side> {
  const t = await seed.tenant();
  const admin = await prov.admin(t.org);
  const connection = await prov.connection(t.org);
  const bound = await call(admin, 'post', P, { connectionId: connection.publicId });
  expect(bound.status, JSON.stringify(bound.body)).toBe(201);
  const integration = await prov.probed(bound.body.id);
  const account = await seed.mailbox(t.org.id);
  await prov.identity(account, integration);
  await prov.item(account, integration);
  return { t, admin, connection, integration: bound.body.id, account: account.publicId };
}

/** Everything of an organization that a cross-tenant call could change. */
async function snapshot(s: Side) {
  const where = { where: { organizationId: s.t.org.id } };
  const [integrations, streams, identities, items, audits] = await Promise.all([
    ctx.prisma.atoProviderIntegration.findMany({ ...where, orderBy: { id: 'asc' } }),
    ctx.prisma.atoProviderStream.findMany({ ...where, orderBy: { id: 'asc' } }),
    ctx.prisma.atoAccountIdentity.findMany({ ...where, orderBy: { id: 'asc' } }),
    ctx.prisma.atoProviderMailboxItem.findMany({ ...where, orderBy: { id: 'asc' } }),
    ctx.prisma.auditLog.count({
      where: { organizationId: s.t.org.id, action: { startsWith: 'ato.' } },
    }),
  ]);
  return JSON.stringify({ integrations, streams, identities, items, audits }, (_k, v: unknown) =>
    typeof v === 'bigint' ? v.toString() : v,
  );
}

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  seed = new AtoSeeder(ctx, fx);
  prov = new ProviderSeeder(ctx, fx);
  a = await side();
  b = await side();
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('identity-provider tenant isolation (§6)', () => {
  it('every route of organization A answers 404 for organization B’s ids; B is unchanged', async () => {
    const before = await snapshot(b);
    const settings = defaultBindingSettings();
    const cases: Array<[string, Test, string]> = [
      ['get', call(a.admin, 'get', `${P}/${b.integration}`), 'ato_provider_not_found'],
      [
        'patch',
        call(a.admin, 'patch', `${P}/${b.integration}`, { rowVersion: 1, settings }),
        'ato_provider_not_found',
      ],
      [
        'pause',
        call(a.admin, 'post', `${P}/${b.integration}/pause`, { reason: 'Cross tenant' }),
        'ato_provider_not_found',
      ],
      ['resume', call(a.admin, 'post', `${P}/${b.integration}/resume`), 'ato_provider_not_found'],
      [
        'health-check',
        call(a.t.apiKey, 'post', `${P}/${b.integration}/health-check`),
        'ato_provider_not_found',
      ],
      [
        'backfill',
        call(a.admin, 'post', `${P}/${b.integration}/backfill`, {
          from: new Date(Date.now() - DAY).toISOString(),
        }),
        'ato_provider_not_found',
      ],
      [
        'delete',
        call(a.admin, 'delete', `${P}/${b.integration}`, { reason: 'Cross tenant' }),
        'ato_provider_not_found',
      ],
      [
        'create with B’s connection',
        call(a.admin, 'post', P, { connectionId: b.connection.publicId }),
        'ato_provider_connection_not_found',
      ],
      [
        'mailbox-state',
        call(a.t.analystAuth, 'get', `${BASE}/accounts/${b.account}/mailbox-state`),
        'ato_account_not_found',
      ],
      [
        'mailbox-state refresh',
        call(a.t.apiKey, 'post', `${BASE}/accounts/${b.account}/mailbox-state/refresh`),
        'ato_account_not_found',
      ],
    ];
    for (const [name, request, code] of cases) {
      const res = await request;
      expect(res.status, `${name}: ${JSON.stringify(res.body)}`).toBe(404);
      expect(res.body.code, name).toBe(code);
      expect(JSON.stringify(res.body), name).not.toContain(b.t.org.publicId);
    }
    expect(await snapshot(b)).toBe(before);
  });

  it('A’s lists hold only A’s integrations and connections; the requirements hold no tenant data', async () => {
    // Replica reads: wait until the binding of both sides is visible.
    await expect
      .poll(
        async () => {
          const body = (await call(a.t.analystAuth, 'get', P)).body as {
            data?: Array<{ id: string }>;
          };
          return body.data?.map((d) => d.id);
        },
        { timeout: 10_000, interval: 100 },
      )
      .toEqual([a.integration]);
    const all = await call(a.t.analystAuth, 'get', `${P}?includeDisabled=true`);
    expect(all.body.data.map((d: { id: string }) => d.id)).toEqual([a.integration]);
    const connections = await call(a.admin, 'get', `${P}/connections`);
    expect(connections.body.data.map((c: { id: string }) => c.id)).toEqual([a.connection.publicId]);
    const requirements = await call(a.t.analystAuth, 'get', `${P}/requirements`);
    expect(requirements.status).toBe(200);
    const text = JSON.stringify(requirements.body);
    for (const id of [a.integration, b.integration, a.connection.publicId, b.connection.publicId]) {
      expect(text).not.toContain(id);
    }
    // A's own mailbox state names only A's integration.
    const own = await call(a.t.analystAuth, 'get', `${BASE}/accounts/${a.account}/mailbox-state`);
    expect(own.status).toBe(200);
    expect(own.body.integrations.map((i: { id: string }) => i.id)).toEqual([a.integration]);
    expect(JSON.stringify(own.body)).not.toContain(b.integration);
    // The 8.4 settings of A list only A's integration.
    const settings = await call(a.t.analystAuth, 'get', `${BASE}/settings`);
    expect(JSON.stringify(settings.body.identityProviders)).not.toContain(b.integration);
  });
});
