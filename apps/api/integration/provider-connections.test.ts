/**
 * Microsoft 365 and Google Workspace connections (step 8.2 §5, §10.4) against the real MySQL
 * writer and replica of the worktree schema: every route of §5.2 over HTTP with real
 * repositories, tenant isolation (another organization's connections, grants, consent states,
 * domains and runs answer like unknown ids), the encrypted credential custody (ciphertext only,
 * row-bound AAD, never in a response, an audit row or a log line), the apply transaction
 * (destinations + `domain.routing.changed.v1` + connector + connection columns + audit commit
 * together; a failure after the destination write rolls everything back), the `smtp_connectors`
 * changes (`provider_relay` read-only, `409 connector_managed_by_provider_connection`, `422
 * network_shared_provider` against the seeded egress ranges), and the organization purge order
 * and tenant export of §3.3.
 *
 * Redis and S3 are replaced by in-process stand-ins (an in-memory key-value store for rate
 * limits, sessions and idempotency reservations): the suite needs only MySQL. The
 * integration-worker's writes (verification, provider domain checks, run completion, probe
 * evidence) are simulated with SQL, as the other suites do for worker-owned rows.
 */
// @covers get /api/v1/provider-integrations/catalog
// @covers get /api/v1/provider-connections
// @covers post /api/v1/provider-connections
// @covers get /api/v1/provider-connections/:id
// @covers patch /api/v1/provider-connections/:id
// @covers delete /api/v1/provider-connections/:id
// @covers get /api/v1/provider-connections/:id/wizard
// @covers post /api/v1/provider-connections/:id/grants
// @covers post /api/v1/provider-connections/consent/complete
// @covers put /api/v1/provider-connections/:id/grants/:profile/credentials
// @covers post /api/v1/provider-connections/:id/grants/:profile/verify
// @covers delete /api/v1/provider-connections/:id/grants/:profile
// @covers get /api/v1/provider-connections/:id/domains
// @covers put /api/v1/provider-connections/:id/domains
// @covers post /api/v1/provider-connections/:id/mail-flow/preview
// @covers post /api/v1/provider-connections/:id/mail-flow/apply
// @covers get /api/v1/provider-connections/:id/mail-flow
// @covers post /api/v1/provider-connections/:id/attestations
// @covers post /api/v1/provider-connections/:id/validations
// @covers get /api/v1/provider-connections/:id/validations
// @covers get /api/v1/provider-connections/:id/validations/:runId
// @covers get /api/v1/provider-connections/:id/health
// @covers post /api/v1/provider-connections/:id/health/check
// @covers get /api/v1/provider-connections/:id/setup-guide
import { createHash, randomUUID } from 'node:crypto';
import { PrismaReadService, RedisService, S3Service } from '@email-gateway/common';
import { ProviderCredentialCipher } from '@email-gateway/provider-integrations';
import type { Response, Test } from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { KeyValueStore } from '../src/kv/key-value-store';
import { ProviderConnectionsRepository } from '../src/modules/provider-connections/repositories/provider-connections.repository';
import { ProviderTenantDataRepository } from '../src/modules/tenant-data/provider-tenant-data.repository';
import { InMemoryKeyValueStore } from '../test/support/in-memory-key-value-store';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { bearer, loginWithMfa, uniqueIp } from './support/http';
import { insertDomain, type InsertedDomain, randomV4Network } from './support/smtp';

const P = '/api/v1/provider-connections';
const TENANT = '7a1c2b3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d';
const CLIENT_SECRET = 'it-provider-client-secret-0123456789abcdef';
const POLL = { timeout: 10_000, interval: 100 };

const sha256 = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');
const json = (value: unknown): string =>
  JSON.stringify(value, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: Record<string, string>;
let readerA: Record<string, string>;
let adminB: Record<string, string>;
/** Every secret the suite sent or received (scanned against audit rows and logs). */
const secrets = new Set<string>([CLIENT_SECRET]);
/** The consent state of the platform_app grant (never in a guide or a stored response). */
let consentState = 'unset-consent-state';

/** One request as `who`, from a fresh client address (the global per-IP limits never trip). */
function call(
  who: Record<string, string>,
  method: 'get' | 'post' | 'put' | 'patch' | 'delete',
  path: string,
  body?: object,
  keyed = method !== 'get',
): Test {
  let req = ctx.http[method](path).set(who).set('X-Forwarded-For', uniqueIp());
  if (keyed) req = req.set('Idempotency-Key', `it-${randomUUID()}`);
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

async function preview(who: Record<string, string>, id: string, change: object) {
  const res = await call(who, 'post', `${P}/${id}/mail-flow/preview`, { change }, false);
  return res;
}

async function previewAndApply(id: string, change: object) {
  const pre = await preview(adminA, id, change);
  expect(pre.status, json(pre.body)).toBe(200);
  const res = await call(adminA, 'post', `${P}/${id}/mail-flow/apply`, {
    change,
    impactToken: pre.body.impactToken,
    confirm: true,
  });
  return { pre, res };
}

/** What the integration-worker writes when the grant and the domains verify (D3.4, D4, I10). */
async function workerBinds(connectionPublicId: string, mxHost: string | null) {
  const c = await ctx.prisma.providerConnection.findUniqueOrThrow({
    where: { publicId: connectionPublicId },
  });
  await ctx.prisma.providerConnectionGrant.updateMany({
    where: { connectionId: c.id, status: { not: 'revoked' } },
    data: {
      status: 'active',
      verifiedAt: new Date(),
      observedPermissions: ['Organization.Read.All', 'Domain.Read.All'],
      missingPermissions: [],
      excessPermissions: [],
      rowVersion: { increment: 1 },
    },
  });
  await ctx.prisma.providerConnectionDomain.updateMany({
    where: { connectionId: c.id },
    data: {
      providerVerification: 'verified',
      providerCheckedAt: new Date(),
      providerMxHost: mxHost,
    },
  });
  await ctx.prisma.providerConnection.update({
    where: { id: c.id },
    data: {
      status: 'active',
      externalTenantId: TENANT,
      externalTenantName: 'Contoso IT',
      tenantVerifiedAt: new Date(),
      activeTenantKey: `microsoft_365:${TENANT}`,
      rowVersion: { increment: 1 },
    },
  });
}

beforeAll(async () => {
  ctx = await createIntegrationApp(
    {
      REDIS_DKIM_URL: '',
    },
    {
      override: (builder) =>
        builder
          .overrideProvider(RedisService)
          .useValue({ healthName: 'redis', checkHealth: () => Promise.resolve() })
          .overrideProvider(S3Service)
          .useValue({ healthName: 's3', checkHealth: () => Promise.resolve() })
          .overrideProvider(KeyValueStore)
          .useValue(new InMemoryKeyValueStore()),
    },
  );
  fx = createFixtures(ctx);
  [orgA, orgB] = [await fx.createOrganization(), await fx.createOrganization()];
  const login = async (org: FixtureOrganization, roles: string[]) =>
    bearer(
      (await loginWithMfa(ctx, fx, await fx.createUser(org, { roles, mfa: true }))).accessToken,
    );
  adminA = await login(orgA, ['organization_admin']);
  readerA = await login(orgA, [await fx.createCustomRole(orgA, ['integration:read'])]);
  adminB = await login(orgB, ['organization_admin']);
  const purge = ctx.get(ProviderTenantDataRepository);
  // Provider rows reference the organizations with RESTRICT: purge them before the fixtures go.
  fx.registerCleanup(async () => {
    await purge.purgeOrganization(systemScope(orgA.id));
    await purge.purgeOrganization(systemScope(orgB.id));
  });
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('catalogue and connections (#1–#7)', () => {
  let connectionId: string;

  it('serves the catalogue with the seeded egress sets and the gateway values', async () => {
    const res = await call(readerA, 'get', '/api/v1/provider-integrations/catalog');
    expect(res.status, json(res.body)).toBe(200);
    const m365 = res.body.providers.find(
      (p: { provider: string }) => p.provider === 'microsoft_365',
    );
    expect(m365.profiles[0]).toMatchObject({ key: 'm365.mail_flow', readOnly: true });
    expect(m365.egressSet).toMatchObject({ version: expect.any(Number) });
    expect(res.body.probeDomain).toBe(ctx.config.PROVIDER_PROBE_DOMAIN);
  });

  it('creates (keyed, replayed), lists with a signed cursor, reads, renames and computes the wizard', async () => {
    const key = `it-${randomUUID()}`;
    const body = { provider: 'microsoft_365', displayName: `Contoso ${randomUUID()}` };
    const created = await ctx.http
      .post(P)
      .set(adminA)
      .set('X-Forwarded-For', uniqueIp())
      .set('Idempotency-Key', key)
      .send(body);
    expect(created.status, json(created.body)).toBe(201);
    connectionId = created.body.id;
    const replay = await ctx.http
      .post(P)
      .set(adminA)
      .set('X-Forwarded-For', uniqueIp())
      .set('Idempotency-Key', key)
      .send(body);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body.id).toBe(connectionId);
    const row = await ctx.prisma.providerConnection.findUniqueOrThrow({
      where: { publicId: connectionId },
    });
    expect(row).toMatchObject({ organizationId: orgA.id, status: 'draft', outboundMode: 'off' });
    const second = await call(adminA, 'post', P, {
      provider: 'google_workspace',
      displayName: `Google ${randomUUID()}`,
    });
    expect(second.status).toBe(201);

    const page = await eventually(
      () => call(readerA, 'get', `${P}?limit=1`),
      (r) => r.status === 200 && r.body.data[0]?.id === second.body.id,
    );
    expect(page.body.nextCursor).toEqual(expect.any(String));
    const next = await call(
      readerA,
      'get',
      `${P}?limit=1&cursor=${encodeURIComponent(page.body.nextCursor)}`,
    );
    expect(next.body.data.map((r: { id: string }) => r.id)).toEqual([connectionId]);
    // The cursor is bound to organization A.
    const foreignCursor = await call(
      adminB,
      'get',
      `${P}?limit=1&cursor=${encodeURIComponent(page.body.nextCursor)}`,
    );
    expect(foreignCursor.status).toBe(400);
    expect((await call(adminB, 'get', P)).body.data).toEqual([]);

    const detail = await eventually(
      () => call(readerA, 'get', `${P}/${connectionId}`),
      (r) => r.status === 200,
    );
    expect(detail.body).toMatchObject({ id: connectionId, status: 'draft', rowVersion: 1 });
    const renamed = await call(
      adminA,
      'patch',
      `${P}/${connectionId}`,
      {
        displayName: `Contoso renamed ${randomUUID()}`,
        rowVersion: 1,
      },
      false,
    );
    expect(renamed.status, json(renamed.body)).toBe(200);
    const stale = await call(
      adminA,
      'patch',
      `${P}/${connectionId}`,
      {
        displayName: 'Stale',
        rowVersion: 1,
      },
      false,
    );
    expect(stale.status).toBe(409);
    const wizard = await call(readerA, 'get', `${P}/${connectionId}/wizard`);
    expect(wizard.status).toBe(200);
    expect(wizard.body.nextAction).toEqual({ step: 'connect', action: 'grant_access' });
    expect(
      (await call(readerA, 'post', P, { provider: 'microsoft_365', displayName: 'x' })).status,
    ).toBe(403);
  });

  it('another organization sees none of it (404 like an unknown id)', async () => {
    for (const [method, path, body] of [
      ['get', `${P}/${connectionId}`],
      ['patch', `${P}/${connectionId}`, { displayName: 'B', rowVersion: 2 }],
      ['get', `${P}/${connectionId}/wizard`],
      [
        'post',
        `${P}/${connectionId}/grants`,
        { profile: 'm365.mail_flow', authMethod: 'customer_app_secret' },
      ],
      ['get', `${P}/${connectionId}/domains`],
      ['put', `${P}/${connectionId}/domains`, { domainIds: [] }],
      ['post', `${P}/${connectionId}/mail-flow/preview`, { change: { kind: 'suspend' } }],
      ['get', `${P}/${connectionId}/mail-flow`],
      [
        'post',
        `${P}/${connectionId}/attestations`,
        { code: 'm365.inbound_connector_created', attested: true },
      ],
      ['post', `${P}/${connectionId}/validations`, { kind: 'credentials' }],
      ['get', `${P}/${connectionId}/validations`],
      ['get', `${P}/${connectionId}/health`],
      ['post', `${P}/${connectionId}/health/check`, {}],
      ['get', `${P}/${connectionId}/setup-guide`],
    ] as Array<['get' | 'post' | 'put' | 'patch', string, object?]>) {
      const res = await call(adminB, method, path, body);
      expect(res.status, `${method} ${path}: ${json(res.body)}`).toBe(404);
      expect(res.body.code, path).toBe('connection_not_found');
    }
  });

  describe('grants, consent and credentials (#8–#12, D3, D5)', () => {
    it('platform_app: the state is stored only as SHA-256 and bound to the consenting user and organization', async () => {
      const created = await call(adminA, 'post', `${P}/${connectionId}/grants`, {
        profile: 'm365.mail_flow',
        authMethod: 'platform_app',
      });
      expect(created.status, json(created.body)).toBe(201);
      const state = new URL(created.body.consent.consentUrl).searchParams.get('state')!;
      secrets.add(state);
      consentState = state;
      const stored = await ctx.prisma.providerConsentState.findMany({
        where: { organizationId: orgA.id },
      });
      expect(stored.map((s) => s.stateSha256)).toContain(sha256(state));
      expect(json(stored)).not.toContain(state);
      const body = { state, tenant: TENANT, adminConsent: true };
      // Organization B cannot complete A's consent.
      const foreign = await call(adminB, 'post', `${P}/consent/complete`, body);
      expect(foreign.status).toBe(404);
      expect(foreign.body.code).toBe('consent_state_invalid');
      const done = await call(adminA, 'post', `${P}/consent/complete`, body);
      expect(done.status, json(done.body)).toBe(200);
      expect(done.body).toMatchObject({ connectionId, status: 'verifying' });
      expect((await call(adminA, 'post', `${P}/consent/complete`, body)).status).toBe(404);
      const grant = await ctx.prisma.providerConnectionGrant.findFirstOrThrow({
        where: { organizationId: orgA.id, connection: { publicId: connectionId } },
      });
      expect(grant).toMatchObject({ status: 'verifying', claimedTenantId: TENANT });
    });
  });

  describe('domains, binding and the mail-flow apply (#13–#17, D4, D13)', () => {
    let domain: InsertedDomain;

    it('links active domains of the organization only; another organization’s domain is 404', async () => {
      domain = await insertDomain(ctx, orgA, { label: 'prov' });
      const pending = await insertDomain(ctx, orgA, {
        label: 'prov-p',
        status: 'pending_verification',
      });
      const foreign = await insertDomain(ctx, orgB, { label: 'prov-b' });
      const path = `${P}/${connectionId}/domains`;
      expect((await call(adminA, 'put', path, { domainIds: [pending.publicId] })).body.code).toBe(
        'domain_not_verified',
      );
      expect((await call(adminA, 'put', path, { domainIds: [foreign.publicId] })).status).toBe(404);
      const ok = await call(adminA, 'put', path, { domainIds: [domain.publicId] });
      expect(ok.status, json(ok.body)).toBe(200);
      const list = await eventually(
        () => call(readerA, 'get', path),
        (r) => r.status === 200 && r.body.data.length === 1,
      );
      expect(list.body.data[0]).toMatchObject({
        id: domain.publicId,
        providerVerification: 'unknown',
      });
      // A second connection of A cannot take the same domain.
      const other = await call(adminA, 'post', P, {
        provider: 'microsoft_365',
        displayName: `Other ${randomUUID()}`,
      });
      const taken = await call(adminA, 'put', `${P}/${other.body.id}/domains`, {
        domainIds: [domain.publicId],
      });
      expect(taken.status).toBe(409);
      expect(taken.body.code).toBe('domain_linked_elsewhere');
    });

    it('applies inbound in ONE transaction; a failure after the destination write rolls it all back', async () => {
      const before = await preview(adminA, connectionId, {
        kind: 'inbound',
        domainIds: [domain.publicId],
      });
      expect(before.status).toBe(409);
      expect(before.body.code).toBe('connection_not_bound');
      await workerBinds(
        connectionId,
        `${domain.name.replace(/\./g, '-')}.mail.protection.outlook.com`,
      );

      const change = { kind: 'inbound', domainIds: [domain.publicId] };
      // Rollback: the connection write after the destinations fails once.
      const repo = ctx.get(ProviderConnectionsRepository);
      const original = repo.update.bind(repo);
      let failed = false;
      repo.update = (...args: Parameters<typeof repo.update>) => {
        if (!failed) {
          failed = true;
          return Promise.reject(new Error('injected failure after the destination write'));
        }
        return original(...args);
      };
      try {
        const pre = await preview(adminA, connectionId, change);
        expect(pre.status, json(pre.body)).toBe(200);
        const broken = await call(adminA, 'post', `${P}/${connectionId}/mail-flow/apply`, {
          change,
          impactToken: pre.body.impactToken,
          confirm: true,
        });
        expect(broken.status).toBe(500);
      } finally {
        repo.update = original;
      }
      expect(await ctx.prisma.domainMailServer.count({ where: { domainId: domain.id } })).toBe(0);
      expect(
        await ctx.prisma.messageOutbox.count({
          where: { eventType: 'domain.routing.changed.v1', aggregateId: domain.id.toString() },
        }),
      ).toBe(0);

      const { pre, res } = await previewAndApply(connectionId, change);
      expect(pre.body.changeSet.domains[0]).toMatchObject({
        changed: true,
        proposed: { provider: 'microsoft_365' },
      });
      expect(res.status, json(res.body)).toBe(200);
      const servers = await ctx.prisma.domainMailServer.findMany({
        where: { domainId: domain.id, role: 'inbound_destination' },
      });
      expect(servers).toEqual([
        expect.objectContaining({
          provider: 'microsoft_365',
          host: `${domain.name.replace(/\./g, '-')}.mail.protection.outlook.com`,
        }),
      ]);
      expect(
        await ctx.prisma.messageOutbox.count({
          where: { eventType: 'domain.routing.changed.v1', aggregateId: domain.id.toString() },
        }),
      ).toBe(1);
      const link = await ctx.prisma.providerConnectionDomain.findUniqueOrThrow({
        where: { domainId: domain.id },
      });
      expect(link.inboundAppliedAt).not.toBeNull();
      const applied = await ctx.prisma.auditLog.findMany({
        where: {
          organizationId: orgA.id,
          action: 'integration.mail_flow_applied',
          resourceId: connectionId,
        },
      });
      expect(applied).toHaveLength(1);
      // A replayed token is refused (the row version moved).
      const again = await call(adminA, 'post', `${P}/${connectionId}/mail-flow/apply`, {
        change,
        impactToken: pre.body.impactToken,
        confirm: true,
      });
      expect(again.status).toBe(409);
      expect(['impact_changed', 'change_not_applicable']).toContain(again.body.code);
    });

    it('outbound probe_only creates the provider_relay connector, read-only in /smtp-connectors', async () => {
      const { res } = await previewAndApply(connectionId, { kind: 'outbound', mode: 'probe_only' });
      expect(res.status, json(res.body)).toBe(200);
      const c = await ctx.prisma.providerConnection.findUniqueOrThrow({
        where: { publicId: connectionId },
        include: { smtpConnector: true },
      });
      expect(c.outboundMode).toBe('probe_only');
      expect(c.smtpConnector).toMatchObject({
        authType: 'provider_relay',
        status: 'active',
        requireTls: true,
      });
      const connectorId = c.smtpConnector!.publicId;
      const listed = await eventually(
        () => call(adminA, 'get', `/api/v1/smtp-connectors/${connectorId}`),
        (r) => r.status === 200,
      );
      expect(listed.body).toMatchObject({
        authType: 'provider_relay',
        providerConnectionId: connectionId,
      });
      for (const res2 of [
        await call(adminA, 'patch', `/api/v1/smtp-connectors/${connectorId}`, { name: 'x' }, false),
        await call(
          adminA,
          'post',
          `/api/v1/smtp-connectors/${connectorId}/rotate-secret`,
          undefined,
          false,
        ),
        await call(adminA, 'delete', `/api/v1/smtp-connectors/${connectorId}`, undefined, false),
      ]) {
        expect(res2.status).toBe(409);
        expect(res2.body.code).toBe('connector_managed_by_provider_connection');
      }
      const state = await call(adminA, 'get', `${P}/${connectionId}/mail-flow`);
      expect(state.status).toBe(200);
      expect(state.body.routeToken.value).toEqual(expect.any(String));
      secrets.add(state.body.routeToken.value);
      const masked = await call(readerA, 'get', `${P}/${connectionId}/mail-flow`);
      expect(masked.body.routeToken.value).toBeNull();
    });

    it('refuses source_ip networks on shared provider egress ranges (422 network_shared_provider)', async () => {
      const refused = await call(
        adminA,
        'post',
        '/api/v1/smtp-connectors',
        {
          name: `on-m365-${randomUUID().slice(0, 8)}`,
          authType: 'source_ip',
          networks: ['40.107.1.0/24'],
        },
        false,
      );
      expect(refused.status, json(refused.body)).toBe(422);
      expect(refused.body.code).toBe('network_shared_provider');
      const ok = await call(
        adminA,
        'post',
        '/api/v1/smtp-connectors',
        {
          name: `own-${randomUUID().slice(0, 8)}`,
          authType: 'source_ip',
          networks: [randomV4Network(28)],
        },
        false,
      );
      expect(ok.status, json(ok.body)).toBe(201);
      const patched = await call(
        adminA,
        'patch',
        `/api/v1/smtp-connectors/${ok.body.id}`,
        {
          networks: ['2a01:111:f400::1/128'],
        },
        false,
      );
      expect(patched.status).toBe(422);
      expect(patched.body.code).toBe('network_shared_provider');
    });

    it('attestations, validation runs (probe address once), health, check now and the guide', async () => {
      for (const code of [
        'm365.inbound_connector_created',
        'm365.enhanced_filtering_enabled',
        'm365.direct_delivery_locked_down',
      ]) {
        const res = await call(adminA, 'post', `${P}/${connectionId}/attestations`, {
          code,
          attested: true,
        });
        expect(res.status, json(res.body)).toBe(200);
      }
      const unknown = await call(adminA, 'post', `${P}/${connectionId}/attestations`, {
        code: 'google.inbound_gateway_configured',
        attested: true,
      });
      expect(unknown.body.code).toBe('attestation_unknown');

      const run = await call(adminA, 'post', `${P}/${connectionId}/validations`, { kind: 'full' });
      expect(run.status, json(run.body)).toBe(201);
      const probe = run.body.probeAddress as string;
      expect(probe).toMatch(/^eg-probe-[a-z2-7]{26}@/);
      const token = probe.slice('eg-probe-'.length, probe.indexOf('@'));
      secrets.add(token);
      const stored = await ctx.prisma.providerValidationRun.findUniqueOrThrow({
        where: { publicId: run.body.id },
      });
      expect(stored.probeTokenSha256).toMatch(/^[0-9a-f]{64}$/);
      expect(json(stored)).not.toContain(token);
      // The worker completes the run and records the probe (SQL: worker-owned rows).
      const c = await ctx.prisma.providerConnection.findUniqueOrThrow({
        where: { publicId: connectionId },
      });
      await ctx.prisma.providerValidationRun.update({
        where: { id: stored.id },
        data: {
          status: 'passed',
          completedAt: new Date(),
          summary: { pass: 12, warn: 0, fail: 0, skipped: 2, error: 0 },
          results: [
            {
              code: 'credentials.token',
              subject: 'm365.mail_flow',
              status: 'pass',
              severity: 'critical',
              evidence: {},
              remediation: 'connect',
            },
          ],
        },
      });
      await ctx.prisma.providerProbeObservation.create({
        data: {
          organizationId: orgA.id,
          connectionId: c.id,
          validationRunId: stored.id,
          tokenSha256: stored.probeTokenSha256!,
          queueId: `Q${randomUUID().slice(0, 10).toUpperCase()}`,
          provider: 'microsoft_365',
          clientIp: '40.107.1.10',
          tlsProtocol: 'TLSv1.3',
          envelopeFromDomain: domain.name,
          headerFromDomain: domain.name,
          tenantHeader: 'match',
          dkim: 'aligned_pass',
          dkimDomains: [domain.name],
          proofResult: 'pass',
          receivedAt: new Date(),
        },
      });
      await ctx.prisma.providerHealthEvent.create({
        data: {
          organizationId: orgA.id,
          connectionId: c.id,
          fromStatus: 'unknown',
          toStatus: 'healthy',
          failingChecks: [],
        },
      });
      await ctx.prisma.providerRelayCounter.create({
        data: {
          organizationId: orgA.id,
          connectionId: c.id,
          hourStart: new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000),
          accepted: 3,
          probes: 1,
        },
      });

      const list = await eventually(
        () => call(readerA, 'get', `${P}/${connectionId}/validations?limit=10`),
        (r) => r.status === 200 && r.body.data[0]?.status === 'passed',
      );
      expect(list.body.data[0].id).toBe(run.body.id);
      const detail = await call(readerA, 'get', `${P}/${connectionId}/validations/${run.body.id}`);
      expect(detail.status).toBe(200);
      expect(detail.body.probeObservations[0]).toMatchObject({
        proofResult: 'pass',
        dkim: 'aligned_pass',
      });
      expect(json(detail.body)).not.toContain(stored.probeTokenSha256!);
      expect(
        (await call(adminB, 'get', `${P}/${connectionId}/validations/${run.body.id}`)).status,
      ).toBe(404);

      const health = await eventually(
        () => call(readerA, 'get', `${P}/${connectionId}/health`),
        (r) => r.status === 200 && r.body.transitions?.length === 1,
      );
      expect(health.body.transitions[0]).toMatchObject({ to: 'healthy' });
      const check = await call(adminA, 'post', `${P}/${connectionId}/health/check`, {});
      expect(check.status, json(check.body)).toBe(202);

      const guide = await call(adminA, 'get', `${P}/${connectionId}/setup-guide`);
      expect(guide.status, json(guide.body)).toBe(200);
      expect(guide.body.schema).toBe('setup-guide/1');
      const md = await call(readerA, 'get', `${P}/${connectionId}/setup-guide?format=markdown`);
      expect(md.status).toBe(200);
      expect(md.headers['content-type']).toMatch(/^text\/markdown/);
      expect(md.text).toContain(domain.name);
      expect(md.text).not.toContain(consentState);
      expect(md.text).not.toContain(token);
    });

    it('activates outbound after a passed validation and probe, then disconnects keeping destinations', async () => {
      const activate = { kind: 'activate', outboundMode: 'active', internalRouting: false };
      const { res } = await previewAndApply(connectionId, activate);
      expect(res.status, json(res.body)).toBe(200);
      expect(
        (
          await ctx.prisma.providerConnection.findUniqueOrThrow({
            where: { publicId: connectionId },
          })
        ).outboundMode,
      ).toBe('active');
      // A grant cannot be revoked while outbound is on.
      const busy = await call(adminA, 'delete', `${P}/${connectionId}/grants/m365.mail_flow`);
      expect(busy.status).toBe(409);
      expect(busy.body.code).toBe('outbound_active');

      const pre = await preview(adminA, connectionId, { kind: 'disable' });
      expect(pre.status, json(pre.body)).toBe(200);
      const gone = await call(adminA, 'delete', `${P}/${connectionId}`, {
        impactToken: pre.body.impactToken,
        confirm: true,
      });
      expect(gone.status, json(gone.body)).toBe(200);
      expect(gone.body.destinationsKept).toBe(true);
      const c = await ctx.prisma.providerConnection.findUniqueOrThrow({
        where: { publicId: connectionId },
        include: { smtpConnector: true, grants: true },
      });
      expect(c).toMatchObject({ status: 'disabled', outboundMode: 'off', activeTenantKey: null });
      expect(c.smtpConnector).toMatchObject({ status: 'disabled' });
      expect(c.grants.every((g) => g.status === 'revoked' && g.credentialCiphertext === null)).toBe(
        true,
      );
      expect(await ctx.prisma.domainMailServer.count({ where: { domainId: domain.id } })).toBe(1);
    });
  });

  describe('customer credentials (#10–#12, D5, ADR-0077)', () => {
    it('stores only the row-bound ciphertext, re-verifies, and wipes it on revocation', async () => {
      const c = await call(adminA, 'post', P, {
        provider: 'microsoft_365',
        displayName: `Own app ${randomUUID()}`,
      });
      const id = c.body.id as string;
      const grant = await call(adminA, 'post', `${P}/${id}/grants`, {
        profile: 'm365.mail_flow',
        authMethod: 'customer_app_secret',
      });
      expect(grant.status, json(grant.body)).toBe(201);
      const path = `${P}/${id}/grants/m365.mail_flow/credentials`;
      const body = {
        tenantId: TENANT,
        clientId: '3f2504e0-4f89-41d3-9a0c-0305e82c3301',
        clientSecret: CLIENT_SECRET,
      };
      const key = `it-${randomUUID()}`;
      const put = await ctx.http
        .put(path)
        .set(adminA)
        .set('X-Forwarded-For', uniqueIp())
        .set('Idempotency-Key', key)
        .send(body);
      expect(put.status, json(put.body)).toBe(200);
      expect(put.body.credentialFingerprint).toMatch(/^[0-9a-f]{12}$/);
      expect(json(put.body)).not.toContain(CLIENT_SECRET);
      const replay = await ctx.http
        .put(path)
        .set(adminA)
        .set('X-Forwarded-For', uniqueIp())
        .set('Idempotency-Key', key)
        .send(body);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(json(replay.body)).not.toContain(CLIENT_SECRET);
      const row = await ctx.prisma.providerConnectionGrant.findFirstOrThrow({
        where: { organizationId: orgA.id, connection: { publicId: id } },
        include: { connection: true },
      });
      expect(row.credentialCiphertext).toMatch(/^v1\./);
      expect(row.credentialCiphertext).not.toContain(CLIENT_SECRET);
      // Only the key holder (the integration-worker) decrypts, for this row only.
      const cipher = new ProviderCredentialCipher({
        key: ctx.config.PROVIDER_CREDENTIAL_ENCRYPTION_KEY,
      });
      expect(
        cipher.decryptCredential(row.credentialCiphertext!, {
          organizationId: orgA.id,
          connectionPublicId: id,
          grantPublicId: row.publicId,
          credentialVersion: row.credentialVersion,
        }).credential,
      ).toMatchObject({ clientSecret: CLIENT_SECRET });
      // Nothing the api stores in the idempotency table carries the secret.
      const keys = await ctx.prisma.apiIdempotencyKey.findMany({
        where: { organizationId: orgA.id },
        select: { response: true, requestSha256: true },
      });
      expect(keys.length).toBeGreaterThan(0);
      expect(json(keys)).not.toContain(CLIENT_SECRET);
      // The stored consent URL is redacted (ADR-0057): no stored response carries a state.
      expect(json(keys)).not.toContain(consentState);

      const verify = await call(adminA, 'post', `${P}/${id}/grants/m365.mail_flow/verify`, {});
      expect(verify.status, json(verify.body)).toBe(200);
      expect(verify.body.status).toBe('verifying');
      expect(
        (await call(adminB, 'post', `${P}/${id}/grants/m365.mail_flow/verify`, {})).status,
      ).toBe(404);
      expect((await call(adminB, 'put', path, body)).status).toBe(404);
      expect((await call(adminB, 'delete', `${P}/${id}/grants/m365.mail_flow`)).status).toBe(404);

      const revoked = await call(adminA, 'delete', `${P}/${id}/grants/m365.mail_flow`);
      expect(revoked.status, json(revoked.body)).toBe(200);
      const after = await ctx.prisma.providerConnectionGrant.findUniqueOrThrow({
        where: { id: row.id },
      });
      expect(after).toMatchObject({
        status: 'revoked',
        credentialCiphertext: null,
        credentialKeyId: null,
      });
    });
  });

  it('no audit row or log line of the suite carries a secret, consent state, probe token or route token', async () => {
    const rows = await ctx.prisma.auditLog.findMany({
      where: { organizationId: { in: [orgA.id, orgB.id] }, resourceType: 'provider_connection' },
    });
    expect(rows.length).toBeGreaterThan(10);
    const text = json(rows);
    const logs = ctx.logs.join('\n');
    for (const secret of secrets) {
      expect(text).not.toContain(secret);
      expect(logs).not.toContain(secret);
    }
  });
});

describe('organization purge and tenant export (§3.3)', () => {
  it('exports without credential material, then purges in order and detaches relay connectors', async () => {
    const repo = ctx.get(ProviderTenantDataRepository);
    const exported = await repo.exportOrganization(systemScope(orgA.id));
    expect(exported.connections.length).toBeGreaterThanOrEqual(3);
    expect(exported.grants.length).toBeGreaterThanOrEqual(2);
    expect(exported.domains.length).toBe(1);
    expect(exported.validationRuns.length).toBeGreaterThanOrEqual(1);
    expect(exported.healthEvents).toHaveLength(1);
    const text = json(exported);
    expect(text).not.toMatch(/ciphertext|probeTokenSha256/i);
    for (const secret of secrets) expect(text).not.toContain(secret);

    const counts = await repo.purgeOrganization(systemScope(orgA.id));
    expect(counts.provider_relay_counters).toBe(1);
    expect(counts.provider_probe_observations).toBe(1);
    expect(counts.provider_health_events).toBe(1);
    expect(counts.provider_consent_states).toBeGreaterThanOrEqual(1);
    expect(counts.provider_connection_domains).toBe(1);
    expect(counts.smtp_connectors_detached).toBe(1);
    expect(counts.provider_connections).toBe(exported.connections.length);
    for (const model of [
      ctx.prisma.providerConnection,
      ctx.prisma.providerConnectionGrant,
      ctx.prisma.providerConnectionDomain,
      ctx.prisma.providerValidationRun,
      ctx.prisma.providerConsentState,
    ] as unknown as Array<{ count: (a: object) => Promise<number> }>) {
      expect(await model.count({ where: { organizationId: orgA.id } })).toBe(0);
    }
    expect(
      await ctx.prisma.smtpConnector.count({
        where: { organizationId: orgA.id, authType: 'provider_relay' },
      }),
    ).toBe(1);
    // Organization B is untouched by A's purge; a re-run is a no-op.
    expect(
      Object.values(await repo.purgeOrganization(systemScope(orgA.id))).every((n) => n === 0),
    ).toBe(true);
    // The reader replica catches up (the routes read from it).
    await expect
      .poll(
        async () =>
          await ctx
            .get(PrismaReadService)
            .client.providerConnection.count({ where: { organizationId: orgA.id } }),
        POLL,
      )
      .toBe(0);
  });
});
