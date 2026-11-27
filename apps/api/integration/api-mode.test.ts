/**
 * Step API-1 api on the real writer and replica (docs/plan/steps/35-api-mode-protection.md D1,
 * D2, D4, D6, D10-D12, §9.4): protection modes end to end (MX conflict from `domain_mx_records`,
 * the organization fan-out, audit rows, inline mail flow untouched, the domain and organization
 * views, `POST /domains` with a mode), the lazily created API-mode row with CAS, the feeds,
 * inventory and resync requests, mailboxes and detections from the replica (masked, cursors),
 * cross-tenant 404s, the public Graph callbacks against stored subscription rows (coalescing
 * UPDATE, constant-time client-state hash match), the `remediation:write` gate of the
 * mailbox-access grants, the journal intake entitlement without archiving, API-mode copies
 * absent from the gateway views (explorer, detail, reports) and counted in `apiCopiesToday`, and
 * the organization purge of the six API-mode tables. Synthetic `it-*` organizations only.
 */
// @covers get /api/v1/organizations/:id/protection-mode
// @covers put /api/v1/organizations/:id/protection-mode
// @covers put /api/v1/domains/:domainId/protection-mode
// @covers get /api/v1/api-mode/overview
// @covers get /api/v1/api-mode/connections
// @covers get /api/v1/api-mode/connections/:connectionId
// @covers get /api/v1/api-mode/connections/:connectionId/setup-guide
// @covers put /api/v1/api-mode/connections/:connectionId/settings
// @covers post /api/v1/api-mode/connections/:connectionId/inventory-sync
// @covers get /api/v1/api-mode/mailboxes
// @covers get /api/v1/api-mode/mailboxes/:mailboxId
// @covers post /api/v1/api-mode/mailboxes/:mailboxId/resync
// @covers get /api/v1/api-mode/detections
// @covers get /api/v1/api-mode/detections/:detectionId
// @covers post /api/v1/provider-notifications/graph
// @covers post /api/v1/provider-notifications/graph/lifecycle
import { createHash, randomUUID } from 'node:crypto';
import { RedisService, S3Service, uuidv7 } from '@email-gateway/common';
import { clientStateHash } from '@email-gateway/mailbox-api';
import type { Response, Test } from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { KeyValueStore } from '../src/kv/key-value-store';
import { ApiModeTenantDataRepository } from '../src/modules/tenant-data/api-mode-tenant-data.repository';
import { JournalIntakeTenantDataRepository } from '../src/modules/tenant-data/journal-intake-tenant-data.repository';
import { ProviderTenantDataRepository } from '../src/modules/tenant-data/provider-tenant-data.repository';
import { InMemoryKeyValueStore } from '../test/support/in-memory-key-value-store';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa, uniqueIp } from './support/http';
import { deleteMessagesData, seedMessage } from './support/messages-data';
import { insertDomain, type InsertedDomain } from './support/smtp';

const BASE = '/api/v1/api-mode';
const GRAPH = '/api/v1/provider-notifications/graph';
const TENANT = '7c1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f';
const STATE = 'integration-client-state-placeholder-000000';
const REASON = 'Integration: protect by API';
const POLL = { timeout: 15_000, interval: 200 };
const sha256 = (v: string) => createHash('sha256').update(v).digest('hex');

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let orgStd: FixtureOrganization;
let adminA: Record<string, string>;
let readerA: Record<string, string>;
let adminB: Record<string, string>;
let adminStd: Record<string, string>;
let integratorA: Record<string, string>;
let domainA1: InsertedDomain;
let domainA2: InsertedDomain;
let domainStd: InsertedDomain;
let connectionA: { id: bigint; publicId: string };
let connectionB: { id: bigint; publicId: string };
let mailboxA: { id: bigint; publicId: string };
let mailboxB: { id: bigint; publicId: string };
let copyA: { publicId: string; messagePublicId: string };
let copyB: { publicId: string };
let subscriptionId: string;

function call(
  who: Record<string, string>,
  method: 'get' | 'post' | 'put',
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

/** A bound Microsoft 365 connection with one linked verified domain (the 8.2 end state). */
async function boundConnection(org: FixtureOrganization, domain: InsertedDomain) {
  const c = await ctx.prisma.providerConnection.create({
    data: {
      organizationId: org.id,
      provider: 'microsoft_365',
      displayName: `Contoso ${randomUUID().slice(0, 6)}`,
      status: 'active',
      externalTenantId: TENANT,
      activeTenantKey: `microsoft_365:${randomUUID()}`,
      tenantVerifiedAt: new Date(),
    },
    select: { id: true, publicId: true },
  });
  await ctx.prisma.providerConnectionDomain.create({
    data: {
      organizationId: org.id,
      connectionId: c.id,
      domainId: domain.id,
      providerVerification: 'verified',
    },
  });
  return c;
}

/** The active mailbox-access grant of a connection (as the integration-worker leaves it). */
async function activeMailboxGrant(org: FixtureOrganization, connectionId: bigint) {
  await ctx.prisma.providerConnectionGrant.create({
    data: {
      organizationId: org.id,
      connectionId,
      profile: 'm365.mailbox_remediation',
      profileVersion: 1,
      authMethod: 'platform_app',
      status: 'active',
      requestedPermissions: ['Mail.ReadWrite', 'User.Read.All'],
      observedPermissions: ['Mail.ReadWrite', 'User.Read.All'],
      verifiedAt: new Date(),
    },
  });
}

/** An API-mode row, one mailbox with an alias and a subscription, and one copy (the worker's). */
async function seedApiMode(
  org: FixtureOrganization,
  connection: { id: bigint },
  domain: InsertedDomain,
  local: string,
) {
  const p = ctx.prisma;
  const api = await p.apiModeConnection.create({
    data: {
      publicId: uuidv7(),
      organizationId: org.id,
      providerConnectionId: connection.id,
      provider: 'microsoft_365',
      inventoryStatus: 'ok',
      mailboxesTotal: 1,
      healthStatus: 'healthy',
      healthChecks: { v: 1, checks: [{ code: 'connection.active', status: 'pass' }] },
    },
    select: { id: true, publicId: true },
  });
  const sub = `it-sub-${randomUUID()}`;
  const mailbox = await p.apiMailbox.create({
    data: {
      publicId: uuidv7(),
      organizationId: org.id,
      apiConnectionId: api.id,
      providerUserId: `user-${randomUUID()}`,
      primaryAddress: `${local}@${domain.name}`,
      domainId: domain.id,
      status: 'active',
      coverageState: 'covered',
      feedStatus: 'active',
      feedCursor: 'https://graph.microsoft.com/v1.0/opaque-delta-link-placeholder',
      subscriptionId: sub,
      clientStateHash: clientStateHash(STATE),
      clientStateVersion: 1,
    },
    select: { id: true, publicId: true },
  });
  await p.apiMailboxAddress.createMany({
    data: [
      {
        organizationId: org.id,
        mailboxId: mailbox.id,
        address: `${local}@${domain.name}`,
        kind: 'primary',
      },
      {
        organizationId: org.id,
        mailboxId: mailbox.id,
        address: `a.${local}@${domain.name}`,
        kind: 'alias',
      },
    ],
  });
  // The copy's registry message (`mailbox_api`, never delivered) and its per-mailbox row.
  const receivedAt = new Date(Date.now() - 45_000);
  const identity = await p.messageIdentity.create({
    data: { organizationId: org.id, ingestKey: `v2:mbx:${sha256(randomUUID())}`, receivedAt },
    select: { id: true, publicId: true },
  });
  await p.emailMessage.create({
    data: {
      id: identity.id,
      receivedAt,
      organizationId: org.id,
      domainId: domain.id,
      direction: 'inbound',
      status: 'journaled',
      statusChangedAt: receivedAt,
      version: 2,
      ingestSource: 'mailbox_api',
      envelopeFrom: 'billing@fabrikam.example',
      headerFrom: 'billing@fabrikam.example',
      subject: 'Invoice overdue',
      internetMessageId: `<${randomUUID()}@fabrikam.example>`,
      sizeBytes: 1024,
      recipientCount: 1,
      attachmentCount: 0,
      emlObjectKey: `org/${org.id}/eml/fixture/${randomUUID()}.eml`,
      emlSha256: sha256('copy'),
    },
  });
  await p.emailRecipient.create({
    data: {
      receivedAt,
      messageId: identity.id,
      organizationId: org.id,
      rcptSeq: 0,
      address: `${local}@${domain.name}`,
      status: 'journaled',
      direction: 'inbound',
    },
  });
  const copyPublicId = uuidv7();
  await p.apiMessageCopy.create({
    data: {
      publicId: copyPublicId,
      receivedAt,
      organizationId: org.id,
      apiConnectionId: api.id,
      mailboxId: mailbox.id,
      messageId: identity.id,
      source: 'graph',
      seenApi: true,
      messageIdHash: sha256(randomUUID()),
      providerMessageId: `AAMk-${randomUUID()}`,
      providerDeliveredAt: new Date(receivedAt.getTime() - 20_000),
      deliveredBasis: 'graph_received',
      status: 'scanned',
      verdict: 'phishing',
      riskScore: 910,
      verdictAt: new Date(receivedAt.getTime() + 5_000),
      lagMs: 25_000,
    },
  });
  await p.apiCopyDedupeKey.create({
    data: {
      organizationId: org.id,
      mailboxId: mailbox.id,
      messageIdHash: sha256(randomUUID()),
      claimedBy: 'graph',
    },
  });
  const hour = new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000);
  await p.apiModeCounter.create({
    data: {
      organizationId: org.id,
      apiConnectionId: api.id,
      hour,
      feedCopies: 1,
      lagCount: 1,
      lagLe60s: 1,
      lagMaxMs: 25_000,
    },
  });
  return {
    api,
    mailbox,
    sub,
    copy: { publicId: copyPublicId, messagePublicId: identity.publicId },
  };
}

beforeAll(async () => {
  ctx = await createIntegrationApp(
    { REDIS_DKIM_URL: '' },
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
  orgA = await fx.createOrganization({ planCode: 'enterprise' });
  orgB = await fx.createOrganization({ planCode: 'enterprise' });
  orgStd = await fx.createOrganization({ planCode: 'standard' });
  const login = async (org: FixtureOrganization, roles: string[]) => {
    const user = await fx.createUser(org, { roles, mfa: true });
    return bearer((await loginWithMfa(ctx, fx, user)).accessToken);
  };
  adminA = await login(orgA, ['organization_admin']);
  readerA = await login(orgA, ['read_only_user']);
  adminB = await login(orgB, ['organization_admin']);
  adminStd = await login(orgStd, ['organization_admin']);
  integratorA = await login(orgA, [
    await fx.createCustomRole(orgA, ['integration:read', 'integration:manage']),
  ]);
  domainA1 = await insertDomain(ctx, orgA, { status: 'verified', label: 'apimode' });
  domainA2 = await insertDomain(ctx, orgA, { status: 'active', label: 'apimx' });
  domainStd = await insertDomain(ctx, orgStd, { status: 'verified', label: 'apistd' });
  const domainB = await insertDomain(ctx, orgB, { status: 'verified', label: 'apimode' });
  // domainA2's latest definitive MX observation points to the gateway (D2 conflict).
  await ctx.prisma.domainMxRecord.create({
    data: {
      organizationId: orgA.id,
      domainId: domainA2.id,
      priority: 10,
      host: 'mx1.gateway.example',
      pointsToGateway: true,
      lastSeenAt: new Date(),
    },
  });
  connectionA = await boundConnection(orgA, domainA1);
  connectionB = await boundConnection(orgB, domainB);
  await activeMailboxGrant(orgA, connectionA.id);
  const a = await seedApiMode(orgA, connectionA, domainA1, 'alex');
  mailboxA = a.mailbox;
  copyA = a.copy;
  subscriptionId = a.sub;
  const b = await seedApiMode(orgB, connectionB, domainB, 'eve');
  mailboxB = b.mailbox;
  copyB = b.copy;

  const apiModePurge = ctx.get(ApiModeTenantDataRepository);
  const intakePurge = ctx.get(JournalIntakeTenantDataRepository);
  const providerPurge = ctx.get(ProviderTenantDataRepository);
  fx.registerCleanup(async () => {
    const orgs = [orgA, orgB, orgStd];
    // API-mode rows and intake sources reference provider connections (RESTRICT).
    for (const org of orgs) await apiModePurge.purgeOrganization(systemScope(org.id));
    for (const org of orgs) await intakePurge.purgeOrganization(systemScope(org.id));
    for (const org of orgs) await providerPurge.purgeOrganization(systemScope(org.id));
    await deleteMessagesData(
      ctx,
      orgs.map((o) => o.id),
    );
    const where = { organizationId: { in: orgs.map((o) => o.id) } };
    await ctx.prisma.auditLog.deleteMany({ where });
  });
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('protection modes on the writer (D1, D2)', () => {
  it('reads the organization block (entitled, not active yet)', async () => {
    const res = await call(
      readerA,
      'get',
      `/api/v1/organizations/${orgA.publicId}/protection-mode`,
    );
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body).toEqual({
      mode: 'inline',
      changedAt: null,
      entitled: true,
      active: false,
      domainsByEffectiveMode: { inline: 2, api: 0, hybrid: 0 },
    });
  });

  it('refuses api while MX points to the gateway; api on the other domain is audited and leaves mail flow alone', async () => {
    const conflict = await call(
      adminA,
      'put',
      `/api/v1/domains/${domainA2.publicId}/protection-mode`,
      {
        mode: 'api',
        reason: REASON,
      },
    );
    expect(conflict.status).toBe(409);
    expect(conflict.body).toMatchObject({
      code: 'protection_mode_mx_points_to_gateway',
      domains: [{ id: domainA2.publicId, name: domainA2.name }],
    });
    const before = await ctx.prisma.domain.findUniqueOrThrow({ where: { id: domainA1.id } });
    const ok = await call(adminA, 'put', `/api/v1/domains/${domainA1.publicId}/protection-mode`, {
      mode: 'api',
      reason: REASON,
    });
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(ok.body.protectionMode).toMatchObject({ configured: 'api', effective: 'api' });
    const after = await ctx.prisma.domain.findUniqueOrThrow({ where: { id: domainA1.id } });
    expect(after.protectionMode).toBe('api');
    expect(after.protectionModeChangedAt).not.toBeNull();
    // N2: the mode never changes inline mail flow.
    expect({ inbound: after.inboundEnabled, outbound: after.outboundEnabled }).toEqual({
      inbound: before.inboundEnabled,
      outbound: before.outboundEnabled,
    });
    const audit = await ctx.prisma.auditLog.findFirstOrThrow({
      where: { organizationId: orgA.id, action: 'domain.protection_mode_changed' },
    });
    expect(audit.resourceId).toBe(domainA1.publicId);
    expect(audit.metadata).toMatchObject({
      fromConfigured: null,
      toConfigured: 'api',
      fromEffective: 'inline',
      toEffective: 'api',
      reason: REASON,
    });
    // The domain and organization views carry the block.
    const domain = await call(readerA, 'get', `/api/v1/domains/${domainA1.publicId}`);
    expect(domain.body.protectionMode).toMatchObject({
      configured: 'api',
      effective: 'api',
      inherited: false,
    });
    const org = await call(readerA, 'get', `/api/v1/organizations/${orgA.publicId}`);
    expect(org.body.protectionMode).toMatchObject({
      mode: 'inline',
      entitled: true,
      active: true,
    });
  });

  it('the organization change checks every inheriting domain, then applies and audits', async () => {
    const refused = await call(
      adminA,
      'put',
      `/api/v1/organizations/${orgA.publicId}/protection-mode`,
      { mode: 'api', reason: REASON },
    );
    expect(refused.status).toBe(409);
    expect(refused.body.domains).toEqual([{ id: domainA2.publicId, name: domainA2.name }]);
    const hybrid = await call(
      adminA,
      'put',
      `/api/v1/organizations/${orgA.publicId}/protection-mode`,
      { mode: 'hybrid', reason: REASON },
    );
    expect(hybrid.status, JSON.stringify(hybrid.body)).toBe(200);
    expect(hybrid.body).toMatchObject({
      mode: 'hybrid',
      changed: true,
      inheritingDomains: 1,
      domainsByEffectiveMode: { inline: 0, api: 1, hybrid: 1 },
    });
    const row = await ctx.prisma.organization.findUniqueOrThrow({ where: { id: orgA.id } });
    expect(row.protectionMode).toBe('hybrid');
    const audit = await ctx.prisma.auditLog.findFirstOrThrow({
      where: { organizationId: orgA.id, action: 'organization.protection_mode_changed' },
    });
    expect(audit.metadata).toMatchObject({
      from: 'inline',
      to: 'hybrid',
      inheritingDomains: 1,
      effectiveApiDomains: 1,
    });
  });

  it('another tenant gets 404; a plan without api_mode_protection gets 403; read-only users 403', async () => {
    expect(
      (await call(adminB, 'get', `/api/v1/organizations/${orgA.publicId}/protection-mode`)).body
        .code,
    ).toBe('organization_not_found');
    const foreign = await call(
      adminB,
      'put',
      `/api/v1/domains/${domainA1.publicId}/protection-mode`,
      {
        mode: 'inline',
        reason: REASON,
      },
    );
    expect(foreign.status).toBe(404);
    const std = await call(
      adminStd,
      'put',
      `/api/v1/domains/${domainStd.publicId}/protection-mode`,
      {
        mode: 'api',
        reason: REASON,
      },
    );
    expect(std.status).toBe(403);
    expect(std.body.code).toBe('api_mode_not_enabled');
    const ro = await call(readerA, 'put', `/api/v1/domains/${domainA1.publicId}/protection-mode`, {
      mode: 'inline',
      reason: REASON,
    });
    expect(ro.status).toBe(403);
  });

  it('POST /domains with protectionMode api creates the domain with inbound off', async () => {
    const res = await call(
      adminA,
      'post',
      '/api/v1/domains',
      { name: `apinew-${randomUUID().slice(0, 8)}.example.com`, protectionMode: 'api' },
      false,
    );
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(res.body).toMatchObject({
      inboundEnabled: false,
      protectionMode: { configured: 'api', effective: 'api', inherited: false },
    });
    const row = await ctx.prisma.domain.findFirstOrThrow({ where: { publicId: res.body.id } });
    expect(row.protectionMode).toBe('api');
    const conflict = await call(
      adminA,
      'post',
      '/api/v1/domains',
      {
        name: `apibad-${randomUUID().slice(0, 8)}.example.com`,
        protectionMode: 'api',
        inboundEnabled: true,
      },
      false,
    );
    expect(conflict.status).toBe(422);
    expect(conflict.body.code).toBe('protection_mode_inbound_conflict');
  });
});

describe('API-mode connections, mailboxes and detections (D10-D12)', () => {
  it('overview and connections come from the rows; never a cursor, subscription id or client state', async () => {
    const overview = await eventually(
      () => call(readerA, 'get', `${BASE}/overview`),
      (r) => r.status === 200 && r.body.active === true,
    );
    expect(overview.body).toMatchObject({
      entitled: true,
      active: true,
      organizationMode: 'hybrid',
      coverage: { covered: 1, gap: 0, total: 1, percent: 100 },
      copiesToday: 1,
    });
    const list = await call(readerA, 'get', `${BASE}/connections`);
    expect(list.body.data).toHaveLength(1);
    expect(list.body.data[0]).toMatchObject({
      id: connectionA.publicId,
      bound: true,
      grant: { profile: 'm365.mailbox_remediation', status: 'active' },
      rowVersion: 1,
    });
    const detail = await call(readerA, 'get', `${BASE}/connections/${connectionA.publicId}`);
    expect(detail.status).toBe(200);
    expect(
      detail.body.wizard.steps.find((s: { step: string }) => s.step === 'mailbox_access'),
    ).toMatchObject({ status: 'done' });
    expect(detail.body.healthChecks).toEqual([
      { code: 'connection.active', status: 'pass', evidence: null },
    ]);
    const mailbox = await call(readerA, 'get', `${BASE}/mailboxes/${mailboxA.publicId}`);
    for (const body of [overview.body, list.body, detail.body, mailbox.body]) {
      const text = JSON.stringify(body);
      expect(text).not.toContain(subscriptionId);
      expect(text).not.toContain(clientStateHash(STATE));
      expect(text).not.toContain('opaque-delta-link');
    }
    const guide = await call(
      readerA,
      'get',
      `${BASE}/connections/${connectionA.publicId}/setup-guide`,
    );
    expect(guide.body).toMatchObject({ schema: 'api-mode-guide/1', provider: 'microsoft_365' });
    const md = await ctx.http
      .get(`${BASE}/connections/${connectionA.publicId}/setup-guide?format=markdown`)
      .set(readerA)
      .set('X-Forwarded-For', uniqueIp());
    expect(md.headers['content-type']).toMatch(/^text\/markdown/);
  });

  it('settings: the lazily created row, CAS, notify with the platform URL, pending mailboxes, audit', async () => {
    const put = (body: object) =>
      call(adminA, 'put', `${BASE}/connections/${connectionA.publicId}/settings`, body);
    const stale = await put({ feedsEnabled: true, expectedRowVersion: 7 });
    expect(stale.status).toBe(409);
    expect(stale.body).toMatchObject({
      code: 'api_mode_connection_conflict',
      currentRowVersion: 1,
    });
    const mode = ctx.config.API_MODE_GRAPH_NOTIFICATION_URL === undefined ? 'poll' : 'notify';
    const ok = await put({ feedsEnabled: true, feedMode: mode, expectedRowVersion: 1 });
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(ok.body).toMatchObject({ feedsEnabled: true, feedMode: mode, rowVersion: 2 });
    const row = await ctx.prisma.apiModeConnection.findUniqueOrThrow({
      where: { providerConnectionId: connectionA.id },
    });
    expect(row).toMatchObject({ feedsEnabled: true, feedMode: mode, rowVersion: 2 });
    expect(row.feedsEnabledAt).not.toBeNull();
    const mailbox = await ctx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: mailboxA.id } });
    expect(mailbox.feedStatus).toBe('pending');
    expect(mailbox.nextSyncAt).not.toBeNull();
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: orgA.id, action: 'api_mode.settings_updated' },
      }),
    ).toBe(1);
    // Restore the feed status the callbacks below expect.
    await ctx.prisma.apiMailbox.update({
      where: { id: mailboxA.id },
      data: { feedStatus: 'active' },
    });
  });

  it('inventory sync and resync are 202 requests on the writer, audited', async () => {
    const inv = await call(
      adminA,
      'post',
      `${BASE}/connections/${connectionA.publicId}/inventory-sync`,
    );
    expect(inv.status, JSON.stringify(inv.body)).toBe(202);
    const row = await ctx.prisma.apiModeConnection.findUniqueOrThrow({
      where: { providerConnectionId: connectionA.id },
    });
    expect(row.inventoryRequestedAt).not.toBeNull();
    expect(row.rowVersion).toBe(2);
    const resync = await call(adminA, 'post', `${BASE}/mailboxes/${mailboxA.publicId}/resync`);
    expect(resync.status).toBe(202);
    const mailbox = await ctx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: mailboxA.id } });
    expect(mailbox.feedCursor).toBeNull();
    expect(mailbox.syncRequestedAt).not.toBeNull();
    const actions = await ctx.prisma.auditLog.findMany({
      where: { organizationId: orgA.id, action: { startsWith: 'api_mode.' } },
      select: { action: true },
      orderBy: { id: 'asc' },
    });
    expect(actions.map((a) => a.action)).toEqual([
      'api_mode.settings_updated',
      'api_mode.inventory_sync_requested',
      'api_mode.mailbox_resync_requested',
    ]);
    // Read-only users cannot write.
    expect(
      (await call(readerA, 'post', `${BASE}/mailboxes/${mailboxA.publicId}/resync`)).status,
    ).toBe(403);
    await ctx.prisma.apiMailbox.update({
      where: { id: mailboxA.id },
      data: { syncRequestedAt: null },
    });
  });

  it('mailboxes and detections from the replica: alias prefix, masked copies, cursors', async () => {
    const mailboxes = await eventually(
      () => call(readerA, 'get', `${BASE}/mailboxes?q=a.alex`),
      (r) => r.status === 200 && (r.body.data as unknown[]).length === 1,
    );
    expect(mailboxes.body.data[0]).toMatchObject({
      id: mailboxA.publicId,
      connectionId: connectionA.publicId,
      domain: { id: domainA1.publicId, name: domainA1.name },
    });
    const detections = await call(readerA, 'get', `${BASE}/detections?verdict=phishing`);
    expect(detections.body.data).toHaveLength(1);
    expect(detections.body.data[0]).toMatchObject({
      id: copyA.publicId,
      mailboxId: mailboxA.publicId,
      source: 'graph',
      seenApi: true,
      verdict: 'phishing',
      riskScore: 910,
      lagMs: 25_000,
      subject: null,
      subjectMasked: true,
      headerFrom: 'b***@fabrikam.example',
    });
    expect(JSON.stringify(detections.body)).not.toContain('Invoice overdue');
    const detail = await call(readerA, 'get', `${BASE}/detections/${copyA.publicId}`);
    expect(detail.body).toMatchObject({
      direction: 'inbound',
      deliveredBasis: 'graph_received',
      reasonCodes: [],
    });
    const paged = await call(readerA, 'get', `${BASE}/mailboxes?limit=1`);
    expect(paged.body.nextCursor).toBeNull();
  });

  it('another organization’s connection, mailbox and detection are 404; lists never show them', async () => {
    for (const [path, code] of [
      [`${BASE}/connections/${connectionB.publicId}`, 'api_mode_connection_not_found'],
      [`${BASE}/mailboxes/${mailboxB.publicId}`, 'api_mode_mailbox_not_found'],
      [`${BASE}/detections/${copyB.publicId}`, 'api_mode_detection_not_found'],
    ] as const) {
      const res = await call(adminA, 'get', path);
      expect(res.status, path).toBe(404);
      expect(res.body.code, path).toBe(code);
    }
    expect(
      (await call(adminA, 'post', `${BASE}/mailboxes/${mailboxB.publicId}/resync`)).status,
    ).toBe(404);
    const all = await call(adminA, 'get', `${BASE}/detections`);
    expect(all.body.data.map((d: { id: string }) => d.id)).not.toContain(copyB.publicId);
  });
});

describe('public Graph callbacks on the writer (D12.4)', () => {
  it('echoes the handshake; a matching item sets sync_requested_at once (coalescing); mismatches change nothing', async () => {
    const echo = await ctx.http
      .post(`${GRAPH}?validationToken=it-token-1`)
      .set('X-Forwarded-For', uniqueIp());
    expect(echo.status).toBe(200);
    expect(echo.text).toBe('it-token-1');
    const item = { subscriptionId, clientState: STATE, changeType: 'created', tenantId: TENANT };
    const wrong = await ctx.http
      .post(GRAPH)
      .set('X-Forwarded-For', uniqueIp())
      .send({ value: [{ ...item, clientState: 'not-the-client-state' }] });
    expect(wrong.status).toBe(202);
    expect(
      (await ctx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: mailboxA.id } }))
        .syncRequestedAt,
    ).toBeNull();
    const ok = await ctx.http
      .post(GRAPH)
      .set('X-Forwarded-For', uniqueIp())
      .send({ value: [item] });
    expect(ok.status).toBe(202);
    const first = (await ctx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: mailboxA.id } }))
      .syncRequestedAt;
    expect(first).not.toBeNull();
    await new Promise((r) => setTimeout(r, 20));
    await ctx.http
      .post(GRAPH)
      .set('X-Forwarded-For', uniqueIp())
      .send({ value: [item, item] });
    const second = (await ctx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: mailboxA.id } }))
      .syncRequestedAt;
    expect(second!.getTime()).toBe(first!.getTime());
    // A lifecycle event forces the renewal.
    const life = await ctx.http
      .post(`${GRAPH}/lifecycle`)
      .set('X-Forwarded-For', uniqueIp())
      .send({
        value: [{ ...item, changeType: undefined, lifecycleEvent: 'reauthorizationRequired' }],
      });
    expect(life.status).toBe(202);
    const after = await ctx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: mailboxA.id } });
    expect(after.subscriptionExpiresAt).not.toBeNull();
    expect(after.subscriptionId).toBe(subscriptionId);
  });
});

describe('the remediation:write gate of mailbox-access grants (D4)', () => {
  it('refuses a mailbox_remediation grant without remediation:write; the mail-flow profile is unaffected', async () => {
    const refused = await call(
      integratorA,
      'post',
      `/api/v1/provider-connections/${connectionA.publicId}/grants`,
      {
        profile: 'm365.mailbox_remediation',
        authMethod: 'customer_app_secret',
      },
    );
    expect(refused.status).toBe(403);
    expect(refused.body.code).toBe('remediation_permission_required');
    const revoke = await call(
      integratorA,
      'post',
      `/api/v1/provider-connections/${connectionA.publicId}/grants/m365.mailbox_remediation/verify`,
      {},
    );
    expect(revoke.body.code).toBe('remediation_permission_required');
    // An API key with integration:manage only is refused the same way.
    const key = await fx.createApiKey(orgA, ['integration:read', 'integration:manage']);
    const byKey = await call(
      apiKeyHeader(key),
      'post',
      `/api/v1/provider-connections/${connectionB.publicId}/grants`,
      { profile: 'm365.mailbox_remediation', authMethod: 'customer_app_secret' },
    );
    expect(byKey.status).toBe(403);
    expect(byKey.body.code).toBe('remediation_permission_required');
    // organization_admin holds remediation:write: the gate lets the existing-grant rule answer.
    const admin = await call(
      adminA,
      'post',
      `/api/v1/provider-connections/${connectionA.publicId}/grants`,
      {
        profile: 'm365.mailbox_remediation',
        authMethod: 'customer_app_secret',
      },
    );
    expect(admin.status).toBe(409);
    expect(admin.body.code).toBe('grant_exists');
  });
});

describe('journal intake entitled by API mode (D6)', () => {
  it('creates a source without archiving once API mode is active', async () => {
    // orgA has no archive settings: before 8.6 rules it would be 409 archiving_not_enabled.
    expect(await ctx.prisma.archiveSetting.count({ where: { organizationId: orgA.id } })).toBe(0);
    const res = await call(adminA, 'post', '/api/v1/journaling/intake-sources', {
      kind: 'microsoft_365_journal',
      displayName: 'API-mode journal',
      providerConnectionId: connectionA.publicId,
    });
    if (ctx.config.JOURNAL_INTAKE_DOMAIN === undefined) {
      expect(res.status).toBe(503);
      return;
    }
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    const wizard = await eventually(
      () => call(adminA, 'get', `/api/v1/journaling/intake-sources/${res.body.source.id}/wizard`),
      (r) => r.status === 200,
    );
    expect(wizard.body.steps[0]).toEqual({
      step: 'archiving',
      status: 'skipped',
      blockers: [],
      reason: 'api_mode',
    });
    // The standard plan has neither archiving entitled+enabled nor API mode.
    const std = await call(adminStd, 'post', '/api/v1/journaling/intake-sources', {
      kind: 'smtp_bcc',
      displayName: 'No API mode',
      networks: ['198.51.100.16/28'],
    });
    expect([403, 409]).toContain(std.status);
  });
});

describe('API-mode copies stay out of the gateway views (D7.7, R6)', () => {
  it('explorer, detail and reports exclude the copy; usage counts it in apiCopiesToday', async () => {
    const gateway = await seedMessage(ctx, orgA, { domainId: domainA1.id });
    const list = await eventually(
      () => call(readerA, 'get', '/api/v1/messages'),
      (r) =>
        r.status === 200 &&
        (r.body.data as Array<{ id: string }>).some((m) => m.id === gateway.publicId),
    );
    const ids = (list.body.data as Array<{ id: string }>).map((m) => m.id);
    expect(ids).not.toContain(copyA.messagePublicId);
    const detail = await call(adminA, 'get', `/api/v1/messages/${copyA.messagePublicId}`);
    expect(detail.status).toBe(404);
    expect(detail.body.code).toBe('message_not_found');
    const from = new Date(
      Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate()),
    );
    const to = new Date(from.getTime() + 86_400_000);
    const traffic = await eventually(
      () =>
        call(
          adminA,
          'get',
          `/api/v1/reports/traffic?from=${encodeURIComponent(from.toISOString())}` +
            `&to=${encodeURIComponent(to.toISOString())}&granularity=day`,
        ),
      (r) => r.status === 200 && r.body.totals.total >= 1,
    );
    expect(traffic.body.totals.total).toBe(1);
    const usage = await eventually(
      () => call(adminA, 'get', `/api/v1/organizations/${orgA.publicId}/usage`),
      (r) => r.status === 200 && r.body.messages.apiCopiesToday === 1,
    );
    expect(usage.body.messages).toMatchObject({ today: 1, apiCopiesToday: 1 });
  });
});

describe('organization purge of the API-mode tables (§3.2)', () => {
  it('deletes the six tables of one organization in FK-safe order and nothing else', async () => {
    const purge = ctx.get(ApiModeTenantDataRepository);
    const counts = await purge.purgeOrganization(systemScope(orgB.id), 1);
    expect(counts).toEqual({
      // Step API-2 §3.4: the remediation tables go first (none seeded here; see
      // integration/api-mode-remediation.test.ts).
      api_remediation_actions: 0,
      api_remediation_policies: 0,
      api_message_copies: 1,
      api_copy_dedupe_keys: 1,
      api_mailbox_addresses: 2,
      api_mailboxes: 1,
      api_mode_counters: 1,
      api_mode_connections: 1,
    });
    const p = ctx.prisma;
    const byB = { where: { organizationId: orgB.id } };
    expect(
      await Promise.all([
        p.apiMessageCopy.count(byB),
        p.apiCopyDedupeKey.count(byB),
        p.apiMailboxAddress.count(byB),
        p.apiMailbox.count(byB),
        p.apiModeCounter.count(byB),
        p.apiModeConnection.count(byB),
      ]),
    ).toEqual([0, 0, 0, 0, 0, 0]);
    expect(await p.apiMailbox.count({ where: { organizationId: orgA.id } })).toBe(1);
    // A re-run is a no-op.
    expect(Object.values(await purge.purgeOrganization(systemScope(orgB.id)))).toEqual([
      0, 0, 0, 0, 0, 0, 0, 0,
    ]);
  });
});
