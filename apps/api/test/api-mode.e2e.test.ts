/**
 * The step API-1 API-mode routes (docs/plan/steps/35-api-mode-protection.md D1, D2, D10, D12,
 * §9.4) over HTTP with MySQL, Redis and S3 stubbed: the API-mode repository, the API-mode status
 * and the feature lookup through `ApiModeWorld`, the Idempotency-Key store and the audit in
 * memory. For every operation: success, 401, 403 without its permission (a read-only user on
 * every write), 404 for another organization's ids; then the protection-mode rules (entitlement,
 * MX conflict incl. the organization fan-out, inherit, unchanged = no audit), Idempotency-Key
 * replay, CAS, the feeds rules, inventory and resync requests, v1 cursors, masking of subjects
 * and senders, the views never carrying cursors, subscription ids or client state, the setup
 * guide (JSON and Markdown), and the public Graph callbacks (validation echo, 202 without
 * credentials, client-state/tenant checks, 413, 429, the metric). The real writer and replica
 * run in integration/api-mode.test.ts.
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
import { randomUUID } from 'node:crypto';
import { clientStateHash } from '@email-gateway/mailbox-api';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AuditService } from '../src/audit/audit.service';
import { API_MODE_EXAMPLES } from '../src/modules/api-mode/dto/api-mode.schemas';
import { ApiModeWorld, overrideApiMode, type StoredConnection } from './support/api-mode-fixtures';
import {
  createStubbedApiApp,
  InMemoryIdempotencyStore,
  type StubbedApiApp,
} from './support/api-test-app';
import { RecordingAuditService } from './support/messages-fixtures';

const READ = 'remediation:read';
const WRITE = 'remediation:write';
const ORG_READ = 'organization:read';
const ORG_MANAGE = 'organization:manage';
const DOMAIN_MANAGE = 'domain:manage';
const ALL = [READ, WRITE, ORG_READ, ORG_MANAGE, DOMAIN_MANAGE];
const BASE = '/api/v1/api-mode';
const OTHER_ORG = 2n;
const STATE = 'example-client-state-for-e2e-tests-only-0000';
const TENANT = '11111111-2222-3333-4444-555555555555';
const REASON = 'Protect the tenant without an MX change';

type Method = 'get' | 'post' | 'put';

interface Ctx {
  orgId: string;
  foreignOrgId: string;
  domain: string;
  mxDomain: string;
  foreignDomain: string;
  connection: string;
  google: string;
  foreignConnection: string;
  mailbox: string;
  foreignMailbox: string;
  detection: string;
  foreignDetection: string;
}

interface Spec {
  id: string;
  method: Method;
  path: (c: Ctx) => string;
  all?: string[];
  any?: string[];
  keyed?: boolean;
  body?: (c: Ctx) => object;
  ok: number;
}

const SPECS: Spec[] = [
  {
    id: 'org.get',
    method: 'get',
    path: (c) => `/api/v1/organizations/${c.orgId}/protection-mode`,
    any: [ORG_READ, 'platform:organizations'],
    ok: 200,
  },
  {
    id: 'org.put',
    method: 'put',
    path: (c) => `/api/v1/organizations/${c.orgId}/protection-mode`,
    any: [ORG_MANAGE, 'platform:organizations'],
    keyed: true,
    body: () => ({ mode: 'hybrid', reason: REASON }),
    ok: 200,
  },
  {
    id: 'domain.put',
    method: 'put',
    path: (c) => `/api/v1/domains/${c.domain}/protection-mode`,
    all: [DOMAIN_MANAGE],
    keyed: true,
    body: () => ({ mode: 'api', reason: REASON }),
    ok: 200,
  },
  { id: 'overview', method: 'get', path: () => `${BASE}/overview`, all: [READ], ok: 200 },
  { id: 'connections', method: 'get', path: () => `${BASE}/connections`, all: [READ], ok: 200 },
  {
    id: 'connection',
    method: 'get',
    path: (c) => `${BASE}/connections/${c.connection}`,
    all: [READ],
    ok: 200,
  },
  {
    id: 'guide',
    method: 'get',
    path: (c) => `${BASE}/connections/${c.connection}/setup-guide`,
    all: [READ],
    ok: 200,
  },
  {
    id: 'settings',
    method: 'put',
    path: (c) => `${BASE}/connections/${c.connection}/settings`,
    all: [WRITE],
    keyed: true,
    body: () => ({ feedsEnabled: true, feedMode: 'poll', expectedRowVersion: 1 }),
    ok: 200,
  },
  {
    id: 'inventory',
    method: 'post',
    path: (c) => `${BASE}/connections/${c.connection}/inventory-sync`,
    all: [WRITE],
    keyed: true,
    ok: 202,
  },
  { id: 'mailboxes', method: 'get', path: () => `${BASE}/mailboxes`, all: [READ], ok: 200 },
  {
    id: 'mailbox',
    method: 'get',
    path: (c) => `${BASE}/mailboxes/${c.mailbox}`,
    all: [READ],
    ok: 200,
  },
  {
    id: 'resync',
    method: 'post',
    path: (c) => `${BASE}/mailboxes/${c.mailbox}/resync`,
    all: [WRITE],
    keyed: true,
    ok: 202,
  },
  { id: 'detections', method: 'get', path: () => `${BASE}/detections`, all: [READ], ok: 200 },
  {
    id: 'detection',
    method: 'get',
    path: (c) => `${BASE}/detections/${c.detection}`,
    all: [READ],
    ok: 200,
  },
];

describe('API-mode routes (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new ApiModeWorld();
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();
  let org: bigint;
  let ctx: Ctx;
  let m365: StoredConnection;

  beforeAll(async () => {
    api = await createStubbedApiApp(
      { API_MODE_NOTIFICATION_RATE_PER_MINUTE: '1000' },
      {
        override: (b) =>
          store.override(overrideApiMode(b, world).overrideProvider(AuditService).useValue(audit)),
      },
    );
    org = api.principals.organizationId;
  });

  afterAll(async () => {
    await api?.close();
  });

  function seed(): Ctx {
    const foreignOrgId = randomUUID();
    world.addOrganization(org, api.principals.ids.org);
    world.addOrganization(OTHER_ORG, foreignOrgId);
    world.entitled.add(org);
    m365 = world.addConnection(org, {
      displayName: 'Contoso Microsoft 365',
      grant: {
        profile: 'm365.mailbox_remediation',
        status: 'active',
        authMethod: 'platform_app',
        clientId: null,
        subjectEmail: null,
      },
      journalSources: [
        {
          publicId: randomUUID(),
          displayName: 'Contoso journal',
          kind: 'microsoft_365_journal',
          status: 'active',
          healthStatus: 'healthy',
          verifiedAt: new Date(),
          addressVersion: 1,
        },
      ],
    });
    m365.api = world.apiRow({ healthStatus: 'healthy', inventoryStatus: 'ok', mailboxesTotal: 2 });
    const google = world.addConnection(org, {
      displayName: 'Contoso Google',
      provider: 'google_workspace',
      externalTenantId: 'C0123abc',
      activeTenantKey: 'google_workspace:C0123abc',
    });
    const foreignConnection = world.addConnection(OTHER_ORG, { displayName: 'Other' });
    const domain = world.addDomain(org, 'contoso.example', { connectionId: m365.id });
    const mxDomain = world.addDomain(org, 'mx.contoso.example', { mxPointsToGateway: true });
    const foreignDomain = world.addDomain(OTHER_ORG, 'other.example');
    const mailbox = world.addMailbox(m365, 'alex@contoso.example', {
      aliases: ['a.smith@contoso.example'],
      feedStatus: 'active',
      subscriptionId: 'sub-alex-0001',
      clientStateHash: clientStateHash(STATE),
      feedCursor: 'https://graph.example/delta?token=opaque',
    });
    world.addMailbox(m365, 'blair@contoso.example', { coverageState: 'gap' });
    const foreignMailbox = world.addMailbox(foreignConnection, 'eve@other.example');
    const detection = world.addCopy(mailbox, {
      verdict: 'phishing',
      riskScore: 870,
      receivedAt: new Date(Date.now() - 120_000),
    });
    world.reasonCodes.set(
      detection.messageId.toString(),
      Array.from({ length: 12 }, (_, i) => `code.${i}`),
    );
    world.addCopy(mailbox, { receivedAt: new Date(Date.now() - 90_000), subject: null });
    const foreignDetection = world.addCopy(foreignMailbox);
    world.counters.push({
      organizationId: org,
      apiConnectionId: m365.api.id,
      hour: new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000),
      journalCopies: 3,
      feedCopies: 1,
      duplicates: 1,
      skippedInternal: 0,
      tooLarge: 0,
      providerRequests: 5,
      throttled429: 1,
      throttled503: 0,
      providerErrors: 0,
      cursorResets: 0,
      lagCount: 4,
      lagLe60s: 3,
      lagLe300s: 1,
      lagLe900s: 0,
      lagLe3600s: 0,
      lagGt3600s: 0,
      lagMaxMs: 120_000,
    });
    return {
      orgId: api.principals.ids.org,
      foreignOrgId,
      domain: domain.publicId,
      mxDomain: mxDomain.publicId,
      foreignDomain: foreignDomain.publicId,
      connection: m365.publicId,
      google: google.publicId,
      foreignConnection: foreignConnection.publicId,
      mailbox: mailbox.publicId,
      foreignMailbox: foreignMailbox.publicId,
      detection: detection.publicId,
      foreignDetection: foreignDetection.publicId,
    };
  }

  beforeEach(() => {
    world.reset();
    audit.entries.length = 0;
    store.rows.clear();
    api.kv.entries.clear();
    api.principals.apiKeyWith([]);
    ctx = seed();
  });

  const asUser = (permissions: string[]) => api.principals.user(permissions).bearer();

  async function send(
    spec: Spec,
    options: { perms?: string[] | null; apiKey?: string[]; key?: string; body?: object } = {},
  ) {
    const req = api.http()[spec.method](spec.path(ctx));
    if (options.apiKey) {
      api.principals.apiKeyWith(options.apiKey);
      req.set(api.principals.apiKeyHeaders);
    } else if (options.perms !== null) {
      req.set(await asUser(options.perms ?? ALL));
    }
    if (spec.keyed) req.set('Idempotency-Key', options.key ?? randomUUID());
    const body = options.body ?? spec.body?.(ctx);
    return body === undefined ? req : req.send(body);
  }

  const spec = (id: string) => SPECS.find((s) => s.id === id)!;

  describe('every operation (success, auth, RBAC)', () => {
    it.each(SPECS.map((s) => [s.id, s] as const))(
      '%s succeeds with its permission',
      async (_id, s) => {
        const res = await send(s, { perms: s.all ?? [s.any![0]!] });
        expect(res.status, JSON.stringify(res.body)).toBe(s.ok);
      },
    );

    it.each(SPECS.map((s) => [s.id, s] as const))(
      '%s answers 401 without credentials',
      async (_id, s) => {
        expect((await send(s, { perms: null })).status).toBe(401);
      },
    );

    it.each(SPECS.map((s) => [s.id, s] as const))(
      '%s answers 403 without its permission',
      async (_id, s) => {
        const held = ALL.filter((p) => !(s.all ?? s.any ?? []).includes(p));
        const res = await send(s, { perms: held });
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('forbidden');
      },
    );

    it('a read-only user (the tenant read set) is refused every write', async () => {
      const readOnly = [READ, ORG_READ, 'domain:read', 'integration:read'];
      for (const s of SPECS) {
        const res = await send(s, { perms: readOnly });
        if (s.method === 'get') expect(res.status, s.id).toBe(s.ok);
        else expect(res.status, s.id).toBe(403);
      }
    });

    it('API keys with remediation:* use the API-mode routes', async () => {
      for (const s of SPECS.filter((x) => x.all?.includes(READ) || x.all?.includes(WRITE))) {
        world.reset();
        store.rows.clear();
        ctx = seed();
        const res = await send(s, { apiKey: [READ, WRITE] });
        expect(res.status, `${s.id} ${JSON.stringify(res.body)}`).toBe(s.ok);
      }
    });

    it('another organization’s ids answer 404 like unknown ids (tenant from the credential)', async () => {
      const cases: Array<[Method, string, string, object?]> = [
        [
          'get',
          `/api/v1/organizations/${ctx.foreignOrgId}/protection-mode`,
          'organization_not_found',
        ],
        [
          'put',
          `/api/v1/organizations/${ctx.foreignOrgId}/protection-mode`,
          'organization_not_found',
          { mode: 'inline', reason: REASON },
        ],
        [
          'put',
          `/api/v1/domains/${ctx.foreignDomain}/protection-mode`,
          'domain_not_found',
          { mode: 'inline', reason: REASON },
        ],
        ['get', `${BASE}/connections/${ctx.foreignConnection}`, 'api_mode_connection_not_found'],
        [
          'get',
          `${BASE}/connections/${ctx.foreignConnection}/setup-guide`,
          'api_mode_connection_not_found',
        ],
        [
          'put',
          `${BASE}/connections/${ctx.foreignConnection}/settings`,
          'api_mode_connection_not_found',
          { feedsEnabled: false, expectedRowVersion: 1 },
        ],
        [
          'post',
          `${BASE}/connections/${ctx.foreignConnection}/inventory-sync`,
          'api_mode_connection_not_found',
        ],
        ['get', `${BASE}/mailboxes/${ctx.foreignMailbox}`, 'api_mode_mailbox_not_found'],
        ['post', `${BASE}/mailboxes/${ctx.foreignMailbox}/resync`, 'api_mode_mailbox_not_found'],
        ['get', `${BASE}/detections/${ctx.foreignDetection}`, 'api_mode_detection_not_found'],
        ['get', `${BASE}/detections/${randomUUID()}`, 'api_mode_detection_not_found'],
      ];
      for (const [method, path, code, body] of cases) {
        const req = api
          .http()
          [method](path)
          .set(await asUser(ALL));
        if (method !== 'get') req.set('Idempotency-Key', randomUUID());
        const res = await (body ? req.send(body) : req);
        expect(res.status, path).toBe(404);
        expect(res.body.code, path).toBe(code);
      }
      // Lists never show another organization's rows.
      const mailboxes = await api
        .http()
        .get(`${BASE}/mailboxes`)
        .set(await asUser(ALL));
      expect(mailboxes.body.data.map((m: { id: string }) => m.id)).not.toContain(
        ctx.foreignMailbox,
      );
      const detections = await api
        .http()
        .get(`${BASE}/detections`)
        .set(await asUser(ALL));
      expect(detections.body.data.map((d: { id: string }) => d.id)).not.toContain(
        ctx.foreignDetection,
      );
      // Ids are validated before any read.
      const bad = await api
        .http()
        .get(`${BASE}/connections/not-a-uuid`)
        .set(await asUser(ALL));
      expect(bad.status).toBe(400);
    });
  });

  describe('protection modes (D1, D2)', () => {
    it('reads the organization block and changes it with an audit row; unchanged = no audit', async () => {
      const get = await send(spec('org.get'));
      expect(get.body).toEqual({
        mode: 'inline',
        changedAt: null,
        entitled: true,
        active: false,
        domainsByEffectiveMode: { inline: 2, api: 0, hybrid: 0 },
      });
      const key = randomUUID();
      const put = await send(spec('org.put'), { key });
      expect(put.status).toBe(200);
      expect(put.body).toMatchObject({
        organizationId: ctx.orgId,
        mode: 'hybrid',
        changed: true,
        active: true,
        inheritingDomains: 2,
        domainsByEffectiveMode: { inline: 0, api: 0, hybrid: 2 },
      });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]).toMatchObject({
        organizationId: org,
        action: 'organization.protection_mode_changed',
        resourceType: 'organization',
        resourceId: ctx.orgId,
        metadata: {
          from: 'inline',
          to: 'hybrid',
          reason: REASON,
          inheritingDomains: 2,
          effectiveApiDomains: 0,
        },
      });
      // The same key replays the stored response without a second change or audit row.
      const replay = await send(spec('org.put'), { key });
      expect(replay.status).toBe(200);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body).toEqual(put.body);
      // The same value with a new key: 200, unchanged, no audit row.
      const again = await send(spec('org.put'));
      expect(again.body).toMatchObject({ mode: 'hybrid', changed: false });
      expect(audit.entries).toHaveLength(1);
    });

    it('needs an Idempotency-Key and a 1-500 character reason', async () => {
      const noKey = await api
        .http()
        .put(`/api/v1/organizations/${ctx.orgId}/protection-mode`)
        .set(await asUser(ALL))
        .send({ mode: 'hybrid', reason: REASON });
      expect(noKey.status).toBe(400);
      expect(noKey.body.code).toBe('idempotency_key_required');
      for (const reason of ['', '   ', 'x'.repeat(501)]) {
        const res = await send(spec('org.put'), { body: { mode: 'hybrid', reason } });
        expect(res.status, reason).toBe(400);
      }
      expect(
        (await send(spec('domain.put'), { body: { mode: 'sideways', reason: REASON } })).status,
      ).toBe(400);
      expect(audit.entries).toHaveLength(0);
    });

    it('api and hybrid need api_mode_protection; inline is always allowed', async () => {
      world.entitled.delete(org);
      for (const mode of ['api', 'hybrid']) {
        const res = await send(spec('domain.put'), { body: { mode, reason: REASON } });
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('api_mode_not_enabled');
      }
      const org403 = await send(spec('org.put'));
      expect(org403.body.code).toBe('api_mode_not_enabled');
      const inline = await send(spec('domain.put'), { body: { mode: 'inline', reason: REASON } });
      expect(inline.status).toBe(200);
      expect(inline.body.protectionMode).toEqual(
        expect.objectContaining({ configured: 'inline', effective: 'inline', inherited: false }),
      );
    });

    it('refuses effective api while MX points to the gateway (domain and organization fan-out)', async () => {
      const domain = await api
        .http()
        .put(`/api/v1/domains/${ctx.mxDomain}/protection-mode`)
        .set(await asUser(ALL))
        .set('Idempotency-Key', randomUUID())
        .send({ mode: 'api', reason: REASON });
      expect(domain.status).toBe(409);
      expect(domain.body).toMatchObject({
        code: 'protection_mode_mx_points_to_gateway',
        domains: [{ id: ctx.mxDomain, name: 'mx.contoso.example' }],
      });
      const orgWide = await send(spec('org.put'), { body: { mode: 'api', reason: REASON } });
      expect(orgWide.status).toBe(409);
      expect(orgWide.body.domains).toEqual([{ id: ctx.mxDomain, name: 'mx.contoso.example' }]);
      // Hybrid keeps inline filtering: allowed with MX at the gateway.
      const hybrid = await api
        .http()
        .put(`/api/v1/domains/${ctx.mxDomain}/protection-mode`)
        .set(await asUser(ALL))
        .set('Idempotency-Key', randomUUID())
        .send({ mode: 'hybrid', reason: REASON });
      expect(hybrid.status).toBe(200);
      // With its own mode the MX domain no longer follows the organization: api is accepted.
      const now = await send(spec('org.put'), { body: { mode: 'api', reason: REASON } });
      expect(now.status).toBe(200);
      expect(now.body).toMatchObject({
        mode: 'api',
        inheritingDomains: 1,
        domainsByEffectiveMode: { inline: 0, api: 1, hybrid: 1 },
      });
      expect(audit.entries.map((e) => e.action)).toEqual([
        'domain.protection_mode_changed',
        'organization.protection_mode_changed',
      ]);
      expect(audit.entries[1]!.metadata).toMatchObject({ effectiveApiDomains: 1 });
    });

    it('a domain change and inherit report configured and effective modes with an audit row', async () => {
      const api1 = await send(spec('domain.put'));
      expect(api1.body).toMatchObject({
        domainId: ctx.domain,
        name: 'contoso.example',
        changed: true,
        protectionMode: { configured: 'api', effective: 'api', inherited: false },
      });
      expect(audit.entries.at(-1)).toMatchObject({
        action: 'domain.protection_mode_changed',
        resourceType: 'domain',
        resourceId: ctx.domain,
        metadata: {
          fromConfigured: null,
          toConfigured: 'api',
          fromEffective: 'inline',
          toEffective: 'api',
          reason: REASON,
        },
      });
      const inherit = await send(spec('domain.put'), { body: { mode: 'inherit', reason: REASON } });
      expect(inherit.body.protectionMode).toMatchObject({
        configured: null,
        effective: 'inline',
        inherited: true,
      });
      const same = await send(spec('domain.put'), { body: { mode: 'inherit', reason: REASON } });
      expect(same.body.changed).toBe(false);
      expect(audit.entries).toHaveLength(2);
    });
  });

  describe('API-mode views (D12 #4-#7)', () => {
    it('overview: coverage, health, lag and throttling from the rows and counters', async () => {
      world.domains[0]!.configured = 'api';
      const res = await send(spec('overview'));
      expect(res.body).toMatchObject({
        entitled: true,
        active: true,
        organizationMode: 'inline',
        domainsByEffectiveMode: { inline: 1, api: 1, hybrid: 0 },
        coverage: { covered: 1, gap: 1, total: 2, percent: 50 },
        connectionsByHealth: { unknown: 1, healthy: 1, degraded: 0, failing: 0 },
        lag: { p50Seconds1h: 60, p95Seconds1h: 300 },
        throttling: { events1h: 1, events24h: 1 },
        copiesToday: 4,
      });
      expect(res.body.connections).toHaveLength(2);
      expect(res.body.connections[0]).toMatchObject({
        id: ctx.connection,
        grantStatus: 'active',
        health: 'healthy',
      });
      expect(res.body.connections[1]).toMatchObject({
        id: ctx.google,
        grantStatus: null,
        coverage: { total: null, percent: null },
      });
    });

    it('connections and detail never carry a cursor, subscription id or client state', async () => {
      const list = await send(spec('connections'));
      expect(list.body.data.map((c: { id: string }) => c.id)).toEqual([ctx.connection, ctx.google]);
      expect(list.body.data[1]).toMatchObject({
        apiConnectionId: null,
        feedsEnabled: false,
        feedMode: 'poll',
        inventoryStatus: 'never',
        health: { status: 'unknown' },
        grant: null,
        rowVersion: 1,
      });
      const detail = await send(spec('connection'));
      expect(detail.body).toMatchObject({
        id: ctx.connection,
        grant: { profile: 'm365.mailbox_remediation', status: 'active' },
        wizard: { steps: expect.any(Array) },
        counters: [expect.objectContaining({ journalCopies: 3, feedCopies: 1 })],
      });
      expect(detail.body.wizard.steps.map((s: { step: string }) => s.step)).toEqual([
        'domains',
        'connection',
        'journal',
        'mailbox_access',
        'feeds',
        'monitor',
      ]);
      const mailbox = await send(spec('mailbox'));
      for (const body of [list.body, detail.body, mailbox.body]) {
        const text = JSON.stringify(body);
        expect(text).not.toContain('sub-alex-0001');
        expect(text).not.toContain(clientStateHash(STATE));
        expect(text).not.toContain('graph.example/delta');
      }
    });

    it('setup guide: api-mode-guide/1 JSON, or Markdown by Accept', async () => {
      const json = await send(spec('guide'));
      expect(json.body).toMatchObject({
        schema: 'api-mode-guide/1',
        provider: 'microsoft_365',
        connection: { id: ctx.connection, displayName: 'Contoso Microsoft 365' },
        permissions: ['Mail.ReadWrite', 'User.Read.All'],
      });
      expect(json.body.sections.length).toBeGreaterThan(3);
      const md = await api
        .http()
        .get(`${BASE}/connections/${ctx.connection}/setup-guide`)
        .set(await asUser([READ]))
        .set('Accept', 'text/markdown');
      expect(md.status).toBe(200);
      expect(md.headers['content-type']).toMatch(/^text\/markdown/);
      expect(md.headers['content-disposition']).toMatch(/attachment; filename=".+\.md"/);
      expect(md.text).toMatch(/^# /);
      const google = await api
        .http()
        .get(`${BASE}/connections/${ctx.google}/setup-guide?format=json`)
        .set(await asUser([READ]));
      expect(google.body).toMatchObject({ provider: 'google_workspace' });
    });
  });

  describe('API-mode writes (D10.1, D11.1, D12 #8, #9, #12)', () => {
    const put = (connection: string, body: object, key = randomUUID()) =>
      asUser([WRITE]).then((auth) =>
        api
          .http()
          .put(`${BASE}/connections/${connection}/settings`)
          .set(auth)
          .set('Idempotency-Key', key)
          .send(body),
      );

    it('enables feeds with CAS: pending mailboxes, audit, replay; a stale version is 409', async () => {
      world.domains[0]!.configured = 'api';
      const key = randomUUID();
      const res = await put(ctx.connection, { feedsEnabled: true, expectedRowVersion: 1 }, key);
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body).toMatchObject({ feedsEnabled: true, feedMode: 'poll', rowVersion: 2 });
      expect(res.body.feedsEnabledAt).not.toBeNull();
      expect(world.mailboxes.filter((m) => m.feedStatus === 'pending').length).toBe(2);
      expect(audit.entries).toEqual([
        expect.objectContaining({
          action: 'api_mode.settings_updated',
          resourceType: 'api_mode_connection',
          metadata: expect.objectContaining({
            connectionId: ctx.connection,
            changedPaths: ['feedsEnabled'],
            feedsEnabled: true,
            mailboxesQueued: 2,
          }),
        }),
      ]);
      const replay = await put(ctx.connection, { feedsEnabled: true, expectedRowVersion: 1 }, key);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(audit.entries).toHaveLength(1);
      const stale = await put(ctx.connection, { feedsEnabled: false, expectedRowVersion: 1 });
      expect(stale.status).toBe(409);
      expect(stale.body).toMatchObject({
        code: 'api_mode_connection_conflict',
        currentRowVersion: 2,
      });
      const off = await put(ctx.connection, { feedsEnabled: false, expectedRowVersion: 2 });
      expect(off.body).toMatchObject({ feedsEnabled: false, feedsEnabledAt: null, rowVersion: 3 });
    });

    it('feeds need the mailbox-access grant; notify needs Microsoft 365 and a notification URL', async () => {
      const noGrant = await put(ctx.google, { feedsEnabled: true, expectedRowVersion: 1 });
      expect(noGrant.status).toBe(409);
      expect(noGrant.body.code).toBe('api_mode_mailbox_access_required');
      // The lazily created row exists now (version 1).
      expect(world.connections.find((c) => c.publicId === ctx.google)!.api).not.toBeNull();
      const google = await put(ctx.google, {
        feedsEnabled: false,
        feedMode: 'notify',
        expectedRowVersion: 1,
      });
      expect(google.status).toBe(422);
      expect(google.body).toMatchObject({
        code: 'api_mode_notifications_unavailable',
        reason: 'provider',
      });
      const platform = await put(ctx.connection, {
        feedsEnabled: true,
        feedMode: 'notify',
        expectedRowVersion: 1,
      });
      expect(platform.status).toBe(422);
      expect(platform.body.reason).toBe('platform');
      // Revoked grant: refused like a missing one.
      m365.grant!.status = 'revoked';
      expect(
        (await put(ctx.connection, { feedsEnabled: true, expectedRowVersion: 1 })).status,
      ).toBe(409);
      // Unchanged settings: 200 without an audit row.
      const same = await put(ctx.connection, { feedsEnabled: false, expectedRowVersion: 1 });
      expect(same.status).toBe(200);
      expect(audit.entries).toHaveLength(0);
    });

    it('inventory sync and mailbox resync: 202, audited, need the grant', async () => {
      const inv = await send(spec('inventory'));
      expect(inv.status).toBe(202);
      expect(inv.body).toMatchObject({ connectionId: ctx.connection });
      expect(m365.api!.inventoryRequestedAt).not.toBeNull();
      // Not a settings change: the CAS version does not move.
      expect(m365.api!.rowVersion).toBe(1);
      const resync = await send(spec('resync'));
      expect(resync.status).toBe(202);
      expect(resync.body).toMatchObject({ mailboxId: ctx.mailbox });
      const mailbox = world.mailboxes.find((m) => m.publicId === ctx.mailbox)!;
      expect(mailbox.feedCursor).toBeNull();
      expect(mailbox.syncRequestedAt).not.toBeNull();
      expect(audit.entries.map((e) => e.action)).toEqual([
        'api_mode.inventory_sync_requested',
        'api_mode.mailbox_resync_requested',
      ]);
      const noGrant = await api
        .http()
        .post(`${BASE}/connections/${ctx.google}/inventory-sync`)
        .set(await asUser([WRITE]))
        .set('Idempotency-Key', randomUUID());
      expect(noGrant.status).toBe(409);
      expect(noGrant.body.code).toBe('api_mode_mailbox_access_required');
      mailbox.grantActive = false;
      expect((await send(spec('resync'))).body.code).toBe('api_mode_mailbox_access_required');
    });
  });

  describe('mailboxes and detections (D12 #10, #11, #13, #14)', () => {
    it('mailboxes: v1 cursor pages bound to the filters; address prefix over aliases', async () => {
      const first = await api
        .http()
        .get(`${BASE}/mailboxes?limit=1`)
        .set(await asUser([READ]));
      expect(first.status).toBe(200);
      expect(first.body.data).toHaveLength(1);
      expect(first.body.nextCursor).toEqual(expect.any(String));
      const second = await api
        .http()
        .get(`${BASE}/mailboxes?limit=1&cursor=${encodeURIComponent(first.body.nextCursor)}`)
        .set(await asUser([READ]));
      expect(second.body.data[0].id).not.toBe(first.body.data[0].id);
      const tampered = await api
        .http()
        .get(
          `${BASE}/mailboxes?limit=1&coverage=gap&cursor=${encodeURIComponent(first.body.nextCursor)}`,
        )
        .set(await asUser([READ]));
      expect(tampered.status).toBe(400);
      expect(tampered.body.code).toBe('cursor_invalid');
      const alias = await api
        .http()
        .get(`${BASE}/mailboxes?q=A.SMITH`)
        .set(await asUser([READ]));
      expect(alias.body.data.map((m: { id: string }) => m.id)).toEqual([ctx.mailbox]);
      const gaps = await api
        .http()
        .get(`${BASE}/mailboxes?coverage=gap&connectionId=${ctx.connection}`)
        .set(await asUser([READ]));
      expect(gaps.body.data.map((m: { address: string }) => m.address)).toEqual([
        'blair@contoso.example',
      ]);
      expect(
        (
          await api
            .http()
            .get(`${BASE}/mailboxes?unknown=1`)
            .set(await asUser([READ]))
        ).status,
      ).toBe(400);
    });

    it('mailbox detail: aliases, notifications flag and masked recent detections', async () => {
      const res = await send(spec('mailbox'));
      expect(res.body).toMatchObject({
        id: ctx.mailbox,
        address: 'alex@contoso.example',
        domain: { name: 'contoso.example' },
        aliases: ['a.smith@contoso.example'],
        notifications: { subscribed: true },
      });
      expect(res.body.recentDetections).toHaveLength(2);
      for (const d of res.body.recentDetections) {
        expect(d.subject).toBeNull();
        expect(d.headerFrom).toBe('b***@fabrikam.example');
      }
    });

    it('detections: subject withheld, sender masked, filters, range and cursors', async () => {
      const res = await send(spec('detections'));
      expect(res.body.data).toHaveLength(2);
      const [newest, older] = res.body.data;
      expect(newest).toMatchObject({
        mailboxAddress: 'alex@contoso.example',
        subject: null,
        subjectMasked: false,
        headerFrom: 'b***@fabrikam.example',
      });
      expect(older).toMatchObject({
        id: ctx.detection,
        verdict: 'phishing',
        riskScore: 870,
        subject: null,
        subjectMasked: true,
      });
      expect(JSON.stringify(res.body)).not.toContain('Quarterly invoice');
      expect(JSON.stringify(res.body)).not.toContain('billing@');
      const phishing = await api
        .http()
        .get(`${BASE}/detections?verdict=phishing&minRiskScore=800`)
        .set(await asUser([READ]));
      expect(phishing.body.data.map((d: { id: string }) => d.id)).toEqual([ctx.detection]);
      const paged = await api
        .http()
        .get(`${BASE}/detections?limit=1`)
        .set(await asUser([READ]));
      const next = await api
        .http()
        .get(`${BASE}/detections?limit=1&cursor=${encodeURIComponent(paged.body.nextCursor)}`)
        .set(await asUser([READ]));
      expect(next.body.data[0].id).toBe(ctx.detection);
      expect(next.body.nextCursor).toBeNull();
      const tooLong = await api
        .http()
        .get(`${BASE}/detections?from=2026-01-01T00:00:00.000Z&to=2026-03-01T00:00:00.000Z`)
        .set(await asUser([READ]));
      expect(tooLong.status).toBe(400);
    });

    it('detection detail: at most 10 reason codes, codes only', async () => {
      const res = await send(spec('detection'));
      expect(res.body).toMatchObject({
        id: ctx.detection,
        direction: 'inbound',
        subject: null,
        headerFrom: 'b***@fabrikam.example',
      });
      expect(res.body.reasonCodes).toEqual(Array.from({ length: 10 }, (_, i) => `code.${i}`));
    });

    it('the documented examples match the response shapes', () => {
      expect(API_MODE_EXAMPLES.detection.subject).toBeNull();
      expect(JSON.stringify(API_MODE_EXAMPLES)).not.toMatch(
        /whsec_|AKIA|ghp_|BEGIN [A-Z ]*PRIVATE KEY|egk_|sk-[A-Za-z0-9]{8}/,
      );
    });
  });

  describe('public Graph callbacks (D12.4)', () => {
    const GRAPH = '/api/v1/provider-notifications/graph';
    const LIFECYCLE = '/api/v1/provider-notifications/graph/lifecycle';
    const item = (patch: object = {}) => ({
      subscriptionId: 'sub-alex-0001',
      clientState: STATE,
      changeType: 'created',
      tenantId: TENANT,
      resource: "users/x/mailFolders('inbox')/messages/y",
      ...patch,
    });

    it('echoes the validation token as text/plain with nosniff, without credentials', async () => {
      const res = await api.http().post(`${GRAPH}?validationToken=Validation%3A%20abc-123`);
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toBe('text/plain; charset=utf-8');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.text).toBe('Validation: abc-123');
      const life = await api.http().post(`${LIFECYCLE}?validationToken=tok`);
      expect(life.text).toBe('tok');
      // An unusable token is not echoed.
      const bad = await api.http().post(`${GRAPH}?validationToken=${'x'.repeat(1100)}`);
      expect(bad.status).toBe(202);
      expect(bad.text).toBe('');
    });

    it('a matching notification only requests a sync; mismatches change nothing; always 202', async () => {
      const ok = await api
        .http()
        .post(GRAPH)
        .send({ value: [item()] });
      expect(ok.status).toBe(202);
      expect(ok.text).toBe('');
      const mailbox = world.mailboxes.find((m) => m.publicId === ctx.mailbox)!;
      expect(mailbox.syncRequestedAt).not.toBeNull();
      expect(world.notifications).toEqual([
        {
          mailboxId: mailbox.id,
          effect: { requestSync: true, expireSubscription: false, clearSubscription: false },
        },
      ]);
      world.notifications = [];
      for (const value of [
        [item({ clientState: 'wrong-client-state' })],
        [item({ tenantId: '99999999-2222-3333-4444-555555555555' })],
        [item({ subscriptionId: 'unknown-subscription' })],
      ]) {
        const res = await api.http().post(GRAPH).send({ value });
        expect(res.status).toBe(202);
        expect(res.text).toBe('');
      }
      // Not a notification collection at all: still 202.
      expect((await api.http().post(GRAPH).send({ hello: 'world' })).status).toBe(202);
      expect(world.notifications).toEqual([]);
      // Lifecycle: reauthorizationRequired forces the renewal.
      const life = await api
        .http()
        .post(LIFECYCLE)
        .send({
          value: [item({ changeType: undefined, lifecycleEvent: 'reauthorizationRequired' })],
        });
      expect(life.status).toBe(202);
      expect(world.notifications).toEqual([
        {
          mailboxId: mailbox.id,
          effect: { requestSync: true, expireSubscription: true, clearSubscription: false },
        },
      ]);
      const metrics = await api.http().get('/metrics');
      expect(metrics.text).toMatch(
        /api_mode_notifications_total\{kind="change",result="accepted"[^}]*\} [1-9]/,
      );
      expect(metrics.text).toMatch(
        /api_mode_notifications_total\{kind="change",result="client_state_mismatch"[^}]*\} [1-9]/,
      );
    });

    it('bodies over 256 KiB are 413; up to it are accepted', async () => {
      const big = { value: [item({ padding: 'x'.repeat(260 * 1024) })] };
      const res = await api
        .http()
        .post(GRAPH)
        .set('Content-Type', 'application/json')
        .send(JSON.stringify(big));
      expect(res.status).toBe(413);
      const fits = { value: [item({ padding: 'x'.repeat(200 * 1024) })] };
      expect(
        (
          await api
            .http()
            .post(GRAPH)
            .set('Content-Type', 'application/json')
            .send(JSON.stringify(fits))
        ).status,
      ).toBe(202);
    });
  });
});

describe('public Graph callbacks: per-IP rate limit (D12.4)', () => {
  let api: StubbedApiApp;
  const world = new ApiModeWorld();

  beforeAll(async () => {
    api = await createStubbedApiApp(
      { API_MODE_NOTIFICATION_RATE_PER_MINUTE: '2' },
      { override: (b) => overrideApiMode(b, world) },
    );
  });

  afterAll(async () => {
    await api?.close();
  });

  it('answers 429 rate_limited with Retry-After above API_MODE_NOTIFICATION_RATE_PER_MINUTE', async () => {
    const post = () => api.http().post('/api/v1/provider-notifications/graph?validationToken=tok');
    expect((await post()).status).toBe(200);
    expect((await post()).status).toBe(200);
    const limited = await post();
    expect(limited.status).toBe(429);
    expect(limited.body).toMatchObject({ code: 'rate_limited', scope: 'route' });
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
  });
});
