/**
 * Step 6.1 WP3 e2e (stubbed infrastructure): `GET /audit/logs` and `GET /platform/audit/logs`
 * (docs/plan/steps/18-rest-api.md §3.3, D3, D6, D7, D11): pages and v1 cursors, filters and the
 * scan budget, strict queries, `cursor_invalid`, RBAC (permission, API key on the platform
 * route, MFA, non-platform users), the audited first page, and the OpenAPI operations.
 * Override sessions are refused by the permission guard (platform permissions stripped); that
 * path runs against real sessions in integration/tenant-isolation-insights.test.ts.
 */
// @covers get /api/v1/audit/logs
// @covers get /api/v1/platform/audit/logs
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildOpenApiDocument } from '../src/http/openapi';
import type { AuditLogRecord } from '../src/modules/audit-logs/audit-logs.repository';
import {
  createInsightApp,
  expectCoded,
  type InsightApp,
  OTHER_ORG_PUBLIC_ID,
} from './insights-support';

let t: InsightApp;
const now = Date.now();

const row = (
  id: bigint,
  minutesAgo: number,
  organizationId: bigint | null,
  action = 'domain.created',
): AuditLogRecord => ({
  id,
  createdAt: new Date(now - minutesAgo * 60_000),
  organizationId,
  actorType: 'user',
  actorId: '01930c2e-7d1a-7000-8000-0000000000a1',
  action,
  resourceType: action.split('.')[0]!,
  resourceId: `res-${id}`,
  correlationId: 'corr-1',
  sourceIp: '203.0.113.1',
  metadata: { requestId: 'r' },
});

beforeAll(async () => {
  t = await createInsightApp();
});
afterAll(async () => {
  await t?.close();
});
beforeEach(() => {
  t.principals.user(['audit:read']);
  t.principals.apiKeyWith(['audit:read']);
  t.doubles.audit.entries.length = 0;
  t.doubles.auditLogs.rows = [
    row(10n, 1, 1n, 'quarantine.entry_released'),
    row(9n, 2, 1n, 'domain.created'),
    row(8n, 3, 1n, 'quarantine.entry_rejected'),
    row(7n, 4, 2n, 'quarantine.entry_released'),
    row(6n, 5, null, 'platform.organization_created'),
  ];
});

const get = async (path: string, auth?: Record<string, string>) =>
  t
    .http()
    .get(path)
    .set(auth ?? (await t.principals.bearer()));

describe('GET /audit/logs', () => {
  it('lists the organization’s rows newest first with signed cursors and audits the first page', async () => {
    const first = await get('/api/v1/audit/logs?limit=2');
    expect(first.status).toBe(200);
    expect(first.body.data.map((r: { id: string }) => r.id)).toEqual(['10', '9']);
    expect(first.body.data[0]).toEqual({
      id: '10',
      createdAt: new Date(now - 60_000).toISOString(),
      actor: { type: 'user', id: '01930c2e-7d1a-7000-8000-0000000000a1' },
      action: 'quarantine.entry_released',
      resourceType: 'quarantine',
      resourceId: 'res-10',
      correlationId: 'corr-1',
      sourceIp: '203.0.113.1',
      metadata: { requestId: 'r' },
    });
    expect(first.body.nextCursor).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$/);
    const second = await get(`/api/v1/audit/logs?limit=2&cursor=${first.body.nextCursor}`);
    expect(second.body).toEqual({ data: [expect.objectContaining({ id: '8' })], nextCursor: null });
    expect(t.doubles.audit.actions()).toEqual(['audit.searched']);
    expect(t.doubles.audit.entries[0]).toMatchObject({
      organizationId: 1n,
      resourceType: 'audit_log',
      metadata: { filters: [], resultCount: 2 },
    });
  });

  it('accepts API keys and filters (action, actionPrefix, actor, resource, sort)', async () => {
    const byKey = await get(
      '/api/v1/audit/logs?actionPrefix=quarantine.&sort=createdAt',
      t.principals.apiKeyHeaders,
    );
    expect(byKey.status).toBe(200);
    expect(byKey.body.data.map((r: { id: string }) => r.id)).toEqual(['8', '10']);
    expect(t.doubles.auditLogs.calls.boundary).toBeGreaterThan(0);
    const exact = await get(
      '/api/v1/audit/logs?action=domain.created&resourceId=res-9&actorType=user',
    );
    expect(exact.body.data.map((r: { id: string }) => r.id)).toEqual(['9']);
    expect(t.doubles.audit.entries.at(-1)!.metadata).toMatchObject({
      filters: ['action', 'actorType', 'resourceId'],
      identifierSha256: { resourceId: expect.stringMatching(/^[0-9a-f]{64}$/) },
    });
    expect(JSON.stringify(t.doubles.audit.entries.at(-1)!.metadata)).not.toContain('res-9');
  });

  it('ends a filtered page at the scan budget with a short page and a cursor', async () => {
    const small = await createInsightApp({ API_LIST_SCAN_BUDGET_ROWS: '1000' });
    try {
      small.principals.user(['audit:read']);
      const rows: AuditLogRecord[] = [];
      for (let i = 0; i < 1500; i += 1)
        rows.push(
          row(BigInt(5000 - i), i / 100, 1n, i === 1200 ? 'user.invited' : 'domain.created'),
        );
      small.doubles.auditLogs.rows = rows;
      const auth = await small.principals.bearer();
      const first = await small.http().get('/api/v1/audit/logs?action=user.invited').set(auth);
      expect(first.status).toBe(200);
      expect(first.body.data).toEqual([]);
      expect(first.body.nextCursor).not.toBeNull();
      const second = await small
        .http()
        .get(`/api/v1/audit/logs?action=user.invited&cursor=${first.body.nextCursor}`)
        .set(auth);
      expect(second.body.data.map((r: { action: string }) => r.action)).toEqual(['user.invited']);
      expect(second.body.nextCursor).toBeNull();
    } finally {
      await small.close();
    }
  });

  it('refuses unknown parameters, bad values, too long ranges and invalid or foreign cursors', async () => {
    for (const query of [
      'organizationId=01930c2e-7d1a-7000-8000-00000000b0b0',
      'scope=platform',
      'foo=1',
      'limit=0',
      'limit=101',
      'sort=-id',
      'actorType=robot',
      'action=a.b&actionPrefix=a.',
      'actionPrefix=Quarantine.',
      'from=2026-01-01T00:00:00Z&to=2026-11-01T00:00:00Z',
    ]) {
      const res = await get(`/api/v1/audit/logs?${query}`);
      expect(res.status, query).toBe(400);
      expectCoded(res.body, 'validation_failed');
    }
    expectCoded((await get('/api/v1/audit/logs?cursor=abc.def')).body, 'cursor_invalid');
    const page = await get('/api/v1/audit/logs?limit=1');
    const cursor = page.body.nextCursor as string;
    expectCoded(
      (await get(`/api/v1/audit/logs?limit=1&cursor=${cursor}&action=x.y`)).body,
      'cursor_invalid',
    );
    expectCoded(
      (await get(`/api/v1/audit/logs?limit=1&cursor=${cursor}&sort=createdAt`)).body,
      'cursor_invalid',
    );
    // The platform route's resource never accepts a tenant cursor.
    t.principals.user(['platform:operations', 'audit:read'], {
      mfaAuthenticated: true,
      orgKind: 'platform',
    });
    expectCoded(
      (await get(`/api/v1/platform/audit/logs?scope=platform&cursor=${cursor}`)).body,
      'cursor_invalid',
    );
  });

  it('requires audit:read', async () => {
    t.principals.user(['report:read']);
    t.principals.apiKeyWith(['report:read']);
    expectCoded((await get('/api/v1/audit/logs')).body, 'forbidden');
    expect((await get('/api/v1/audit/logs', t.principals.apiKeyHeaders)).status).toBe(403);
    expect((await t.http().get('/api/v1/audit/logs')).status).toBe(401);
  });
});

describe('GET /platform/audit/logs', () => {
  const platformUser = (mfa = true) =>
    t.principals.user(['platform:operations', 'audit:read'], {
      mfaAuthenticated: mfa,
      orgKind: 'platform',
    });

  it('lets an MFA platform user read any organization or the platform rows, audited', async () => {
    platformUser();
    const other = await get(`/api/v1/platform/audit/logs?organizationId=${OTHER_ORG_PUBLIC_ID}`);
    expect(other.status).toBe(200);
    expect(other.body.data.map((r: { id: string }) => r.id)).toEqual(['7']);
    const platform = await get('/api/v1/platform/audit/logs?scope=platform');
    expect(platform.body.data.map((r: { id: string }) => r.id)).toEqual(['6']);
    expect(t.doubles.audit.entries.map((e) => [e.action, e.organizationId, e.resourceId])).toEqual([
      ['platform.audit_searched', 2n, OTHER_ORG_PUBLIC_ID],
      ['platform.audit_searched', null, 'platform'],
    ]);
  });

  it('requires exactly one known target', async () => {
    platformUser();
    expectCoded((await get('/api/v1/platform/audit/logs')).body, 'validation_failed');
    expectCoded(
      (
        await get(
          `/api/v1/platform/audit/logs?scope=platform&organizationId=${OTHER_ORG_PUBLIC_ID}`,
        )
      ).body,
      'validation_failed',
    );
    expectCoded(
      (await get('/api/v1/platform/audit/logs?organizationId=not-a-uuid')).body,
      'validation_failed',
    );
    const unknown = await get(
      '/api/v1/platform/audit/logs?organizationId=01930c2e-7d1a-7000-8000-00000000dead',
    );
    expect(unknown.status).toBe(404);
    expectCoded(unknown.body, 'organization_not_found');
  });

  it('refuses API keys, sessions without MFA, customer users and missing permissions', async () => {
    t.principals.apiKeyWith(['platform:operations', 'audit:read']);
    const key = await get('/api/v1/platform/audit/logs?scope=platform', t.principals.apiKeyHeaders);
    expect(key.status).toBe(403);
    expect(['user_required', 'forbidden']).toContain(key.body.code);

    platformUser(false);
    expectCoded((await get('/api/v1/platform/audit/logs?scope=platform')).body, 'mfa_required');

    t.principals.user(['platform:operations', 'audit:read'], { mfaAuthenticated: true });
    expect((await get('/api/v1/platform/audit/logs?scope=platform')).status).toBe(403);

    t.principals.user(['audit:read'], { mfaAuthenticated: true, orgKind: 'platform' });
    expectCoded((await get('/api/v1/platform/audit/logs?scope=platform')).body, 'forbidden');
    expect(t.doubles.audit.entries).toEqual([]);
  });
});

describe('audit OpenAPI operations', () => {
  it('documents both searches with tags, permissions, cursor v1, examples and codes', () => {
    const doc = buildOpenApiDocument(t.app);
    const tenant = doc.paths['/api/v1/audit/logs']!.get as unknown as Record<string, unknown> & {
      responses: Record<string, { content?: Record<string, { example?: unknown }> }>;
      parameters: Array<{ name: string }>;
    };
    expect(tenant.tags).toEqual(['audit']);
    expect(tenant['x-eg-cursor']).toBe('v1');
    expect(tenant['x-eg-permissions']).toEqual({ mode: 'all', permissions: ['audit:read'] });
    expect(tenant.parameters.map((p) => p.name)).toEqual(
      expect.arrayContaining(['from', 'to', 'action', 'actionPrefix', 'sort', 'limit', 'cursor']),
    );
    expect(tenant.parameters.map((p) => p.name)).not.toContain('organizationId');
    expect(JSON.stringify(tenant.responses['400'])).toContain('cursor_invalid');
    expect(tenant.responses['200']!.content!['application/json']!.example).toBeDefined();

    const platform = doc.paths['/api/v1/platform/audit/logs']!.get as unknown as Record<
      string,
      unknown
    > & {
      responses: Record<string, unknown>;
      parameters: Array<{ name: string }>;
      security: unknown[];
    };
    expect(platform.tags).toEqual(['platform']);
    expect(platform['x-eg-permissions']).toEqual({
      mode: 'all',
      permissions: ['platform:operations', 'audit:read'],
    });
    expect(platform['x-eg-cursor']).toBe('v1');
    expect(platform.parameters.map((p) => p.name)).toEqual(
      expect.arrayContaining(['organizationId', 'scope']),
    );
    expect(JSON.stringify(platform.responses['404'])).toContain('organization_not_found');
    expect(JSON.stringify(platform.security)).not.toContain('api-key');
    expect(platform.summary).toEqual(expect.any(String));
  });
});
