/**
 * Step 6.1 WP3 integration (real MySQL writer + replica, Redis): the audit log searches
 * (docs/plan/steps/18-rest-api.md §3.3, D3, D6, D7, D11) against seeded `audit_logs` rows of two
 * organizations and the platform: pages equal to SQL ground truth in both sort orders, filters,
 * the scan budget with real rows, the audit rows of the searches themselves, the platform route
 * for an MFA platform user, and EXPLAIN FORMAT=JSON of the search statements.
 */
// @covers get /api/v1/audit/logs
// @covers get /api/v1/platform/audit/logs
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { auditSql, type AuditSearch } from '../src/modules/audit-logs/audit-logs.repository';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
} from './support/fixtures';
import { bearer, login, loginWithMfa } from './support/http';
import {
  type AuditSpec,
  DAY_MS,
  explain,
  HOUR_MS,
  insertAuditRows,
  partitionsOf,
  POLL,
  reader,
  waitFor,
} from './support/insights';

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: FixtureUser;
let tokenA: string;
let platformToken: string;
const marker = randomUUID();
const base = Date.now() - 4 * DAY_MS;
const windowFrom = new Date(base - HOUR_MS).toISOString();
const windowTo = new Date(base + 2 * DAY_MS).toISOString();

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  adminA = await fx.createUser(orgA, { roles: ['organization_admin'] });
  tokenA = (
    await login(ctx, { email: adminA.email, password: adminA.password, organization: orgA.slug })
  ).body.accessToken as string;
  const operator = await fx.createPlatformUser(['platform_admin']);
  platformToken = (await loginWithMfa(ctx, fx, operator)).accessToken;

  const rows: AuditSpec[] = [];
  const actions = ['quarantine.entry_released', 'domain.created', 'quarantine.entry_rejected'];
  for (let i = 0; i < 9; i += 1) {
    rows.push({
      organizationId: orgA.id,
      createdAt: new Date(base + i * HOUR_MS),
      action: actions[i % 3]!,
      resourceId: `${marker}-${i}`,
      actorType: i % 2 === 0 ? 'user' : 'api_key',
      actorId: i % 2 === 0 ? adminA.publicId : null,
    });
  }
  // Two rows with the same instant (keyset tie on created_at, ordered by id).
  rows.push({
    organizationId: orgA.id,
    createdAt: new Date(base + 20 * HOUR_MS),
    action: 'user.invited',
    resourceId: `${marker}-t1`,
  });
  rows.push({
    organizationId: orgA.id,
    createdAt: new Date(base + 20 * HOUR_MS),
    action: 'user.invited',
    resourceId: `${marker}-t2`,
  });
  for (let i = 0; i < 4; i += 1) {
    rows.push({
      organizationId: orgB.id,
      createdAt: new Date(base + i * HOUR_MS),
      action: 'domain.created',
      resourceId: `${marker}-b${i}`,
    });
  }
  rows.push({
    organizationId: null,
    createdAt: new Date(base + HOUR_MS),
    action: 'platform.organization_created',
    resourceId: `${marker}-p`,
  });
  await insertAuditRows(ctx, rows);
  await waitFor(
    () => reader(ctx).auditLog.count({ where: { resourceId: { startsWith: marker } } }),
    rows.length,
  );
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

const search = (params: Record<string, string>, token = tokenA, path = '/api/v1/audit/logs') =>
  ctx.http.get(`${path}?${new URLSearchParams(params).toString()}`).set(bearer(token));

/** Ground truth on the writer, in the same order. */
async function truth(
  organizationId: bigint | null,
  order: 'desc' | 'asc',
  extra: Record<string, unknown> = {},
) {
  const rows = await ctx.prisma.auditLog.findMany({
    where: {
      organizationId,
      createdAt: { gte: new Date(windowFrom), lt: new Date(windowTo) },
      ...extra,
    },
    select: { id: true },
    orderBy: [{ createdAt: order }, { id: order }],
  });
  return rows.map((r) => r.id.toString());
}

async function allPages(params: Record<string, string>, token = tokenA, path?: string) {
  const ids: string[] = [];
  let cursor: string | null = null;
  let pages = 0;
  do {
    const res = await search({ ...params, ...(cursor && { cursor }) }, token, path).expect(200);
    ids.push(...(res.body.data as Array<{ id: string }>).map((r) => r.id));
    cursor = res.body.nextCursor as string | null;
    pages += 1;
  } while (cursor !== null && pages < 50);
  return { ids, pages };
}

describe('GET /audit/logs', () => {
  it('pages through the organization rows newest first, equal to SQL ground truth', async () => {
    const { ids, pages } = await allPages({ from: windowFrom, to: windowTo, limit: '4' });
    expect(ids).toEqual(await truth(orgA.id, 'desc'));
    expect(ids).toHaveLength(11);
    expect(pages).toBe(3);
    const asc = await allPages({ from: windowFrom, to: windowTo, limit: '3', sort: 'createdAt' });
    expect(asc.ids).toEqual(await truth(orgA.id, 'asc'));
  });

  it('returns the documented item fields', async () => {
    const res = await search({
      from: windowFrom,
      to: windowTo,
      limit: '1',
      sort: 'createdAt',
    }).expect(200);
    expect(res.body.data[0]).toEqual({
      id: expect.stringMatching(/^\d+$/),
      createdAt: new Date(base).toISOString(),
      actor: { type: 'user', id: adminA.publicId },
      action: 'quarantine.entry_released',
      resourceType: 'quarantine',
      resourceId: `${marker}-0`,
      correlationId: 'insights-fixture',
      sourceIp: '203.0.113.50',
      metadata: { fixture: true },
    });
  });

  it('filters by action, actionPrefix, actor and resource like SQL', async () => {
    const prefix = await allPages({
      from: windowFrom,
      to: windowTo,
      actionPrefix: 'quarantine.',
      limit: '2',
    });
    expect(prefix.ids).toEqual(
      await truth(orgA.id, 'desc', { action: { startsWith: 'quarantine.' } }),
    );
    expect(prefix.ids).toHaveLength(6);
    const exact = await allPages({ from: windowFrom, to: windowTo, action: 'domain.created' });
    expect(exact.ids).toEqual(await truth(orgA.id, 'desc', { action: 'domain.created' }));
    const actor = await allPages({
      from: windowFrom,
      to: windowTo,
      actorType: 'user',
      actorId: adminA.publicId,
    });
    expect(actor.ids).toEqual(
      await truth(orgA.id, 'desc', { actorType: 'user', actorId: adminA.publicId }),
    );
    const resource = await allPages({
      from: windowFrom,
      to: windowTo,
      resourceType: 'user',
      resourceId: `${marker}-t2`,
    });
    expect(resource.ids).toHaveLength(1);
    // `_` in a prefix is literal: no row matches "quarantine_" + anything.
    const literal = await allPages({ from: windowFrom, to: windowTo, actionPrefix: 'quarantin_.' });
    expect(literal.ids).toEqual([]);
  });

  it('matches filters exactly: a case or trailing-space variant finds nothing (200, never 503)', async () => {
    // The columns are utf8mb4_unicode_ci; the search compares under utf8mb4_0900_bin, so SQL
    // and the echo check agree (an uppercase id used to match in SQL and fail the echo check).
    const exact = await allPages({ from: windowFrom, to: windowTo, resourceId: `${marker}-t2` });
    expect(exact.ids).toHaveLength(1);
    const variants: Array<Record<string, string>> = [
      { resourceId: `${marker}-T2`.toUpperCase() },
      { resourceId: `${marker}-t2 ` },
      { actorId: adminA.publicId.toUpperCase() },
      { action: 'DOMAIN.CREATED' },
      { action: 'domain.created ' },
      { resourceType: 'USER' },
    ];
    for (const params of variants) {
      const res = await search({ from: windowFrom, to: windowTo, ...params }).expect(200);
      expect(res.body.data).toEqual([]);
    }
  });

  it('audits the first page of each search (filter names, hash, count, request id), never later pages', async () => {
    const before = new Date();
    const first = await search({
      from: windowFrom,
      to: windowTo,
      resourceId: `${marker}-3`,
      limit: '1',
    }).expect(200);
    expect(first.body.data).toHaveLength(1);
    await expect
      .poll(
        () =>
          ctx.prisma.auditLog.findMany({
            where: {
              organizationId: orgA.id,
              action: 'audit.searched',
              createdAt: { gte: before },
            },
            select: { actorId: true, resourceType: true, metadata: true },
          }),
        POLL,
      )
      .toEqual([
        {
          actorId: adminA.publicId,
          resourceType: 'audit_log',
          metadata: expect.objectContaining({
            filters: ['resourceId'],
            filterHash: expect.stringMatching(/^[0-9a-f]{16}$/),
            resultCount: 1,
            requestId: expect.any(String),
            identifierSha256: { resourceId: expect.stringMatching(/^[0-9a-f]{64}$/) },
          }),
        },
      ]);
    const rows = await ctx.prisma.auditLog.findMany({
      where: { organizationId: orgA.id, action: 'audit.searched', createdAt: { gte: before } },
      select: { metadata: true },
    });
    expect(JSON.stringify(rows)).not.toContain(`${marker}-3`);
  });

  it('ends filtered pages at the scan budget with real rows and still finds every match', async () => {
    const small = await createIntegrationApp({ API_LIST_SCAN_BUDGET_ROWS: '1000' });
    try {
      const orgC = await fx.createOrganization();
      const admin = await fx.createUser(orgC, { roles: ['organization_admin'] });
      const token = (
        await login(small, {
          email: admin.email,
          password: admin.password,
          organization: orgC.slug,
        })
      ).body.accessToken as string;
      const t0 = Date.now() - 2 * DAY_MS;
      const specs: AuditSpec[] = [];
      for (let i = 0; i < 1500; i += 1) {
        specs.push({
          organizationId: orgC.id,
          createdAt: new Date(t0 + i * 1000),
          action: i === 100 || i === 1400 ? 'user.invited' : 'domain.updated',
        });
      }
      await insertAuditRows(small, specs);
      await waitFor(
        () => reader(small).auditLog.count({ where: { organizationId: orgC.id } }),
        1500,
      );
      const params = new URLSearchParams({
        from: new Date(t0 - 1000).toISOString(),
        to: new Date(t0 + DAY_MS).toISOString(),
        action: 'user.invited',
      });
      const first = await small.http
        .get(`/api/v1/audit/logs?${params.toString()}`)
        .set(bearer(token))
        .expect(200);
      // Newest first: the first 1000 entries hold the match at i = 1400 only.
      expect(first.body.data.map((r: { createdAt: string }) => r.createdAt)).toEqual([
        new Date(t0 + 1_400_000).toISOString(),
      ]);
      expect(first.body.nextCursor).not.toBeNull();
      params.set('cursor', first.body.nextCursor as string);
      const second = await small.http
        .get(`/api/v1/audit/logs?${params.toString()}`)
        .set(bearer(token))
        .expect(200);
      expect(second.body.data.map((r: { createdAt: string }) => r.createdAt)).toEqual([
        new Date(t0 + 100_000).toISOString(),
      ]);
      expect(second.body.nextCursor).toBeNull();
    } finally {
      await small.close();
    }
  });
});

describe('GET /platform/audit/logs', () => {
  it('lets an MFA platform administrator read any organization and the platform rows, audited in the target trail', async () => {
    const before = new Date();
    const forB = await allPages(
      { organizationId: orgB.publicId, from: windowFrom, to: windowTo },
      platformToken,
      '/api/v1/platform/audit/logs',
    );
    expect(forB.ids).toEqual(await truth(orgB.id, 'desc'));
    expect(forB.ids).toHaveLength(4);
    const platform = await search(
      { scope: 'platform', from: windowFrom, to: windowTo, resourceId: `${marker}-p` },
      platformToken,
      '/api/v1/platform/audit/logs',
    ).expect(200);
    expect(platform.body.data).toHaveLength(1);
    expect(platform.body.data[0].action).toBe('platform.organization_created');
    await expect
      .poll(
        async () =>
          (
            await ctx.prisma.auditLog.findMany({
              where: { action: 'platform.audit_searched', createdAt: { gte: before } },
              select: { organizationId: true, resourceId: true },
              orderBy: { id: 'asc' },
            })
          ).filter((r) => r.organizationId === orgB.id || r.resourceId === 'platform'),
        POLL,
      )
      .toEqual([
        { organizationId: orgB.id, resourceId: orgB.publicId },
        { organizationId: null, resourceId: 'platform' },
      ]);
  });

  it('answers 404 organization_not_found for an unknown organization', async () => {
    const res = await search(
      { organizationId: randomUUID() },
      platformToken,
      '/api/v1/platform/audit/logs',
    ).expect(404);
    expect(res.body.code).toBe('organization_not_found');
  });
});

describe('search statements (EXPLAIN FORMAT=JSON)', () => {
  const searchOf = (owner: AuditSearch['owner']): AuditSearch => ({
    owner,
    from: new Date(windowFrom),
    to: new Date(windowTo),
    direction: 'desc',
    after: { createdAt: new Date(base + 5 * HOUR_MS), id: 1n << 40n },
  });

  it('uses (organization_id, created_at), prunes partitions and needs no filesort', async () => {
    const all = await partitionsOf(ctx, 'audit_logs');
    for (const owner of [
      { kind: 'organization', organizationId: orgA.id } as const,
      { kind: 'platform' } as const,
    ]) {
      for (const sql of [
        auditSql.page(searchOf(owner), 26),
        auditSql.filtered(searchOf(owner), { actionPrefix: 'quarantine.' }, null, 26),
      ]) {
        const { tables, text } = await explain(ctx, sql);
        const t = tables.find((x) => x.table_name === 'audit_logs')!;
        expect(t.key, text).toBe('audit_logs_organization_id_created_at_idx');
        expect(['range', 'ref']).toContain(t.access_type);
        expect(t.partitions!.length, text).toBeLessThan(all.length);
        expect(text).not.toMatch(/"using_filesort": true/);
      }
      const boundary = await explain(ctx, auditSql.boundary(searchOf(owner), 5000));
      const b = boundary.tables.find((x) => x.table_name === 'audit_logs')!;
      expect(b.key).toBe('audit_logs_organization_id_created_at_idx');
      expect(b.using_index, boundary.text).toBe(true);
      expect(boundary.text).not.toMatch(/"using_filesort": true/);
    }
  });
});
