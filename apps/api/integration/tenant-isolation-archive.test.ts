/**
 * Tenant isolation of the step 8.1 archive, legal hold and eDiscovery routes against the real
 * writer and replica, MinIO and OpenSearch (§9.3, A16, A20): two organizations with the same
 * kinds of rows; every route called by organization A with organization B's ids answers like an
 * unknown id (404), lists of A never contain B's rows, A's search through its tenant alias never
 * returns B's documents (also checked directly against OpenSearch: B's ids through A's alias and
 * with A's term filter return nothing), B's download token is useless to A's user, and nothing of
 * B changes.
 */
// @covers get /api/v1/archive/settings
// @covers put /api/v1/archive/settings
// @covers get /api/v1/archive/retention-policies
// @covers post /api/v1/archive/retention-policies
// @covers get /api/v1/archive/retention-policies/:policyId
// @covers put /api/v1/archive/retention-policies/:policyId
// @covers delete /api/v1/archive/retention-policies/:policyId
// @covers get /api/v1/archive/keys
// @covers post /api/v1/archive/keys/rotate
// @covers get /api/v1/archive/status
// @covers get /api/v1/archive/capture-issues
// @covers get /api/v1/archive/capture-issues/:messageId
// @covers post /api/v1/archive/capture-issues/:messageId/retry
// @covers get /api/v1/archive/disposals
// @covers get /api/v1/archive/messages
// @covers get /api/v1/archive/messages/:messageId
// @covers get /api/v1/archive/messages/:messageId/journal
// @covers get /api/v1/archive/messages/:messageId/security
// @covers post /api/v1/archive/messages/:messageId/reveal
// @covers get /api/v1/archive/messages/:messageId/preview
// @covers post /api/v1/archive/messages/:messageId/download-grants
// @covers get /api/v1/archive/downloads/:token
// @covers post /api/v1/archive/messages/:messageId/dispose
// @covers get /api/v1/legal-holds
// @covers get /api/v1/legal-holds/:holdId
// @covers post /api/v1/legal-holds/:holdId/release
// @covers post /api/v1/ediscovery/cases/:caseId/holds
// @covers get /api/v1/ediscovery/cases
// @covers post /api/v1/ediscovery/cases
// @covers get /api/v1/ediscovery/cases/:caseId
// @covers patch /api/v1/ediscovery/cases/:caseId
// @covers post /api/v1/ediscovery/cases/:caseId/close
// @covers post /api/v1/ediscovery/cases/:caseId/searches
// @covers get /api/v1/ediscovery/cases/:caseId/searches
// @covers get /api/v1/ediscovery/cases/:caseId/searches/:searchId
// @covers get /api/v1/ediscovery/cases/:caseId/searches/:searchId/hits
// @covers post /api/v1/ediscovery/cases/:caseId/searches/:searchId/review
// @covers post /api/v1/ediscovery/cases/:caseId/exports
// @covers get /api/v1/ediscovery/cases/:caseId/exports
// @covers get /api/v1/ediscovery/cases/:caseId/exports/:exportId
// @covers post /api/v1/ediscovery/cases/:caseId/exports/:exportId/download-grants
import { randomUUID } from 'node:crypto';
import { tenantAliasName } from '@email-gateway/archive';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { SeededRecord } from '../test/support/archive-seed';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  ARCHIVE_POLL,
  ArchiveFixtures,
  archiveHttp,
  type ArchiveHttp,
  testIndexPrefix,
} from './support/archive';
import {
  createFixtures,
  type FixtureOrganization,
  type FixtureUser,
  type Fixtures,
} from './support/fixtures';
import { bearer, loginWithMfa } from './support/http';

const A = '/api/v1/archive';
const C = '/api/v1/ediscovery/cases';
const DAY = 86_400_000;
const RANGE = `from=${encodeURIComponent(new Date(Date.now() - 30 * DAY).toISOString())}&to=${encodeURIComponent(new Date(Date.now() + DAY).toISOString())}`;
const key = () => `it-${randomUUID()}`;

interface Tenant {
  org: FixtureOrganization;
  user: FixtureUser;
  http: ArchiveHttp;
  record: SeededRecord;
  review: SeededRecord;
  policy: string;
  hold: string;
  case: string;
  search: string;
  export: string;
}

let ctx: IntegrationApp;
let fx: Fixtures;
let ax: ArchiveFixtures;
let a: Tenant;
let b: Tenant;

async function tenant(): Promise<Tenant> {
  const org = await fx.createOrganization({ planCode: 'enterprise' });
  // Step 8.6 (ADR-0089): an organization admin as migrated (archive access through compliance_officer).
  const user = await fx.createUser(org, {
    roles: ['organization_admin', 'compliance_officer'],
    mfa: true,
  });
  const http = archiveHttp(ctx, bearer((await loginWithMfa(ctx, fx, user)).accessToken));
  const policy = await ctx.prisma.archiveRetentionPolicy.create({
    data: { organizationId: org.id, name: 'P', retentionDays: 365, priority: 1 },
  });
  await ax.settings(org, {
    defaultRetentionPolicyId: policy.id,
    settings: { access: { downloadEnabled: true } },
  });
  const record = await ax.record(org, { subject: `Secret of ${org.slug}` });
  const review = await ax.record(
    org,
    { status: 'expiry_review', retainUntil: new Date(Date.now() - DAY) },
    { index: false },
  );
  await ctx.prisma.archiveCaptureIntent.create({
    data: {
      receivedAt: record.row.receivedAt,
      organizationId: org.id,
      messageId: record.row.messageId,
      direction: 'inbound',
      status: 'failed',
      nextCheckAt: new Date(),
      settingsGeneration: 1n,
    },
  });
  const c = await ctx.prisma.ediscoveryCase.create({
    data: { organizationId: org.id, name: `Case ${org.slug}` },
  });
  const hold = await ctx.prisma.archiveLegalHold.create({
    data: {
      organizationId: org.id,
      caseId: c.id,
      name: 'H',
      reason: 'R',
      criteria: { custodians: ['nobody@example.org'] },
      criteriaVersion: 'archive-hold/1',
    },
  });
  const search = await ctx.prisma.ediscoverySearch.create({
    data: {
      organizationId: org.id,
      caseId: c.id,
      criteria: { from: '2026-01-01', to: '2026-12-31' },
      criteriaSha256: 'c'.repeat(64),
      status: 'completed',
    },
  });
  await ctx.prisma.ediscoverySearchHit.create({
    data: {
      searchId: search.id,
      organizationId: org.id,
      messageId: record.row.messageId,
      messageReceivedAt: record.row.receivedAt,
      messagePublicId: record.row.messagePublicId,
    },
  });
  const exp = await ctx.prisma.ediscoveryExport.create({
    data: {
      organizationId: org.id,
      caseId: c.id,
      searchId: search.id,
      reviewTags: ['relevant'],
      status: 'queued',
    },
  });
  return {
    org,
    user,
    http,
    record,
    review,
    policy: policy.publicId,
    hold: hold.publicId,
    case: c.publicId,
    search: search.publicId,
    export: exp.publicId,
  };
}

beforeAll(async () => {
  ctx = await createIntegrationApp({ ARCHIVE_SEARCH_INDEX_PREFIX: testIndexPrefix() });
  fx = createFixtures(ctx);
  ax = new ArchiveFixtures(ctx, ctx.config.ARCHIVE_SEARCH_INDEX_PREFIX);
  fx.registerCleanup(() => ax.cleanup());
  a = await tenant();
  b = await tenant();
}, 240_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('another organization’s ids answer 404 on every id route', () => {
  it('archive routes', async () => {
    const m = b.record.row.messagePublicId;
    const checks: Array<[string, () => Promise<{ status: number; body: { code?: string } }>]> = [
      ['policy get', () => a.http.get(`${A}/retention-policies/${b.policy}`)],
      [
        'policy put',
        () =>
          a.http.put(
            `${A}/retention-policies/${b.policy}`,
            { expectedRowVersion: 1, name: 'x', retentionDays: 1 },
            key(),
          ),
      ],
      ['policy delete', () => a.http.delete(`${A}/retention-policies/${b.policy}`, key())],
      ['capture issue get', () => a.http.get(`${A}/capture-issues/${m}`)],
      ['retry', () => a.http.post(`${A}/capture-issues/${m}/retry`, undefined, key())],
      ['detail', () => a.http.get(`${A}/messages/${m}`)],
      ['journal', () => a.http.get(`${A}/messages/${m}/journal`)],
      ['security', () => a.http.get(`${A}/messages/${m}/security`)],
      ['reveal', () => a.http.post(`${A}/messages/${m}/reveal`, { fields: ['subject'] })],
      ['preview', () => a.http.get(`${A}/messages/${m}/preview`)],
      [
        'grant',
        async () =>
          a.http.post(`${A}/messages/${m}/download-grants`, {
            password: a.user.password,
            totpCode: await fx.totpNow(a.user),
          }),
      ],
      [
        'dispose',
        () =>
          a.http.post(
            `${A}/messages/${b.review.row.messagePublicId}/dispose`,
            { reason: 'x' },
            key(),
          ),
      ],
    ];
    for (const [name, call] of checks) {
      const res = await call();
      expect(res.status, `${name} ${JSON.stringify(res.body)}`).toBe(404);
    }
  });

  it('the capture issue read (AI-5 D8): A reads its own intent, B’s answers the coded 404', async () => {
    // Replica reads: wait until A's own intent (written in the setup) is visible.
    await expect
      .poll(
        async () =>
          (await a.http.get(`${A}/capture-issues/${a.record.row.messagePublicId}`)).status,
        ARCHIVE_POLL,
      )
      .toBe(200);
    const own = await a.http.get(`${A}/capture-issues/${a.record.row.messagePublicId}`);
    expect(own.body).toMatchObject({ messageId: a.record.row.messagePublicId, status: 'failed' });
    const foreign = await a.http.get(`${A}/capture-issues/${b.record.row.messagePublicId}`);
    expect(foreign.status).toBe(404);
    expect(foreign.body.code).toBe('archive_capture_issue_not_found');
    // B still sees its own intent, unchanged by A's calls (failed, never retried).
    const mine = await b.http.get(`${A}/capture-issues/${b.record.row.messagePublicId}`);
    expect(mine.status).toBe(200);
    expect(mine.body).toMatchObject({ messageId: b.record.row.messagePublicId, status: 'failed' });
  });

  it('legal hold and eDiscovery routes', async () => {
    const checks: Array<[string, () => Promise<{ status: number }>]> = [
      ['hold get', () => a.http.get(`/api/v1/legal-holds/${b.hold}`)],
      [
        'hold release',
        () => a.http.post(`/api/v1/legal-holds/${b.hold}/release`, { reason: 'x' }, key()),
      ],
      ['hold create', () => a.http.post(`${C}/${b.case}/holds`, { name: 'x', reason: 'y' }, key())],
      ['case get', () => a.http.get(`${C}/${b.case}`)],
      [
        'case patch',
        () => a.http.patch(`${C}/${b.case}`, { expectedRowVersion: 1, name: 'x' }, key()),
      ],
      ['case close', () => a.http.post(`${C}/${b.case}/close`, undefined, key())],
      [
        'search create',
        () =>
          a.http.post(
            `${C}/${b.case}/searches`,
            { criteria: { from: '2026-01-01', to: '2026-02-01' } },
            key(),
          ),
      ],
      ['search list', () => a.http.get(`${C}/${b.case}/searches`)],
      ['search get', () => a.http.get(`${C}/${a.case}/searches/${b.search}`)],
      ['hits', () => a.http.get(`${C}/${b.case}/searches/${b.search}/hits`)],
      [
        'review',
        () =>
          a.http.post(
            `${C}/${a.case}/searches/${b.search}/review`,
            { tag: 'relevant', messageIds: [b.record.row.messagePublicId] },
            key(),
          ),
      ],
      ['export create', () => a.http.post(`${C}/${b.case}/exports`, { searchId: b.search }, key())],
      [
        'export create foreign search',
        () => a.http.post(`${C}/${a.case}/exports`, { searchId: b.search }, key()),
      ],
      ['export list', () => a.http.get(`${C}/${b.case}/exports`)],
      ['export get', () => a.http.get(`${C}/${a.case}/exports/${b.export}`)],
      [
        'export grant',
        async () =>
          a.http.post(`${C}/${a.case}/exports/${b.export}/download-grants`, {
            password: a.user.password,
            totpCode: await fx.totpNow(a.user),
          }),
      ],
    ];
    for (const [name, call] of checks) {
      const res = await call();
      expect(res.status, name).toBe(404);
    }
  });
});

describe('lists, search and downloads stay inside the organization', () => {
  it('lists of A never show B’s rows; B’s rows are unchanged', async () => {
    const ids = async (path: string, field = 'id') =>
      ((await a.http.get(path)).body.data as Array<Record<string, string>>).map((x) => x[field]);
    expect(await ids(`${A}/retention-policies`)).not.toContain(b.policy);
    expect(await ids(`${A}/capture-issues`, 'messageId')).not.toContain(
      b.record.row.messagePublicId,
    );
    expect(await ids('/api/v1/legal-holds')).not.toContain(b.hold);
    expect(await ids(C)).not.toContain(b.case);
    expect(
      (await a.http.get(`${A}/keys`)).body.data.every((k: { version: number }) => k.version === 1),
    ).toBe(true);
    expect((await a.http.get(`${A}/disposals`)).status).toBe(200);
    expect((await a.http.get(`${A}/status`)).body.records.active).toBe(1);
    expect((await a.http.get(`${A}/settings`)).body.defaultRetentionPolicyId).toBe(a.policy);
    // Writes of A only touch A (settings, policy, rotation).
    const settings = await a.http.get(`${A}/settings`);
    await a.http.put(
      `${A}/settings`,
      {
        expectedRowVersion: settings.body.rowVersion,
        settings: { access: { downloadEnabled: true, previewEnabled: false } },
      },
      key(),
    );
    await a.http.post(`${A}/retention-policies`, { name: 'A only', retentionDays: 10 }, key());
    await a.http.post(`${A}/keys/rotate`, { reason: 'A only' }, key());
    await a.http.post(C, { name: `A ${randomUUID()}` }, key());
    const bKeys = await ctx.prisma.archiveEncryptionKey.findMany({
      where: { organizationId: b.org.id },
    });
    expect(bKeys.map((k) => [k.version, k.status])).toEqual([[1, 'active']]);
    expect(
      await ctx.prisma.archiveRetentionPolicy.count({ where: { organizationId: b.org.id } }),
    ).toBe(1);
    const bSettings = await ctx.prisma.archiveSetting.findUniqueOrThrow({
      where: { organizationId: b.org.id },
    });
    expect(bSettings.rowVersion).toBe(1);
  });

  it('search runs through A’s alias only; B’s documents are invisible even by id', async () => {
    const res = await a.http.get(`${A}/messages?${RANGE}`);
    expect(res.status).toBe(200);
    const found = res.body.data.map((m: { messageId: string }) => m.messageId);
    expect(found).toEqual([a.record.row.messagePublicId]);
    const alias = tenantAliasName(ax.prefix, a.org.id);
    const direct = await ax.search.search(alias, {
      query: { ids: { values: [b.record.row.messagePublicId] } },
    });
    expect(direct.hits).toEqual([]);
    const term = await ax.search.search(alias, {
      query: { term: { org_id: b.org.id.toString() } },
    });
    expect(term.hits).toEqual([]);
    const own = await ax.search.search(alias, { query: { match_all: {} } });
    expect(own.hits.map((h) => h._id)).toEqual([a.record.row.messagePublicId]);
  });

  it('B’s download token is refused for A’s user', async () => {
    const grant = await b.http.post(
      `${A}/messages/${b.record.row.messagePublicId}/download-grants`,
      {
        password: b.user.password,
        totpCode: await fx.totpNow(b.user),
      },
    );
    expect(grant.status, JSON.stringify(grant.body)).toBe(201);
    const stolen = await a.http.get(`${A}/downloads/${grant.body.token}`);
    expect(stolen.status).toBe(404);
    expect(stolen.body.code).toBe('archive_download_token_invalid');
    const row = await ctx.prisma.archiveDownloadGrant.findFirstOrThrow({
      where: { organizationId: b.org.id },
    });
    expect(row.consumedAt).toBeNull();
  });
});
