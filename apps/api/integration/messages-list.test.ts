/**
 * `GET /api/v1/messages` (step 6.1 WP2, D3–D6, D11) against the real MySQL writer and replica,
 * Redis and the in-process api: every plan of D5 (index, verdict, recipient, scan-bounded) over
 * seeded rows (replica visibility polled), pagination with the signed cursor and the pinned
 * window, the scan budget's short pages, the domain filter, the audited searches
 * (`audit_logs` rows with hashed values only) and the 404 of a foreign domain. The EXPLAIN plans
 * at volume run in messages-explain.test.ts.
 */
// @covers get /api/v1/messages
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa } from './support/http';
import {
  deleteMessagesData,
  getAs,
  POLL,
  type SeededMessage,
  seedMessage,
} from './support/messages-data';

const MIN = 60_000;

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let other: FixtureOrganization;
let admin: Record<string, string>;
let key: Record<string, string>;
let seeded: SeededMessage[];
let domainPublicId: string;
const runId = randomUUID().slice(0, 8);
const hot = `hot-${runId}@acme.example`;

beforeAll(async () => {
  // Scan budget at its minimum (1 000) so the scan plan's short pages are reachable.
  ctx = await createIntegrationApp({ API_LIST_SCAN_BUDGET_ROWS: '1000' });
  fx = createFixtures(ctx);
  [org, other] = [await fx.createOrganization(), await fx.createOrganization()];
  fx.registerCleanup(() => deleteMessagesData(ctx, [org.id, other.id]));
  admin = bearer(
    (await loginWithMfa(ctx, fx, await fx.createUser(org, { roles: ['organization_admin'] })))
      .accessToken,
  );
  key = apiKeyHeader(await fx.createApiKey(org, ['message:read']));
  const domain = await ctx.prisma.domain.create({
    data: { organizationId: org.id, name: `list-${runId}.example` },
    select: { id: true, publicId: true },
  });
  domainPublicId = domain.publicId;
  const now = Date.now();
  seeded = [];
  for (let i = 0; i < 6; i += 1) {
    seeded.push(
      await seedMessage(ctx, org, {
        receivedAt: new Date(now - (i + 1) * 10 * MIN),
        verdict: i % 2 === 0 ? 'phishing' : 'clean',
        direction: i === 5 ? 'outbound' : 'inbound',
        domainId: i < 2 ? domain.id : null,
        recipients:
          i === 1
            ? [hot, `x-${runId}@acme.example`]
            : i === 3
              ? [hot]
              : [`r${i}-${runId}@acme.example`],
        envelopeFrom: i === 4 ? `boss-${runId}@corp.example` : `sender-${runId}@vendor.example`,
        riskScore: i * 150,
      }),
    );
  }
  // Same shapes in another organization (same hot recipient): never listed.
  for (let i = 0; i < 3; i += 1) {
    await seedMessage(ctx, other, {
      receivedAt: new Date(now - (i + 1) * 10 * MIN),
      recipients: [hot],
      verdict: 'phishing',
    });
  }
  // A message outside the default 24 h window.
  seeded.push(await seedMessage(ctx, org, { receivedAt: new Date(now - 30 * 60 * MIN) }));
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

const ids = (body: { data: Array<{ id: string }> }) => body.data.map((d) => d.id);
const list = (query: string, headers = admin) => getAs(ctx, headers, `/messages${query}`);

describe('GET /messages against the replica', () => {
  it('index plan: the last 24 h, newest first, own rows only (replica visibility polled)', async () => {
    await expect
      .poll(async () => ids((await list('')).body), POLL)
      .toEqual(seeded.slice(0, 6).map((m) => m.publicId));
    const res = await list('?limit=4', key);
    expect(res.status).toBe(200);
    expect(res.body.data[0]).toMatchObject({
      id: seeded[0]!.publicId,
      finalVerdict: 'phishing',
      domainId: domainPublicId,
      recipientCount: 1,
      sizeBytes: 2048,
    });
    expect(JSON.stringify(res.body)).not.toMatch(/emlObjectKey|org\//);
  });

  it('pages with the cursor in both sorts; the window stays pinned', async () => {
    const first = await list('?limit=4');
    const second = await list(`?limit=4&cursor=${encodeURIComponent(first.body.nextCursor)}`);
    expect([...ids(first.body), ...ids(second.body)]).toEqual(
      seeded.slice(0, 6).map((m) => m.publicId),
    );
    expect(second.body.nextCursor).toBeNull();
    const asc = await list('?sort=receivedAt&limit=3');
    expect(ids(asc.body)).toEqual(
      seeded
        .slice(3, 6)
        .map((m) => m.publicId)
        .reverse(),
    );
    // An explicit, wider window includes the old message.
    const from = new Date(Date.now() - 2 * 86_400_000).toISOString();
    expect(ids((await list(`?from=${from}`)).body)).toContain(seeded[6]!.publicId);
  });

  it('verdict plan and the scan-bounded combinations', async () => {
    expect(ids((await list('?verdict=phishing')).body)).toEqual(
      [0, 2, 4].map((i) => seeded[i]!.publicId),
    );
    expect(ids((await list('?verdict=phishing,clean&direction=outbound')).body)).toEqual([
      seeded[5]!.publicId,
    ]);
    expect(ids((await list(`?domainId=${domainPublicId}`)).body)).toEqual(
      [0, 1].map((i) => seeded[i]!.publicId),
    );
    expect(ids((await list('?riskScore.gte=300&riskScore.lte=600')).body)).toEqual(
      [2, 3, 4].map((i) => seeded[i]!.publicId),
    );
    expect(ids((await list(`?verdict=clean&recipient=${hot}`)).body)).toEqual(
      [1, 3].map((i) => seeded[i]!.publicId),
    );
  });

  it('recipient plan: own messages to the address, a message with the address twice once', async () => {
    const res = await list(`?recipient=${hot.toUpperCase()}`);
    expect(ids(res.body)).toEqual([1, 3].map((i) => seeded[i]!.publicId));
  });

  it('a foreign or unknown domainId is 404 domain_not_found', async () => {
    const foreign = await ctx.prisma.domain.create({
      data: { organizationId: other.id, name: `other-${runId}.example` },
      select: { publicId: true },
    });
    for (const id of [foreign.publicId, randomUUID()]) {
      const res = await list(`?domainId=${id}`);
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('domain_not_found');
    }
  });

  it('audits identifying searches (first page only) with hashed values', async () => {
    const before = new Date(Date.now() - 1000);
    const sender = `boss-${runId}@corp.example`;
    const first = await list(`?sender=${sender}&limit=1`);
    expect(ids(first.body)).toEqual([seeded[4]!.publicId]);
    await list(
      `?sender=${sender}&limit=1&cursor=${encodeURIComponent(first.body.nextCursor ?? 'x')}`,
    );
    const rows = (
      await ctx.prisma.auditLog.findMany({
        where: { organizationId: org.id, action: 'message.searched', createdAt: { gte: before } },
      })
    ).filter((r) => ((r.metadata as { filters?: string[] }).filters ?? []).includes('sender'));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ resourceType: 'message', actorType: 'user' });
    const metadata = rows[0]!.metadata as Record<string, unknown>;
    expect(metadata).toMatchObject({ filters: ['sender'], plan: 'scan', resultCount: 1 });
    expect(JSON.stringify(metadata)).not.toContain(sender);
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: other.id, action: 'message.searched' },
      }),
    ).toBe(0);
  });

  it('an organization B cursor is cursor_invalid for A and the other way round', async () => {
    const keyB = apiKeyHeader(await fx.createApiKey(other, ['message:read']));
    const b = await list('?limit=1', keyB);
    expect(b.body.nextCursor).toEqual(expect.any(String));
    const res = await list(`?limit=1&cursor=${encodeURIComponent(b.body.nextCursor)}`);
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('cursor_invalid');
  });
});
