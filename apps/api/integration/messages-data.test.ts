/**
 * The step 6.1 WP2 message data routes besides the list against the real MySQL writer and
 * replica: detail, recipients with their latest delivery, attachments with the latest round
 * (scans view mapper) and the audited hash search, URLs with verdicts, rewrite and click counts,
 * and the click log with its filters, over seeded rows (replica visibility polled). Never object
 * keys, original filenames, cache outcomes or token material.
 */
// @covers get /api/v1/messages/:messageId
// @covers get /api/v1/messages/:messageId/recipients
// @covers get /api/v1/messages/:messageId/attachments
// @covers get /api/v1/attachments
// @covers get /api/v1/messages/:messageId/urls
// @covers get /api/v1/url-protection/clicks
import { createHash, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader } from './support/http';
import {
  dataLength,
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
let key: Record<string, string>;
let message: SeededMessage;
let older: SeededMessage;
const hash = createHash('sha256').update(randomUUID()).digest('hex');

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  fx.registerCleanup(() => deleteMessagesData(ctx, [org.id]));
  key = apiKeyHeader(await fx.createApiKey(org, ['message:read']));
  const now = Date.now();
  message = await seedMessage(ctx, org, {
    receivedAt: new Date(now - 30 * MIN),
    recipients: ['alice@acme.example', 'bob@acme.example', 'carol@acme.example'],
    attachments: [
      { sha256: hash, filename: 'invoice.pdf' },
      { sha256: 'e'.repeat(64), verdict: 'malicious' },
    ],
    urls: [
      { url: 'https://bad.example/login', host: 'bad.example', verdict: 'malicious' },
      { url: 'https://good.example/', host: 'good.example' },
    ],
    clicks: [
      { urlSeq: 0, decision: 'blocked', clickedAt: new Date(now - 20 * MIN) },
      { urlSeq: 0, decision: 'continued', clickedAt: new Date(now - 10 * MIN) },
      { urlSeq: 1, decision: 'allowed', clickedAt: new Date(now - 5 * MIN), verdict: 'clean' },
    ],
  });
  older = await seedMessage(ctx, org, {
    receivedAt: new Date(now - 3 * 60 * MIN),
    attachments: [{ sha256: hash, verdict: 'suspicious' }],
  });
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

const get = (path: string) => getAs(ctx, key, path);

describe('message data routes against the replica', () => {
  it('detail', async () => {
    await expect
      .poll(async () => (await get(`/messages/${message.publicId}`)).status, POLL)
      .toBe(200);
    const res = await get(`/messages/${message.publicId}`);
    expect(res.body).toMatchObject({
      id: message.publicId,
      version: 3,
      lifecycleRound: 0,
      clientIp: '198.51.100.7',
      clientHelo: 'mx.vendor.example',
      mtaQueueId: 'FIXTUREQ1',
      recipientCount: 3,
      attachmentCount: 2,
    });
    expect(JSON.stringify(res.body)).not.toMatch(/emlObjectKey|org\//);
    expect((await get(`/messages/${randomUUID()}`)).body.code).toBe('message_not_found');
  });

  it('recipients with the latest delivery, paged', async () => {
    await expect
      .poll(
        async () => dataLength(await get(`/messages/${message.publicId}/recipients?limit=2`)),
        POLL,
      )
      .toBe(2);
    const first = await get(`/messages/${message.publicId}/recipients?limit=2`);
    expect(first.body.data[0]).toMatchObject({
      rcptSeq: 0,
      address: 'alice@acme.example',
      status: 'delivered',
      latestDelivery: { deliverySeq: 1, status: 'delivered', finalSmtpCode: 250 },
    });
    expect(first.body.data[1].latestDelivery).toBeNull();
    const second = await get(
      `/messages/${message.publicId}/recipients?limit=2&cursor=${encodeURIComponent(first.body.nextCursor)}`,
    );
    expect(second.body).toEqual({
      data: [expect.objectContaining({ rcptSeq: 2 })],
      nextCursor: null,
    });
  });

  it('attachments with the latest round, sanitized filename only', async () => {
    await expect
      .poll(async () => dataLength(await get(`/messages/${message.publicId}/attachments`)), POLL)
      .toBe(2);
    const res = await get(`/messages/${message.publicId}/attachments`);
    expect(res.body.data[0]).toMatchObject({
      partIndex: 1,
      filename: 'invoice.pdf',
      sha256: hash,
      disposition: 'attachment',
      depth: 1,
      verdict: 'clean',
      latestScan: {
        round: 0,
        verdict: 'clean',
        reasonCodes: ['clean.no_findings'],
        detectedType: 'pdf',
      },
    });
    expect(res.body.data[1]).toMatchObject({
      verdict: 'malicious',
      latestScan: { reasonCodes: ['malware.clamav'] },
    });
    expect(JSON.stringify(res.body)).not.toMatch(/ORIGINAL|objectKey|\.att|cache/);
  });

  it('attachment hash search: newest first, cursor, audited with the hash hashed', async () => {
    const before = new Date(Date.now() - 1000);
    const from = new Date(Date.now() - 86_400_000).toISOString();
    await expect
      .poll(async () => dataLength(await get(`/attachments?sha256=${hash}&from=${from}`)), POLL)
      .toBe(2);
    const first = await get(`/attachments?sha256=${hash.toUpperCase()}&from=${from}&limit=1`);
    expect(first.body.data).toEqual([
      expect.objectContaining({
        messageId: message.publicId,
        partIndex: 1,
        filename: 'invoice.pdf',
        verdict: 'clean',
      }),
    ]);
    const second = await get(
      `/attachments?sha256=${hash}&from=${from}&limit=1&cursor=${encodeURIComponent(first.body.nextCursor)}`,
    );
    expect(second.body.data).toEqual([
      expect.objectContaining({ messageId: older.publicId, verdict: 'suspicious' }),
    ]);
    const rows = await ctx.prisma.auditLog.findMany({
      where: { organizationId: org.id, action: 'attachment.searched', createdAt: { gte: before } },
      orderBy: { id: 'asc' },
    });
    // The polled first pages and the explicit first page are audited; the cursor page is not.
    expect(rows.length).toBeGreaterThanOrEqual(2);
    expect(rows.at(-1)).toMatchObject({ resourceType: 'attachment', actorType: 'api_key' });
    expect((rows.at(-1)!.metadata as Record<string, unknown>).resultCount).toBe(1);
    expect(JSON.stringify(rows.map((r) => r.metadata))).not.toContain(hash);
  });

  it('URLs with the latest verdict, rewrite and clicks by decision', async () => {
    await expect
      .poll(async () => dataLength(await get(`/messages/${message.publicId}/urls`)), POLL)
      .toBe(2);
    const res = await get(`/messages/${message.publicId}/urls`);
    expect(res.body.data[0]).toMatchObject({
      urlSeq: 0,
      url: 'https://bad.example/login',
      host: 'bad.example',
      sources: { html_href: 1 },
      latest: {
        round: 0,
        verdict: 'malicious',
        reasonCodes: ['url.feed_malicious'],
        rewritten: true,
      },
      rewrite: { round: 0, status: 'rewritten', skipReason: null },
      clicks: { total: 2, byDecision: { blocked: 1, continued: 1 } },
    });
    expect(res.body.data[1].clicks).toEqual({ total: 1, byDecision: { allowed: 1 } });
    expect(JSON.stringify(res.body)).not.toMatch(/fetchCache|tokenKid|cache/);
  });

  it('clicks: newest first with host join, filters, messageId, cursor', async () => {
    await expect.poll(async () => dataLength(await get('/url-protection/clicks')), POLL).toBe(3);
    const res = await get('/url-protection/clicks');
    expect(res.body.data.map((c: { id: string }) => c.id)).toEqual(
      [...message.clickPublicIds].reverse(),
    );
    expect(res.body.data[0]).toMatchObject({
      decision: 'allowed',
      verdict: 'clean',
      messageId: message.publicId,
      urlSeq: 1,
      host: 'good.example',
      registrableDomain: 'good.example',
      clientNetwork: '203.0.113.0/24',
      reasonCodes: ['url.feed_malicious'],
    });
    expect(JSON.stringify(res.body)).not.toMatch(/tokenKid|token_kid|recheck|duration/);
    expect((await get('/url-protection/clicks?decision=blocked,continued')).body.data).toHaveLength(
      2,
    );
    expect((await get('/url-protection/clicks?verdict=clean')).body.data).toHaveLength(1);
    expect(
      (await get(`/url-protection/clicks?messageId=${message.publicId}`)).body.data,
    ).toHaveLength(3);
    expect(
      (await get(`/url-protection/clicks?messageId=${older.publicId}`)).body.data,
    ).toHaveLength(0);
    const page = await get('/url-protection/clicks?limit=2');
    const next = await get(
      `/url-protection/clicks?limit=2&cursor=${encodeURIComponent(page.body.nextCursor)}`,
    );
    expect(next.body).toEqual({
      data: [expect.objectContaining({ decision: 'blocked' })],
      nextCursor: null,
    });
  });
});
