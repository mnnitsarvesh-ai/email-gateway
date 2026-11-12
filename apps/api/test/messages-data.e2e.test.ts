/**
 * The step 6.1 WP2 message data routes besides the list (detail, recipients, attachments and the
 * hash search, URLs, URL clicks) over HTTP with MySQL, Redis and S3 stubbed and the WP2
 * repositories replaced by in-memory doubles (test/support/messages-fixtures.ts): shapes,
 * cursors, strict validation, 404 for another organization's ids, RBAC, the `expensive` class
 * 429 and the OpenAPI operations. Real SQL runs in integration/messages-data.test.ts.
 */
// @covers get /api/v1/messages/:messageId
// @covers get /api/v1/messages/:messageId/recipients
// @covers get /api/v1/messages/:messageId/attachments
// @covers get /api/v1/attachments
// @covers get /api/v1/messages/:messageId/urls
// @covers get /api/v1/url-protection/clicks
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildOpenApiDocument } from '../src/http/openapi';
import type { LatestResultRow } from '../src/modules/attachments/attachments.repository';
import type { MessageUrlFullRow } from '../src/modules/url-protection/url-protection.repository';
import { createStubbedApiApp, type StubbedApiApp } from './support/api-test-app';
import {
  type OpenApiOperation,
  MessagesWorld,
  overrideMessagesData,
  RecordingAuditService,
  type WorldMessage,
} from './support/messages-fixtures';

const READ = 'message:read';
const OTHER_ORG = 2n;
const HASH = 'c0ffee'.padEnd(64, '0');

function seed(world: MessagesWorld, org: bigint): WorldMessage {
  const message = world.addMessage(org, {
    recipients: ['alice@acme.example', 'bob@acme.example', 'carol@acme.example'],
    attachmentCount: 2,
  });
  const [first] = world.recipients.filter((r) => r.messageId === message.id);
  world.users.push({ id: 900n + org, publicId: randomUUID(), organizationId: org });
  first!.userId = 900n + org;
  world.deliveries.push(
    {
      organizationId: org,
      messageId: message.id,
      recipientId: first!.id,
      deliverySeq: 0,
      status: 'deferred',
      finalSmtpCode: 451,
      deliveredAt: null,
    },
    {
      organizationId: org,
      messageId: message.id,
      recipientId: first!.id,
      deliverySeq: 1,
      status: 'delivered',
      finalSmtpCode: 250,
      deliveredAt: new Date(),
    },
  );
  const scanId = world.id();
  world.scans.push({ id: scanId, messageId: message.id, organizationId: org, lifecycleRound: 0 });
  for (const partIndex of [1, 2]) {
    const id = world.id();
    world.attachments.push({
      id,
      organizationId: org,
      messageId: message.id,
      receivedAt: message.receivedAt,
      partIndex,
      filename: `file-${partIndex}.pdf`,
      declaredContentType: 'application/pdf',
      detectedContentType: 'application/pdf',
      sizeBytes: 100,
      sha256: HASH,
      disposition: 'attachment',
      depth: 1,
    });
    world.attachmentResults.push({
      scanId,
      attachmentId: id,
      partIndex,
      sha256: HASH,
      sizeBytes: 100,
      detectedType: 'pdf',
      typeFamily: 'document',
      typeMismatch: false,
      verdict: 'clean',
      reasonCodes: ['clean.no_findings'],
      clamavSignature: null,
      clamavEngineVersion: '1.4.1',
      clamavDbVersion: 1,
      yaraBundleId: null,
      yaraMatches: null,
      archive: null,
      knownHashSeverity: null,
      organizationId: org,
    } as unknown as LatestResultRow);
  }
  for (const urlSeq of [0, 1]) {
    world.urls.push({
      urlSeq,
      url: `https://link.example/${urlSeq}`,
      urlSha256: String(urlSeq).repeat(64),
      host: 'link.example',
      unicodeHost: null,
      registrableDomain: 'link.example',
      hostKind: 'domain',
      flags: [],
      sources: { html_href: 1 },
      organizationId: org,
      messageId: message.id,
    } as unknown as MessageUrlFullRow);
    world.urlResults.push({
      scanId,
      urlSeq,
      urlSha256: String(urlSeq).repeat(64),
      verdict: urlSeq === 0 ? 'malicious' : 'clean',
      reasonCodes: [urlSeq === 0 ? 'url.feed_malicious' : 'clean.no_findings'],
      rewritten: true,
      organizationId: org,
      messageId: message.id,
    });
  }
  for (let i = 0; i < 3; i += 1) {
    world.clicks.push({
      id: world.id(),
      clickedAt: new Date(Date.now() - (i + 1) * 60_000),
      publicId: randomUUID(),
      organizationId: org,
      messageId: message.id,
      messageReceivedAt: message.receivedAt,
      urlSeq: 0,
      decision: i === 0 ? 'blocked' : 'continued',
      verdict: 'malicious',
      reasonCodes: ['url.feed_malicious'],
      clientNetwork: '203.0.113.0/24',
    });
  }
  return message;
}

describe('message data routes (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new MessagesWorld();
  let own: WorldMessage;
  let foreign: WorldMessage;

  beforeAll(async () => {
    api = await createStubbedApiApp(
      {},
      { override: (b) => overrideMessagesData(b, world, new RecordingAuditService()) },
    );
    own = seed(world, api.principals.organizationId);
    foreign = seed(world, OTHER_ORG);
  });

  afterAll(async () => {
    await api?.close();
  });

  const get = async (path: string, headers?: Record<string, string>) =>
    api
      .http()
      .get(`/api/v1${path}`)
      .set(headers ?? (await api.principals.user([READ]).bearer()));

  const messagePaths = (id: string) => [
    `/messages/${id}`,
    `/messages/${id}/recipients`,
    `/messages/${id}/attachments`,
    `/messages/${id}/urls`,
  ];

  it('detail: the detail fields, never the object key', async () => {
    const res = await get(`/messages/${own.publicId}`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      id: own.publicId,
      internetMessageId: own.internetMessageId,
      version: 3,
      lifecycleRound: 0,
      clientIp: '198.51.100.1',
      mtaQueueId: 'QID1',
    });
    expect(res.body).not.toHaveProperty('emlObjectKey');
  });

  it('recipients: rcptSeq order, latest delivery, user public id, cursor paging', async () => {
    const first = await get(`/messages/${own.publicId}/recipients?limit=2`);
    expect(first.status).toBe(200);
    expect(first.body.data.map((r: { rcptSeq: number }) => r.rcptSeq)).toEqual([0, 1]);
    expect(first.body.data[0]).toMatchObject({
      address: 'alice@acme.example',
      userId: world.users[0]!.publicId,
      latestDelivery: { deliverySeq: 1, status: 'delivered', finalSmtpCode: 250 },
    });
    expect(first.body.data[1].latestDelivery).toBeNull();
    const second = await get(
      `/messages/${own.publicId}/recipients?limit=2&cursor=${encodeURIComponent(first.body.nextCursor)}`,
    );
    expect(second.body).toEqual({
      data: [expect.objectContaining({ rcptSeq: 2 })],
      nextCursor: null,
    });
    // The cursor is bound to the message.
    const other = await get(
      `/messages/${randomUUID()}/recipients?cursor=${encodeURIComponent(first.body.nextCursor)}`,
    );
    expect(other.status).toBe(400);
    expect(other.body.code).toBe('cursor_invalid');
  });

  it('attachments: metadata and the latest round through the scans mapper', async () => {
    const res = await get(`/messages/${own.publicId}/attachments`);
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(2);
    expect(res.body.data[0]).toMatchObject({
      partIndex: 1,
      filename: 'file-1.pdf',
      sha256: HASH,
      verdict: 'clean',
      latestScan: { round: 0, verdict: 'clean', reasonCodes: ['clean.no_findings'] },
    });
    expect(JSON.stringify(res.body)).not.toMatch(/objectKey|originalFilename|cache/);
  });

  it('attachment search: own rows only, newest first, sha256 required and validated', async () => {
    const res = await get(`/attachments?sha256=${HASH.toUpperCase()}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(2);
    expect(res.body.data.every((d: { messageId: string }) => d.messageId === own.publicId)).toBe(
      true,
    );
    expect(res.body.data[0]).toMatchObject({ verdict: 'clean', filename: expect.any(String) });
    for (const query of [
      '',
      '?sha256=abc',
      `?sha256=${'z'.repeat(64)}`,
      `?sha256=${HASH}&name=x`,
    ]) {
      const bad = await get(`/attachments${query}`);
      expect(bad.status, query).toBe(400);
      expect(bad.body.code).toBe('validation_failed');
    }
    const to = new Date();
    const tooLong = await get(
      `/attachments?sha256=${HASH}&from=${new Date(to.getTime() - 40 * 86_400_000).toISOString()}&to=${to.toISOString()}`,
    );
    expect(tooLong.status).toBe(400);
  });

  it('URLs: tenant URL fields, latest verdict, clicks by decision', async () => {
    const res = await get(`/messages/${own.publicId}/urls`);
    expect(res.status).toBe(200);
    expect(res.body.data[0]).toMatchObject({
      urlSeq: 0,
      host: 'link.example',
      latest: {
        round: 0,
        verdict: 'malicious',
        reasonCodes: ['url.feed_malicious'],
        rewritten: true,
      },
      clicks: { total: 3, byDecision: { blocked: 1, continued: 2 } },
    });
    expect(res.body.data[1].clicks).toEqual({ total: 0, byDecision: {} });
    expect(JSON.stringify(res.body)).not.toMatch(/fetchCache|cache|reputation/);
  });

  it('clicks: own clicks newest first, filters, host join, no token material', async () => {
    const res = await get('/url-protection/clicks');
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(3);
    expect(res.body.data[0]).toMatchObject({
      decision: 'blocked',
      messageId: own.publicId,
      host: 'link.example',
      registrableDomain: 'link.example',
    });
    expect(JSON.stringify(res.body)).not.toMatch(/tokenKid|token_kid|recheck/);
    expect((await get('/url-protection/clicks?decision=continued')).body.data).toHaveLength(2);
    expect(
      (await get(`/url-protection/clicks?messageId=${own.publicId}&verdict=malicious`)).body.data,
    ).toHaveLength(3);
    const paged = await get('/url-protection/clicks?limit=2');
    const next = await get(
      `/url-protection/clicks?limit=2&cursor=${encodeURIComponent(paged.body.nextCursor)}`,
    );
    expect(next.body.data).toHaveLength(1);
    for (const query of ['?decision=maybe', '?decision.gte=x', '?messageId=x', '?token=1']) {
      const bad = await get(`/url-protection/clicks${query}`);
      expect(bad.status, query).toBe(400);
    }
    const to = new Date();
    const tooLong = await get(
      `/url-protection/clicks?from=${new Date(to.getTime() - 32 * 86_400_000).toISOString()}&to=${to.toISOString()}`,
    );
    expect(tooLong.status).toBe(400);
  });

  it("another organization's message is 404 message_not_found on every route and filter", async () => {
    for (const path of [
      ...messagePaths(foreign.publicId),
      ...messagePaths(randomUUID()),
      `/url-protection/clicks?messageId=${foreign.publicId}`,
    ]) {
      const res = await get(path);
      expect(res.status, path).toBe(404);
      expect(res.body.code).toBe('message_not_found');
    }
  });

  it('bad ids, unknown query fields and bad cursors are 400', async () => {
    for (const path of messagePaths('not-a-uuid')) {
      expect((await get(path)).status, path).toBe(400);
    }
    for (const path of messagePaths(own.publicId).slice(1)) {
      const unknown = await get(`${path}?foo=1`);
      expect(unknown.status, path).toBe(400);
      expect(unknown.body.code).toBe('validation_failed');
      const cursor = await get(`${path}?cursor=bad`);
      expect(cursor.status, path).toBe(400);
      expect(cursor.body.code).toBe('cursor_invalid');
    }
    for (const path of [
      `/attachments?sha256=${HASH}&cursor=bad`,
      '/url-protection/clicks?cursor=bad',
    ]) {
      expect((await get(path)).body.code).toBe('cursor_invalid');
    }
  });

  it('RBAC: 403 without message:read for users and API keys; API keys accepted', async () => {
    const paths = [
      ...messagePaths(own.publicId),
      `/attachments?sha256=${HASH}`,
      '/url-protection/clicks',
    ];
    const userWithout = await api.principals.user(['delivery:read']).bearer();
    for (const path of paths) {
      expect((await get(path, userWithout)).status, path).toBe(403);
      expect((await api.http().get(`/api/v1${path}`)).status, path).toBe(401);
    }
    api.principals.apiKeyWith(['delivery:read']);
    for (const path of paths)
      expect((await get(path, api.principals.apiKeyHeaders)).status).toBe(403);
    api.principals.apiKeyWith([READ]);
    for (const path of paths)
      expect((await get(path, api.principals.apiKeyHeaders)).status).toBe(200);
  });

  it('documents every operation with its tag, permission, cursor and an example', () => {
    const doc = buildOpenApiDocument(api.app);
    const ops: Array<[string, string, string | null]> = [
      ['/api/v1/messages/{messageId}', 'messages', null],
      ['/api/v1/messages/{messageId}/recipients', 'messages', 'v1'],
      ['/api/v1/messages/{messageId}/attachments', 'attachments', 'v1'],
      ['/api/v1/attachments', 'attachments', 'v1'],
      ['/api/v1/messages/{messageId}/urls', 'url-protection', 'v1'],
      ['/api/v1/url-protection/clicks', 'url-protection', 'v1'],
    ];
    for (const [path, tag, cursor] of ops) {
      const op = doc.paths[path]?.get as unknown as OpenApiOperation | undefined;
      expect(op, path).toBeDefined();
      expect(op!.tags).toEqual([tag]);
      expect(op!.summary).toEqual(expect.any(String));
      expect(op!['x-eg-permissions']).toEqual({ mode: 'all', permissions: [READ] });
      expect(op!['x-eg-cursor']).toBe(cursor ?? undefined);
      expect(op!.responses['200']!.content['application/json']!.schema.example).toBeDefined();
      for (const status of ['400', '401', '403', '429'])
        expect(op!.responses[status], `${path} ${status}`).toBeDefined();
    }
    const search = doc.paths['/api/v1/attachments']!.get as unknown as OpenApiOperation;
    expect(search['x-eg-rate-class']).toBe('expensive');
    expect(search.parameters.find((p: { name: string }) => p.name === 'sha256')!.required).toBe(
      true,
    );
  });
});

describe('GET /api/v1/attachments 429 (expensive class)', () => {
  let api: StubbedApiApp;
  beforeAll(async () => {
    api = await createStubbedApiApp(
      { API_RATE_EXPENSIVE_PER_MINUTE: '2' },
      {
        override: (b) => overrideMessagesData(b, new MessagesWorld(), new RecordingAuditService()),
      },
    );
  });
  afterAll(async () => {
    await api?.close();
  });

  it('answers 429 with scope expensive, RateLimit headers and Retry-After', async () => {
    const bearer = await api.principals.user([READ]).bearer();
    for (let i = 0; i < 2; i += 1) {
      expect((await api.http().get(`/api/v1/attachments?sha256=${HASH}`).set(bearer)).status).toBe(
        200,
      );
    }
    const res = await api.http().get(`/api/v1/attachments?sha256=${HASH}`).set(bearer);
    expect(res.status).toBe(429);
    expect(res.body).toMatchObject({ code: 'rate_limited', scope: 'expensive' });
    expect(res.headers['ratelimit-limit']).toBe('2');
    expect(res.headers['ratelimit-remaining']).toBe('0');
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    // Other classes are unaffected.
    expect((await api.http().get('/api/v1/url-protection/clicks').set(bearer)).status).toBe(200);
  });
});
