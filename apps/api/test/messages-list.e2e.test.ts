/**
 * `GET /api/v1/messages` (step 6.1 WP2, D3–D6, D11; step 7.2 §2 E1, E2) over HTTP with MySQL,
 * Redis and S3 stubbed and the repositories replaced by in-memory doubles
 * (test/support/messages-fixtures.ts): the list shape, the search drivers by filter, v1 cursor
 * pagination and its refusals, strict query validation, the domain filter, RBAC (users and API
 * keys), the filter-level permissions per system role, the 422/503 refusals of the subject prefix,
 * the audited searches, the 429 of the global limiter, and the operation in the OpenAPI document.
 * The SQL drivers, EXPLAIN checks and the real replica run in integration/messages-list.test.ts,
 * messages-search.test.ts and messages-explain.test.ts.
 */
// @covers get /api/v1/messages
import { createHash, randomUUID } from 'node:crypto';
import { SYSTEM_ROLES } from '@email-gateway/database';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildOpenApiDocument } from '../src/http/openapi';
import { createStubbedApiApp, type StubbedApiApp } from './support/api-test-app';
import {
  type OpenApiOperation,
  MessagesWorld,
  overrideMessagesData,
  RecordingAuditService,
} from './support/messages-fixtures';

const READ = 'message:read';
const REVEAL = 'message:reveal';
const OTHER_ORG = 2n;
const HOUR = 3_600_000;

describe('GET /api/v1/messages (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  let world: MessagesWorld;
  const audit = new RecordingAuditService();
  let domainId: string;

  beforeAll(async () => {
    world = new MessagesWorld();
    api = await createStubbedApiApp({}, { override: (b) => overrideMessagesData(b, world, audit) });
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    world.messages = [];
    world.recipients = [];
    world.domains = [];
    audit.entries.length = 0;
    api.kv.entries.clear();
    const now = Date.now();
    const org = api.principals.organizationId;
    domainId = randomUUID();
    world.domains.push({ id: 77n, publicId: domainId, organizationId: org });
    for (let i = 0; i < 5; i += 1) {
      world.addMessage(org, {
        receivedAt: new Date(now - (i + 1) * HOUR),
        finalVerdict: i % 2 === 0 ? 'spam' : 'clean',
        direction: i === 4 ? 'outbound' : 'inbound',
        domainId: i === 0 ? 77n : null,
        recipients: i === 1 ? ['bob@acme.example', 'carol@acme.example'] : ['alice@acme.example'],
        attachmentCount: i === 2 ? 2 : 0,
        riskScore: i * 200,
      });
    }
    // Identical rows of another organization: never listed.
    for (let i = 0; i < 5; i += 1) {
      world.addMessage(OTHER_ORG, { receivedAt: new Date(now - (i + 1) * HOUR) });
    }
  });

  const list = async (query = '', headers?: Record<string, string>) =>
    api
      .http()
      .get(`/api/v1/messages${query}`)
      .set(headers ?? (await api.principals.user([READ]).bearer()));

  it('lists the newest messages of the last 24 h with the item fields and no internal data', async () => {
    const res = await list();
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(5);
    expect(res.body.nextCursor).toBeNull();
    const own = world.messages.filter((m) => m.organizationId === api.principals.organizationId);
    expect(res.body.data.map((d: { id: string }) => d.id)).toEqual(own.map((m) => m.publicId));
    expect(Object.keys(res.body.data[0]).sort()).toEqual(
      [
        'attachmentCount',
        'direction',
        'domainId',
        'envelopeFrom',
        'finalAction',
        'finalVerdict',
        'headerFrom',
        'id',
        'receivedAt',
        'recipientCount',
        'riskScore',
        'sizeBytes',
        'status',
        'statusChangedAt',
        'subject',
        'subjectMasked',
      ].sort(),
    );
    expect(res.body.data[0].domainId).toBe(domainId);
    // Step 7.2 (§2 E5): the subject is withheld for every caller.
    for (const item of res.body.data as Array<{ subject: unknown; subjectMasked: boolean }>) {
      expect(item.subject).toBeNull();
      expect(item.subjectMasked).toBe(true);
    }
    expect(JSON.stringify(res.body)).not.toMatch(/emlObjectKey|organizationId/);
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('pages with a signed cursor that pins the window; ascending sort', async () => {
    const first = await list('?limit=2');
    expect(first.body.data).toHaveLength(2);
    expect(first.body.nextCursor).toEqual(expect.any(String));
    const second = await list(`?limit=2&cursor=${encodeURIComponent(first.body.nextCursor)}`);
    const third = await list(`?limit=2&cursor=${encodeURIComponent(second.body.nextCursor)}`);
    expect(third.body.nextCursor).toBeNull();
    const ids = [...first.body.data, ...second.body.data, ...third.body.data].map(
      (d: { id: string }) => d.id,
    );
    expect(new Set(ids).size).toBe(5);
    const asc = await list('?sort=receivedAt&limit=5');
    expect(asc.body.data.map((d: { id: string }) => d.id)).toEqual([...ids].reverse());
  });

  it('filters: one verdict, several verdicts, recipient, direction, domain, risk, attachments', async () => {
    const count = async (query: string) =>
      ((await list(query)).body as { data: unknown[] }).data.length;
    expect(await count('?verdict=spam')).toBe(3);
    expect(await count('?verdict=spam,clean')).toBe(5);
    // The exact recipient needs message:reveal (it confirms a masked address, ADR-0062).
    const revealer = await api.principals.user([READ, REVEAL]).bearer();
    const byRecipient = await list('?recipient=Carol@Acme.example', revealer);
    expect(byRecipient.body.data).toHaveLength(1);
    const refused = await list('?recipient=Carol@Acme.example');
    expect(refused.status).toBe(403);
    expect(refused.body).toMatchObject({
      code: 'message_filter_forbidden',
      filter: 'recipient',
      permission: REVEAL,
    });
    expect(await count('?recipientDomain=Acme.example')).toBe(5);
    expect(await count('?direction=outbound')).toBe(1);
    expect(await count(`?domainId=${domainId}`)).toBe(1);
    expect(await count('?riskScore.gte=400&riskScore.lt=800')).toBe(2);
    expect(await count('?hasAttachments=true')).toBe(1);
    expect(await count('?verdict=spam&direction=inbound')).toBe(2);
  });

  it('a domainId of another organization or unknown is 404 domain_not_found', async () => {
    world.domains.push({ id: 78n, publicId: randomUUID(), organizationId: OTHER_ORG });
    for (const id of [world.domains[1]!.publicId, randomUUID()]) {
      const res = await list(`?domainId=${id}`);
      expect(res.status).toBe(404);
      expect(res.body).toMatchObject({ code: 'domain_not_found', requestId: expect.any(String) });
    }
  });

  it.each([
    ['?subjectKey=hello', 'Unrecognized key'],
    ['?verdict.gte=spam', 'Unrecognized key'],
    ['?status=received,persisted,scanning,scanned,approved,expired', 'status'],
    ['?verdict=nonsense', 'verdict'],
    ['?riskScore.gte=1001', 'riskScore.gte'],
    ['?domainId=not-a-uuid', 'domainId'],
    ['?limit=0', 'limit'],
    ['?limit=101', 'limit'],
    ['?sort=-subject', 'sort'],
    ['?from=yesterday', 'from'],
    ['?direction=inbound&direction=outbound', 'direction'],
  ])('refuses %s with 400 validation_failed', async (query, text) => {
    const res = await list(query);
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('validation_failed');
    expect(JSON.stringify(res.body.message)).toContain(text);
  });

  it('refuses a range longer than API_MESSAGES_MAX_RANGE_DAYS', async () => {
    const to = new Date();
    const from = new Date(to.getTime() - 32 * 86_400_000);
    const res = await list(`?from=${from.toISOString()}&to=${to.toISOString()}`);
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('validation_failed');
    expect(res.body.message).toEqual(['to: the range may cover at most 31 days']);
  });

  it('refuses a bad, tampered or foreign cursor with 400 cursor_invalid', async () => {
    const first = await list('?limit=1');
    const cursor: string = first.body.nextCursor;
    const tampered = `${cursor.slice(0, -2)}${cursor.endsWith('AA') ? 'BA' : 'AA'}`;
    for (const query of [
      '?cursor=garbage',
      `?cursor=${encodeURIComponent(tampered)}`,
      `?limit=1&verdict=spam&cursor=${encodeURIComponent(cursor)}`,
      `?limit=1&sort=receivedAt&cursor=${encodeURIComponent(cursor)}`,
      `?limit=1&to=${new Date(Date.now() - HOUR).toISOString()}&cursor=${encodeURIComponent(cursor)}`,
    ]) {
      const res = await list(query);
      expect(res.status, query).toBe(400);
      expect(res.body.code).toBe('cursor_invalid');
    }
  });

  it('RBAC: 401 without credentials, 403 without message:read (user and API key), API key accepted', async () => {
    expect((await api.http().get('/api/v1/messages')).status).toBe(401);
    const denied = await list('', await api.principals.user(['delivery:read']).bearer());
    expect(denied.status).toBe(403);
    expect(denied.body.code).toBe('forbidden');
    api.principals.apiKeyWith([]);
    expect((await list('', api.principals.apiKeyHeaders)).status).toBe(403);
    api.principals.apiKeyWith([READ]);
    const ok = await list('?limit=1', api.principals.apiKeyHeaders);
    expect(ok.status).toBe(200);
    expect(ok.body.data).toHaveLength(1);
  });

  it('audits identifying searches on the first page only, never the value in clear', async () => {
    const revealer = await api.principals.user([READ, REVEAL]).bearer();
    const first = await list('?limit=1&recipient=alice@acme.example', revealer);
    expect(first.status).toBe(200);
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]).toMatchObject({
      action: 'message.searched',
      organizationId: api.principals.organizationId,
      actor: { type: 'user', id: api.principals.ids.user },
      metadata: { filters: ['recipient'], plan: 'recipient', resultCount: 1 },
    });
    expect(JSON.stringify(audit.entries[0]!.metadata)).not.toContain('alice@acme.example');
    await list(
      `?limit=1&recipient=alice@acme.example&cursor=${encodeURIComponent(first.body.nextCursor)}`,
      revealer,
    );
    await list('?verdict=spam');
    expect(audit.entries).toHaveLength(1);
  });

  it('is documented with tag, permissions, cursor, parameters, example and errors', () => {
    const doc = buildOpenApiDocument(api.app);
    const op = doc.paths['/api/v1/messages']?.get as unknown as OpenApiOperation;
    expect(op).toBeDefined();
    expect(op.tags).toEqual(['messages']);
    expect(op['x-eg-permissions']).toEqual({ mode: 'all', permissions: [READ] });
    expect(op['x-eg-cursor']).toBe('v1');
    expect(op.description).toContain('API_LIST_SCAN_BUDGET_ROWS');
    const names = (op.parameters as Array<{ name: string }>).map((p) => p.name);
    for (const name of [
      'limit',
      'cursor',
      'sort',
      'from',
      'to',
      'verdict',
      'recipient',
      'riskScore.gte',
      'domainId',
    ]) {
      expect(names).toContain(name);
    }
    expect(op.responses['200']!.content['application/json']!.schema.example?.data).toHaveLength(1);
    for (const status of ['400', '401', '403', '404', '429', '503'])
      expect(op.responses[status]).toBeDefined();
  });
});

describe('GET /api/v1/messages 429 (principal limit)', () => {
  let api: StubbedApiApp;
  beforeAll(async () => {
    const world = new MessagesWorld();
    api = await createStubbedApiApp(
      { API_RATE_PRINCIPAL_PER_MINUTE: '10' },
      { override: (b) => overrideMessagesData(b, world, new RecordingAuditService()) },
    );
  });
  afterAll(async () => {
    await api?.close();
  });

  it('answers 429 rate_limited with RateLimit headers and Retry-After', async () => {
    const bearer = await api.principals.user([READ]).bearer();
    for (let i = 0; i < 10; i += 1) {
      const ok = await api.http().get('/api/v1/messages').set(bearer);
      expect(ok.status).toBe(200);
      expect(ok.headers['ratelimit-limit']).toBe('10');
    }
    const res = await api.http().get('/api/v1/messages').set(bearer);
    expect(res.status).toBe(429);
    expect(res.body).toMatchObject({ code: 'rate_limited', scope: 'principal' });
    expect(res.headers['ratelimit-remaining']).toBe('0');
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
  });
});

describe('GET /api/v1/messages search drivers and filters (step 7.2, e2e)', () => {
  let api: StubbedApiApp;
  let world: MessagesWorld;
  const audit = new RecordingAuditService();
  const ALL = ['message:read', 'message:reveal', 'delivery:read', 'quarantine:read'];
  const ids: Record<string, string> = {};

  beforeAll(async () => {
    world = new MessagesWorld();
    api = await createStubbedApiApp({}, { override: (b) => overrideMessagesData(b, world, audit) });
  });
  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    world.messages = [];
    world.recipients = [];
    world.deliveries = [];
    world.quarantine = [];
    world.prefixFailure = null;
    audit.entries.length = 0;
    api.kv.entries.clear();
    const org = api.principals.organizationId;
    const now = Date.now();
    const add = (name: string, i: number, over: Parameters<MessagesWorld['addMessage']>[1]) => {
      const m = world.addMessage(org, { receivedAt: new Date(now - (i + 1) * HOUR), ...over });
      ids[name] = m.publicId;
      return m;
    };
    add('invoice', 0, {
      subject: 'RE: Fwd:  Invoice 100%  overdue',
      envelopeFrom: 'billing@vendor.example',
      headerFrom: 'Billing <billing@vendor.example>',
      internetMessageId: '<inv-1@vendor.example>',
      recipients: ['ap@partner.example'],
    });
    const bounced = add('bounced', 1, {
      subject: 'Weekly report',
      envelopeFrom: 'reports@corp.example',
      recipients: ['ceo@corp.example', 'cfo@corp.example'],
    });
    world.deliveries.push({
      organizationId: org,
      messageId: bounced.id,
      recipientId: 1n,
      deliverySeq: 0,
      status: 'bounced',
      finalSmtpCode: 550,
      deliveredAt: null,
    } as never);
    const held = add('held', 2, { subject: 'Invoice reminder', envelopeFrom: 'x@evil.example' });
    world.quarantine.push({ organizationId: org, messageId: held.id, status: 'held' });
    // Another organization's identical message: never listed.
    world.addMessage(2n, {
      receivedAt: new Date(now - HOUR),
      subject: 'Invoice 100% overdue',
      envelopeFrom: 'billing@vendor.example',
    });
  });

  const list = async (query: string, permissions: string[] = ALL) =>
    api
      .http()
      .get(`/api/v1/messages${query}`)
      .set(await api.principals.user(permissions).bearer());
  const listed = async (query: string) => {
    const res = await list(query);
    expect(res.status, query).toBe(200);
    return (res.body.data as Array<{ id: string }>).map((d) => d.id);
  };

  it('every new filter finds its messages (exact drivers, no short pages)', async () => {
    expect(await listed('?subject=invoice%20100%25%20overdue')).toEqual([ids.invoice]);
    expect(await listed('?subjectPrefix=Re:%20invoice')).toEqual([ids.invoice, ids.held]);
    expect(await listed('?senderDomain=@Vendor.example')).toEqual([ids.invoice]);
    expect(await listed('?recipientDomain=corp.example')).toEqual([ids.bounced]);
    expect(await listed('?deliveryStatus=bounced')).toEqual([ids.bounced]);
    expect(await listed('?quarantineStatus=held')).toEqual([ids.held]);
    expect(await listed('?internetMessageId=inv-1@vendor.example')).toEqual([ids.invoice]);
    expect(await listed('?internetMessageId=%3Cinv-1@vendor.example%3E')).toEqual([ids.invoice]);
    expect(await listed('?headerFrom=billing%20%3Cbilling@vendor.example%3E')).toEqual([
      ids.invoice,
    ]);
    // A driver with residuals.
    expect(await listed('?subjectPrefix=invoice&senderDomain=evil.example')).toEqual([ids.held]);
    expect(await listed('?recipientDomain=corp.example&deliveryStatus=delivered')).toEqual([]);
  });

  it.each([
    ['?subject=', 'subject'],
    ['?subject=Re:%20', 'subject: must contain text besides reply markers'],
    ['?subjectPrefix=ab', 'subjectPrefix: must be 3 to 128 characters'],
    [`?subjectPrefix=${'x'.repeat(129)}`, 'subjectPrefix'],
    ['?senderDomain=bad_domain', 'senderDomain'],
    ['?recipientDomain=a@b.example', 'recipientDomain'],
    ['?deliveryStatus=bounced,failed', 'deliveryStatus'],
    ['?deliveryStatus=lost', 'deliveryStatus'],
    ['?quarantineStatus=quarantined', 'quarantineStatus'],
    ['?internetMessageId=%3C%3E', 'internetMessageId'],
    ['?senderDomain=a.example&senderDomain=b.example', 'senderDomain'],
  ])('refuses %s with 400 validation_failed', async (query, text) => {
    const res = await list(query);
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('validation_failed');
    expect(JSON.stringify(res.body.message)).toContain(text);
  });

  it('applies the filter-level permissions of every system role (403 message_filter_forbidden)', async () => {
    const gated: Array<[string, string]> = [
      ['?recipient=alice%40corp.example', 'message:reveal'],
      ['?subject=Weekly%20report', 'message:reveal'],
      ['?subjectPrefix=Wee', 'message:reveal'],
      ['?deliveryStatus=bounced', 'delivery:read'],
      ['?quarantineStatus=held', 'quarantine:read'],
    ];
    for (const role of SYSTEM_ROLES) {
      const permissions = [...role.permissions] as string[];
      for (const [query, permission] of gated) {
        const res = await list(query, permissions);
        if (!permissions.includes('message:read')) {
          expect(res.status, `${role.key} ${query}`).toBe(403);
          expect(res.body.code).toBe('forbidden');
        } else if (permissions.includes(permission)) {
          expect(res.status, `${role.key} ${query}`).toBe(200);
        } else {
          expect(res.status, `${role.key} ${query}`).toBe(403);
          expect(res.body).toMatchObject({
            code: 'message_filter_forbidden',
            permission,
            requestId: expect.any(String),
          });
        }
      }
    }
    // The ungated new filters work with message:read alone.
    expect((await list('?senderDomain=vendor.example', ['message:read'])).status).toBe(200);
    expect(audit.entries.every((e) => e.action === 'message.searched')).toBe(true);
  });

  it('API keys: a subject search needs message:reveal in the key scope', async () => {
    api.principals.apiKeyWith(['message:read']);
    const denied = await api
      .http()
      .get('/api/v1/messages?subject=Weekly%20report')
      .set(api.principals.apiKeyHeaders);
    expect(denied.status).toBe(403);
    expect(denied.body).toMatchObject({ code: 'message_filter_forbidden', filter: 'subject' });
    api.principals.apiKeyWith(['message:read', 'message:reveal']);
    const ok = await api
      .http()
      .get('/api/v1/messages?subject=Weekly%20report')
      .set(api.principals.apiKeyHeaders);
    expect(ok.status).toBe(200);
    expect(ok.body.data.map((d: { id: string }) => d.id)).toEqual([ids.bounced]);
  });

  it('maps a too broad prefix to 422 and a timeout to 503 (coded, with requestId)', async () => {
    world.prefixFailure = { kind: 'too_broad', matches: 5001 };
    const broad = await list('?subjectPrefix=Inv');
    expect(broad.status).toBe(422);
    expect(broad.body).toMatchObject({
      code: 'message_search_too_broad',
      maxMatches: 5000,
      requestId: expect.any(String),
    });
    world.prefixFailure = { kind: 'timeout' };
    const slow = await list('?subjectPrefix=Inv');
    expect(slow.status).toBe(503);
    expect(slow.body).toMatchObject({
      code: 'message_search_timeout',
      requestId: expect.any(String),
    });
  });

  it('audits subject searches with the SHA-256 of the normalized value', async () => {
    await list('?subject=RE:%20%20Weekly%20%20report');
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.metadata).toMatchObject({
      filters: ['subject'],
      plan: 'subject',
      budgeted: false,
      valueSha256: {
        subject: createHash('sha256').update('Weekly report').digest('hex'),
      },
    });
    expect(JSON.stringify(audit.entries[0]!.metadata)).not.toContain('Weekly');
    await list('?senderDomain=corp.example&deliveryStatus=bounced');
    expect(audit.entries).toHaveLength(1);
  });

  it('cursors are bound to the filters (and driver): another filter set, a tampered or another installation’s cursor is 400 cursor_invalid', async () => {
    const first = await list('?senderDomain=corp.example&limit=1');
    expect(first.status).toBe(200);
    world.addMessage(api.principals.organizationId, {
      receivedAt: new Date(Date.now() - 5 * HOUR),
      envelopeFrom: 'other@corp.example',
    });
    const page = await list('?senderDomain=corp.example&limit=1');
    const cursor: string = page.body.nextCursor;
    expect(cursor).toEqual(expect.any(String));
    const next = await list(
      `?senderDomain=corp.example&limit=1&cursor=${encodeURIComponent(cursor)}`,
    );
    expect(next.status).toBe(200);
    for (const query of [
      // Same filter value, another driver: senderDomain alone vs with a sender (sender drives).
      `?senderDomain=corp.example&sender=reports@corp.example&limit=1&cursor=${encodeURIComponent(cursor)}`,
      `?recipientDomain=corp.example&limit=1&cursor=${encodeURIComponent(cursor)}`,
      `?senderDomain=corp.example&limit=1&cursor=${encodeURIComponent(`${cursor.slice(0, -3)}xyz`)}`,
    ]) {
      const res = await list(query);
      expect(res.status, query).toBe(400);
      expect(res.body.code).toBe('cursor_invalid');
    }
    // A cursor signed by another installation (another key and organization).
    const other = await createStubbedApiApp(
      {},
      { override: (b) => overrideMessagesData(b, world, audit) },
    );
    try {
      const foreign = await other
        .http()
        .get(
          `/api/v1/messages?senderDomain=corp.example&limit=1&cursor=${encodeURIComponent(cursor)}`,
        )
        .set(await other.principals.user(ALL).bearer());
      expect(foreign.status).toBe(400);
      expect(foreign.body.code).toBe('cursor_invalid');
    } finally {
      await other.close();
    }
  });

  it('documents the new parameters, the filter permissions and the refusals', () => {
    const doc = buildOpenApiDocument(api.app);
    const op = doc.paths['/api/v1/messages']?.get as unknown as OpenApiOperation;
    const names = op.parameters.map((p) => p.name);
    for (const name of [
      'subject',
      'subjectPrefix',
      'senderDomain',
      'recipientDomain',
      'deliveryStatus',
      'quarantineStatus',
      'internetMessageId',
    ]) {
      expect(names).toContain(name);
    }
    expect(op.description).toContain('message:reveal');
    expect(op.description).toContain('API_MESSAGES_SEARCH_MAX_MATCHES');
    expect(JSON.stringify(op.responses['403'])).toContain('message_filter_forbidden');
    expect(JSON.stringify(op.responses['422'])).toContain('message_search_too_broad');
    expect(JSON.stringify(op.responses['503'])).toContain('message_search_timeout');
  });
});
