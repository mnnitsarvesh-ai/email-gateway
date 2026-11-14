/**
 * Sensitive message metadata (step 7.2 WP2, docs/plan/steps/21-email-explorer-details.md §2
 * E5–E9, §3.3, ADR-0062) over HTTP with MySQL, Redis and S3 stubbed and the repositories replaced
 * by in-memory doubles (test/support/messages-fixtures.ts): the masked fields of the message,
 * recipients and delivery routes for every system role and API keys, the stored headers with the
 * safe subset, the two audited reveal operations (RBAC, strict bodies, 404 and omitted foreign
 * ids, recipients cursor, audit-first ordering with a failing audit, `Cache-Control: no-store`)
 * and the reveal limit (429 with `RateLimit-*` and `Retry-After`, 503 when the store is down).
 * Real SQL, the writer audit rows and tenant isolation run in integration/messages-sensitive.test.ts.
 */
// @covers get /api/v1/messages/:messageId/headers
// @covers post /api/v1/messages/reveal
// @covers post /api/v1/messages/:messageId/reveal
import { randomUUID } from 'node:crypto';
import { SYSTEM_ROLES } from '@email-gateway/database';
import type { TestingModuleBuilder } from '@nestjs/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { AuditEntry } from '../src/audit/audit.service';
import type { TenantScope } from '../src/auth-contracts/tenant-scope';
import { TransactionRunner } from '../src/database/transaction-runner';
import { CursorCodec } from '../src/http/cursor/cursor-codec';
import { filterHash } from '../src/http/listing';
import {
  DeliveriesRepository,
  type DeliveryRow,
} from '../src/modules/deliveries/repositories/deliveries.repository';
import { MESSAGE_RECIPIENTS_REVEAL_RESOURCE } from '../src/modules/messages/dto/message-sensitive.schemas';
import type { MessageRef } from '../src/modules/messages/repositories/message-data.repository';
import {
  type HeaderRow,
  MessageHeadersRepository,
} from '../src/modules/messages/repositories/message-headers.repository';
import { MessageRevealRepository } from '../src/modules/messages/repositories/message-reveal.repository';
import { createStubbedApiApp, immediateRunner, type StubbedApiApp } from './support/api-test-app';
import {
  MessagesWorld,
  overrideMessagesData,
  RecordingAuditService,
  type WorldMessage,
} from './support/messages-fixtures';

const OTHER_ORG = 2n;
const READ = 'message:read';
const REVEAL = 'message:reveal';
const ADDRESSES = ['alice.w@acme.example', 'bob@acme.example', 'carol@acme.example'];

/** RecordingAuditService that can fail like an unavailable writer. */
class FlakyAuditService extends RecordingAuditService {
  fail = false;
  override record(entry: AuditEntry): Promise<void> {
    if (this.fail) return Promise.reject(new Error('writer unavailable'));
    return super.record(entry);
  }
}

interface SensitiveWorld {
  world: MessagesWorld;
  headers: Map<bigint, { parse: string | null; rows: HeaderRow[] }>;
  deliveries: Array<DeliveryRow & { organizationId: bigint }>;
}

/** The repository doubles of the WP2 routes over the messages world. */
function overrideSensitive(builder: TestingModuleBuilder, s: SensitiveWorld): TestingModuleBuilder {
  const { world } = s;
  const refOf = (m: WorldMessage): MessageRef => ({
    id: m.id,
    publicId: m.publicId,
    receivedAt: m.receivedAt,
    organizationId: m.organizationId,
  });
  const own = (scope: TenantScope) =>
    world.messages.filter((m) => m.organizationId === scope.organizationId);
  const messageOf = (scope: TenantScope, id: bigint) => own(scope).find((m) => m.id === id);
  return builder
    .overrideProvider(MessageRevealRepository)
    .useValue({
      refs: (scope: TenantScope, ids: readonly string[]) =>
        Promise.resolve(
          own(scope)
            .filter((m) => ids.includes(m.publicId))
            .map(refOf),
        ),
      subjects: (scope: TenantScope, refs: readonly MessageRef[]) =>
        Promise.resolve(
          refs.flatMap((ref) => {
            const m = messageOf(scope, ref.id);
            return m ? [{ ref, subject: m.subject }] : [];
          }),
        ),
    })
    .overrideProvider(MessageHeadersRepository)
    .useValue({
      parseStatus: (scope: TenantScope, ref: MessageRef) =>
        Promise.resolve(messageOf(scope, ref.id) ? (s.headers.get(ref.id)?.parse ?? null) : null),
      headers: (scope: TenantScope, ref: MessageRef, names?: readonly string[]) =>
        Promise.resolve(
          (messageOf(scope, ref.id) ? (s.headers.get(ref.id)?.rows ?? []) : []).filter(
            (r) =>
              names === undefined || names.some((n) => n.toLowerCase() === r.name.toLowerCase()),
          ),
        ),
    })
    .overrideProvider(DeliveriesRepository)
    .useValue({
      findMessage: (scope: TenantScope, publicId: string) => {
        const m = own(scope).find((x) => x.publicId === publicId);
        return Promise.resolve(
          m
            ? {
                id: m.id,
                publicId: m.publicId,
                receivedAt: m.receivedAt,
                direction: m.direction,
                status: m.status,
                statusReason: m.statusReason,
              }
            : null,
        );
      },
      deliveriesOf: (scope: TenantScope, message: { id: bigint }) =>
        Promise.resolve(
          s.deliveries.filter(
            (d) => d.organizationId === scope.organizationId && d.messageId === message.id,
          ),
        ),
      recipientsOf: (scope: TenantScope, message: { id: bigint }) =>
        Promise.resolve(
          world.recipients.filter(
            (r) => r.organizationId === scope.organizationId && r.messageId === message.id,
          ),
        ),
      eventsOf: (scope: TenantScope, message: { id: bigint }) =>
        Promise.resolve(
          s.deliveries
            .filter((d) => d.organizationId === scope.organizationId && d.messageId === message.id)
            .map((d, i) => ({
              id: BigInt(i + 1),
              deliveryId: d.id,
              source: 'postfix_log',
              fromStatus: 'queued',
              toStatus: d.status,
              applied: true,
              occurredAt: d.receivedAt,
              queueId: 'QID1',
              smtpCode: d.finalSmtpCode,
              enhancedStatus: d.enhancedStatus,
              remoteHost: d.remoteHost,
              errorClass: null,
              detail: `relay=mx.acme.example said: ${d.finalSmtpResponse ?? ''}`,
            })),
        ),
      list: (scope: TenantScope) =>
        Promise.resolve(s.deliveries.filter((d) => d.organizationId === scope.organizationId)),
      recipientsByIds: (scope: TenantScope, ids: readonly bigint[]) =>
        Promise.resolve(
          world.recipients.filter(
            (r) => r.organizationId === scope.organizationId && ids.includes(r.id),
          ),
        ),
      messagePublicIds: (scope: TenantScope, ids: readonly bigint[]) =>
        Promise.resolve(
          new Map(
            own(scope)
              .filter((m) => ids.includes(m.id))
              .map((m) => [m.id, m.publicId]),
          ),
        ),
    })
    .overrideProvider(TransactionRunner)
    .useValue(immediateRunner);
}

/** One message with three recipients, a delivery with an SMTP reply, headers and a user. */
function seed(s: SensitiveWorld, org: bigint, subject = 'Quarterly invoice'): WorldMessage {
  const message = s.world.addMessage(org, { subject, recipients: [...ADDRESSES] });
  const [first] = s.world.recipients.filter((r) => r.messageId === message.id);
  const userId = s.world.id();
  s.world.users.push({ id: userId, publicId: randomUUID(), organizationId: org });
  first!.userId = userId;
  s.deliveries.push({
    id: s.world.id(),
    organizationId: org,
    receivedAt: message.receivedAt,
    messageId: message.id,
    recipientId: first!.id,
    deliverySeq: 0,
    direction: 'inbound',
    status: 'bounced',
    attemptCount: 1,
    lastAttemptAt: message.receivedAt,
    deliveredAt: null,
    remoteHost: 'mx.acme.example',
    finalSmtpCode: 550,
    enhancedStatus: '5.1.1',
    finalSmtpResponse: '550 5.1.1 <alice.w@acme.example>: Recipient address rejected',
    lastErrorClass: 'permanent',
    failureReason: null,
    dsnQueueId: null,
    statusChangedAt: message.receivedAt,
  });
  s.headers.set(message.id, {
    parse: 'parsed',
    rows: [
      { seq: 0, name: 'From', value: 'Vendor <billing@vendor.example>' },
      { seq: 1, name: 'To', value: 'Alice <alice.w@acme.example>' },
      { seq: 2, name: 'Cc', value: 'bob@acme.example' },
      { seq: 3, name: 'Subject', value: subject },
      { seq: 4, name: 'Message-ID', value: '<m1@vendor.example>' },
    ],
  });
  return message;
}

async function sensitiveApp(
  env: Record<string, string>,
  s: SensitiveWorld,
  audit: RecordingAuditService,
): Promise<StubbedApiApp> {
  return createStubbedApiApp(env, {
    override: (b) => overrideSensitive(overrideMessagesData(b, s.world, audit), s),
  });
}

describe('sensitive message metadata (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const s: SensitiveWorld = { world: new MessagesWorld(), headers: new Map(), deliveries: [] };
  const audit = new FlakyAuditService();
  let own: WorldMessage;
  let second: WorldMessage;
  let foreign: WorldMessage;

  beforeAll(async () => {
    api = await sensitiveApp({ API_MESSAGES_REVEAL_PER_MINUTE: '600' }, s, audit);
    own = seed(s, api.principals.organizationId);
    second = seed(s, api.principals.organizationId, 'Second subject');
    s.world.messages.find((m) => m.id === second.id)!.subject = null;
    foreign = seed(s, OTHER_ORG, 'Foreign subject');
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    audit.entries.length = 0;
    audit.fail = false;
    api.kv.entries.clear();
  });

  const as = async (permissions: string[]) => api.principals.user(permissions).bearer();
  const get = async (path: string, permissions: string[] = [READ, 'delivery:read']) =>
    api
      .http()
      .get(`/api/v1${path}`)
      .set(await as(permissions));
  const post = async (path: string, body: unknown, permissions: string[] = [REVEAL]) =>
    api
      .http()
      .post(`/api/v1${path}`)
      .set(await as(permissions))
      .send(body as object);

  /** No clear recipient address, matched user or subject anywhere in a read body. */
  const expectNoClearValues = (body: unknown, label: string) => {
    const text = JSON.stringify(body);
    for (const address of ADDRESSES) expect(text, label).not.toContain(address);
    for (const value of ['Quarterly invoice', 'Second subject', 'Foreign subject']) {
      expect(text, label).not.toContain(value);
    }
    for (const user of s.world.users) expect(text, label).not.toContain(user.publicId);
  };

  describe('masked reads for every system role (§2 E5, E7, E9)', () => {
    const MESSAGE_ROUTES = (id: string) => [
      '/messages',
      `/messages/${id}`,
      `/messages/${id}/recipients`,
      `/messages/${id}/headers`,
    ];
    const DELIVERY_ROUTES = (id: string) => [
      `/messages/${id}/deliveries`,
      `/messages/${id}/deliveries/events`,
      '/deliveries',
    ];

    it.each(SYSTEM_ROLES.map((r) => [r.key, [...r.permissions] as string[]] as const))(
      '%s: masked values or 403, never a clear value',
      async (_role, permissions) => {
        for (const path of MESSAGE_ROUTES(own.publicId)) {
          const res = await get(path, permissions);
          if (!permissions.includes(READ)) {
            expect(res.status, path).toBe(403);
            continue;
          }
          expect(res.status, path).toBe(200);
          expectNoClearValues(res.body, path);
        }
        for (const path of DELIVERY_ROUTES(own.publicId)) {
          const res = await get(path, permissions);
          if (!permissions.includes('delivery:read')) {
            expect(res.status, path).toBe(403);
            continue;
          }
          expect(res.status, path).toBe(200);
          expectNoClearValues(res.body, path);
        }
      },
    );

    it('list and detail: subject null, subjectMasked when one exists', async () => {
      const list = await get('/messages');
      const byId = new Map(
        (list.body.data as Array<{ id: string; subject: unknown; subjectMasked: boolean }>).map(
          (d) => [d.id, d],
        ),
      );
      expect(byId.get(own.publicId)).toMatchObject({ subject: null, subjectMasked: true });
      expect(byId.get(second.publicId)).toMatchObject({ subject: null, subjectMasked: false });
      const detail = await get(`/messages/${own.publicId}`);
      expect(detail.body).toMatchObject({ subject: null, subjectMasked: true });
    });

    it('recipients: masked address, addressMasked, userId null', async () => {
      const res = await get(`/messages/${own.publicId}/recipients`);
      expect(res.body.data).toEqual([
        expect.objectContaining({
          rcptSeq: 0,
          address: 'a***@acme.example',
          addressMasked: true,
          userId: null,
        }),
        expect.objectContaining({
          rcptSeq: 1,
          address: 'b***@acme.example',
          addressMasked: true,
          userId: null,
        }),
        expect.objectContaining({
          rcptSeq: 2,
          address: 'c***@acme.example',
          addressMasked: true,
          userId: null,
        }),
      ]);
    });

    it('deliveries, delivery list and events: masked recipient and address-masked SMTP texts', async () => {
      const forMessage = await get(`/messages/${own.publicId}/deliveries`);
      expect(forMessage.body.deliveries[0]).toMatchObject({
        rcptSeq: 0,
        recipient: 'a***@acme.example',
        recipientMasked: true,
        finalSmtpResponse: '550 5.1.1 <a***@acme.example>: Recipient address rejected',
      });
      const list = await get('/deliveries');
      expect(list.body.data[0]).toMatchObject({
        recipient: 'a***@acme.example',
        recipientMasked: true,
      });
      const events = await get(`/messages/${own.publicId}/deliveries/events`);
      expect(events.body.data[0].detail).toBe(
        'relay=mx.acme.example said: 550 5.1.1 <a***@acme.example>: Recipient address rejected',
      );
    });

    it('headers: the safe subset in clear, To/Cc/Subject withheld, the names and the availability', async () => {
      const res = await get(`/messages/${own.publicId}/headers`, [READ]);
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({
        messageId: own.publicId,
        availability: 'available',
        safeHeaderNames: expect.arrayContaining(['From', 'Message-ID', 'Authentication-Results']),
        storedHeaderNames: expect.arrayContaining(['To', 'Cc', 'Subject', 'From']),
      });
      expect(res.body.headers).toEqual([
        { seq: 0, name: 'From', value: 'Vendor <billing@vendor.example>', masked: false },
        { seq: 1, name: 'To', value: null, masked: true },
        { seq: 2, name: 'Cc', value: null, masked: true },
        { seq: 3, name: 'Subject', value: null, masked: true },
        { seq: 4, name: 'Message-ID', value: '<m1@vendor.example>', masked: false },
      ]);
      // Reads are not audited.
      expect(audit.entries).toEqual([]);
    });

    it('headers: 404 message_not_found for foreign and unknown ids, 400 for a bad id', async () => {
      for (const id of [foreign.publicId, randomUUID()]) {
        const res = await get(`/messages/${id}/headers`, [READ]);
        expect(res.status).toBe(404);
        expect(res.body).toMatchObject({
          code: 'message_not_found',
          requestId: expect.any(String),
        });
      }
      expect((await get('/messages/not-a-uuid/headers', [READ])).status).toBe(400);
    });

    it('API keys see the same masks; headers need message:read', async () => {
      api.principals.apiKeyWith([READ]);
      const res = await api
        .http()
        .get(`/api/v1/messages/${own.publicId}/recipients`)
        .set(api.principals.apiKeyHeaders);
      expect(res.status).toBe(200);
      expectNoClearValues(res.body, 'api key recipients');
      api.principals.apiKeyWith([REVEAL]);
      const denied = await api
        .http()
        .get(`/api/v1/messages/${own.publicId}/headers`)
        .set(api.principals.apiKeyHeaders);
      expect(denied.status).toBe(403);
    });
  });

  describe('reveal RBAC (§2 E5, E6)', () => {
    const REVEALERS = new Set([
      'super_admin',
      'organization_admin',
      'security_analyst',
      'compliance_auditor',
    ]);

    it.each(SYSTEM_ROLES.map((r) => [r.key, [...r.permissions] as string[]] as const))(
      '%s',
      async (role, permissions) => {
        const many = await post('/messages/reveal', { messageIds: [own.publicId] }, permissions);
        const one = await post(
          `/messages/${own.publicId}/reveal`,
          { fields: ['subject'] },
          permissions,
        );
        if (REVEALERS.has(role)) {
          expect(permissions).toContain(REVEAL);
          expect([many.status, one.status], role).toEqual([200, 200]);
          expect(many.body.data).toEqual([{ id: own.publicId, subject: 'Quarterly invoice' }]);
          expect(one.body.subject).toBe('Quarterly invoice');
        } else {
          expect(permissions).not.toContain(REVEAL);
          expect([many.status, one.status], role).toEqual([403, 403]);
          expect(many.body.code).toBe('forbidden');
          expectNoClearValues([many.body, one.body], role);
        }
      },
    );

    it('API keys: only with message:reveal in the key scope', async () => {
      const call = () =>
        api
          .http()
          .post(`/api/v1/messages/${own.publicId}/reveal`)
          .set(api.principals.apiKeyHeaders)
          .send({ fields: ['recipients'] });
      api.principals.apiKeyWith([READ, 'delivery:read', 'quarantine:release']);
      expect((await call()).status).toBe(403);
      api.principals.apiKeyWith([REVEAL]);
      const ok = await call();
      expect(ok.status).toBe(200);
      expect(ok.body.recipients.data.map((r: { address: string }) => r.address)).toEqual(ADDRESSES);
      expect(audit.entries).toEqual([
        expect.objectContaining({
          actor: { type: 'api_key', id: api.principals.apiKey.apiKeyPublicId },
          action: 'message.revealed',
          resourceId: own.publicId,
        }),
      ]);
    });

    it('answers 401 without credentials', async () => {
      await api
        .http()
        .post('/api/v1/messages/reveal')
        .send({ messageIds: [own.publicId] })
        .expect(401);
      await api
        .http()
        .post(`/api/v1/messages/${own.publicId}/reveal`)
        .send({ fields: ['subject'] })
        .expect(401);
    });
  });

  describe('POST /messages/reveal (§2 E6)', () => {
    it('subjects in request order; foreign and unknown ids omitted; one audit row per message', async () => {
      const unknown = randomUUID();
      const res = await post('/messages/reveal', {
        messageIds: [second.publicId, foreign.publicId, unknown, own.publicId.toUpperCase()],
      });
      expect(res.status).toBe(200);
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.body).toEqual({
        revealedAt: expect.any(String),
        data: [
          { id: second.publicId, subject: null },
          { id: own.publicId, subject: 'Quarterly invoice' },
        ],
      });
      expect(JSON.stringify(res.body)).not.toContain('Foreign subject');
      expect(
        audit.entries.map((e) => [e.action, e.resourceType, e.resourceId, e.metadata]),
      ).toEqual([
        ['message.revealed', 'message', second.publicId, { fields: ['subject'], bulk: true }],
        ['message.revealed', 'message', own.publicId, { fields: ['subject'], bulk: true }],
      ]);
      expect(audit.entries[0]!.actor).toEqual({ type: 'user', id: api.principals.ids.user });
    });

    it.each([
      [{}],
      [{ messageIds: [] }],
      [{ messageIds: ['x'] }],
      [{ messageIds: 'nope' }],
      [{ messageIds: [randomUUID()], extra: 1 }],
      [{ messageIds: Array.from({ length: 101 }, () => randomUUID()) }],
    ])('400 validation_failed for %j (nothing read or audited)', async (body) => {
      const res = await post('/messages/reveal', body);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('validation_failed');
      expect(audit.entries).toEqual([]);
    });

    it('400 for duplicate ids, case-insensitively', async () => {
      const res = await post('/messages/reveal', {
        messageIds: [own.publicId, own.publicId.toUpperCase()],
      });
      expect(res.status).toBe(400);
      expect(JSON.stringify(res.body.message)).toContain('twice');
    });

    it('audit-first: a failing audit write is 503 and returns no value', async () => {
      audit.fail = true;
      const res = await post('/messages/reveal', { messageIds: [own.publicId] });
      expect(res.status).toBe(503);
      expect(res.body).toMatchObject({
        code: 'service_unavailable',
        requestId: expect.any(String),
      });
      expect(JSON.stringify(res.body)).not.toContain('Quarterly invoice');
      expect(res.body).not.toHaveProperty('data');
    });
  });

  describe('POST /messages/{messageId}/reveal (§2 E6)', () => {
    it('subject, the To/Cc/Subject rows and the recipients with user ids; one audit row', async () => {
      const res = await post(`/messages/${own.publicId}/reveal`, {
        fields: ['subject', 'headers', 'recipients'],
      });
      expect(res.status).toBe(200);
      expect(res.headers['cache-control']).toBe('no-store');
      const firstRecipient = s.world.recipients.find(
        (r) => r.messageId === own.id && r.rcptSeq === 0,
      )!;
      const user = s.world.users.find((u) => u.id === firstRecipient.userId)!;
      expect(res.body).toEqual({
        messageId: own.publicId,
        revealedAt: expect.any(String),
        subject: 'Quarterly invoice',
        headers: [
          { seq: 1, name: 'To', value: 'Alice <alice.w@acme.example>' },
          { seq: 2, name: 'Cc', value: 'bob@acme.example' },
          { seq: 3, name: 'Subject', value: 'Quarterly invoice' },
        ],
        recipients: {
          data: [
            { rcptSeq: 0, address: ADDRESSES[0], userId: user.publicId },
            { rcptSeq: 1, address: ADDRESSES[1], userId: null },
            { rcptSeq: 2, address: ADDRESSES[2], userId: null },
          ],
          nextCursor: null,
        },
      });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]).toMatchObject({
        organizationId: api.principals.organizationId,
        action: 'message.revealed',
        resourceType: 'message',
        resourceId: own.publicId,
        metadata: {
          fields: ['subject', 'headers', 'recipients'],
          headerCount: 3,
          recipients: { count: 3, firstRcptSeq: 0, lastRcptSeq: 2 },
        },
      });
      expect(JSON.stringify(audit.entries[0]!.metadata)).not.toMatch(/alice|bob|Quarterly/);
    });

    it('pages recipients with recipientsCursor; tampered, other-message and other-tenant cursors are 400', async () => {
      const first = await post(`/messages/${own.publicId}/reveal`, {
        fields: ['recipients'],
        recipientsLimit: 2,
      });
      expect(first.body.recipients.data.map((r: { rcptSeq: number }) => r.rcptSeq)).toEqual([0, 1]);
      const cursor = first.body.recipients.nextCursor as string;
      expect(cursor).toEqual(expect.any(String));
      const next = await post(`/messages/${own.publicId}/reveal`, {
        fields: ['recipients'],
        recipientsCursor: cursor,
        recipientsLimit: 2,
      });
      expect(next.body.recipients).toEqual({
        data: [{ rcptSeq: 2, address: ADDRESSES[2], userId: null }],
        nextCursor: null,
      });
      expect(audit.entries.map((e) => e.metadata)).toEqual([
        { fields: ['recipients'], recipients: { count: 2, firstRcptSeq: 0, lastRcptSeq: 1 } },
        { fields: ['recipients'], recipients: { count: 1, firstRcptSeq: 2, lastRcptSeq: 2 } },
      ]);
      // A cursor of the same resource and message signed for another organization.
      const codec = api.app.get(CursorCodec);
      const otherTenant = codec.encode({
        resource: MESSAGE_RECIPIENTS_REVEAL_RESOURCE,
        organizationPublicId: randomUUID(),
        filterHash: filterHash({
          resource: MESSAGE_RECIPIENTS_REVEAL_RESOURCE,
          filters: { messageId: { values: [own.publicId] } },
          sort: 'rcptSeq',
        }),
        direction: 'asc',
        keys: ['1'],
      });
      audit.entries.length = 0;
      for (const [messageId, c] of [
        [second.publicId, cursor],
        [own.publicId, `${cursor.startsWith('e') ? 'f' : 'e'}${cursor.slice(1)}`],
        [own.publicId, otherTenant],
        [own.publicId, 'not-a-cursor'],
      ] as const) {
        const res = await post(`/messages/${messageId}/reveal`, {
          fields: ['recipients'],
          recipientsCursor: c,
        });
        expect(res.status, c).toBe(400);
        expect(res.body.code).toBe('cursor_invalid');
      }
      expect(audit.entries).toEqual([]);
    });

    it('404 message_not_found for foreign and unknown ids (nothing audited)', async () => {
      for (const id of [foreign.publicId, randomUUID()]) {
        const res = await post(`/messages/${id}/reveal`, { fields: ['subject', 'recipients'] });
        expect(res.status).toBe(404);
        expect(res.body.code).toBe('message_not_found');
        expect(JSON.stringify(res.body)).not.toContain('Foreign subject');
      }
      expect(audit.entries).toEqual([]);
    });

    it.each([
      [{}],
      [{ fields: [] }],
      [{ fields: ['body'] }],
      [{ fields: ['subject', 'subject'] }],
      [{ fields: ['subject'], recipientsCursor: 'x' }],
      [{ fields: ['headers'], recipientsLimit: 10 }],
      [{ fields: ['recipients'], recipientsLimit: 0 }],
      [{ fields: ['recipients'], recipientsLimit: 101 }],
      [{ fields: ['recipients'], recipientsLimit: '10' }],
      [{ fields: ['subject'], messageIds: [] }],
    ])('400 validation_failed for %j', async (body) => {
      const res = await post(`/messages/${own.publicId}/reveal`, body);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('validation_failed');
      expect(audit.entries).toEqual([]);
    });

    it('400 for a messageId that is not a UUID', async () => {
      expect((await post('/messages/not-a-uuid/reveal', { fields: ['subject'] })).status).toBe(400);
    });

    it('audit-first: a failing audit write is 503 and returns no value', async () => {
      audit.fail = true;
      const res = await post(`/messages/${own.publicId}/reveal`, {
        fields: ['subject', 'headers', 'recipients'],
      });
      expect(res.status).toBe(503);
      expect(res.body.code).toBe('service_unavailable');
      const text = JSON.stringify(res.body);
      for (const value of [...ADDRESSES, 'Quarterly invoice']) expect(text).not.toContain(value);
    });
  });
});

describe('reveal limit (e2e, API_MESSAGES_REVEAL_PER_MINUTE=3)', () => {
  let api: StubbedApiApp;
  const s: SensitiveWorld = { world: new MessagesWorld(), headers: new Map(), deliveries: [] };
  const audit = new RecordingAuditService();
  let own: WorldMessage;

  beforeAll(async () => {
    api = await sensitiveApp({ API_MESSAGES_REVEAL_PER_MINUTE: '3' }, s, audit);
    own = seed(s, api.principals.organizationId);
  });

  afterAll(async () => {
    await api?.close();
  });

  it('both operations share one per-principal bucket: 429 rate_limited with RateLimit-* and Retry-After', async () => {
    const headers = await api.principals.user([REVEAL]).bearer();
    const many = () =>
      api
        .http()
        .post('/api/v1/messages/reveal')
        .set(headers)
        .send({ messageIds: [own.publicId] });
    const one = () =>
      api
        .http()
        .post(`/api/v1/messages/${own.publicId}/reveal`)
        .set(headers)
        .send({ fields: ['subject'] });
    const first = await many();
    expect(first.status).toBe(200);
    expect(first.headers['ratelimit-limit']).toBe('3');
    expect(first.headers['ratelimit-remaining']).toBe('2');
    expect((await one()).status).toBe(200);
    expect((await many()).status).toBe(200);
    const limited = await one();
    expect(limited.status).toBe(429);
    expect(limited.body).toMatchObject({
      code: 'rate_limited',
      scope: 'route',
      requestId: expect.any(String),
    });
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
    expect(limited.headers['ratelimit-limit']).toBe('3');
    expect(limited.headers['ratelimit-remaining']).toBe('0');
    expect(limited.headers['ratelimit-reset']).toEqual(expect.any(String));
    expect(limited.body).not.toHaveProperty('subject');
    // The refused request wrote no audit row.
    expect(audit.entries).toHaveLength(3);
    // Another principal (an API key) has its own bucket.
    api.principals.apiKeyWith([REVEAL]);
    await api
      .http()
      .post('/api/v1/messages/reveal')
      .set(api.principals.apiKeyHeaders)
      .send({ messageIds: [own.publicId] })
      .expect(200);
    // A request refused by RBAC never counts.
    api.kv.entries.clear();
    const reader = await api.principals.user([READ]).bearer();
    for (let i = 0; i < 5; i += 1) {
      await api
        .http()
        .post('/api/v1/messages/reveal')
        .set(reader)
        .send({ messageIds: [own.publicId] })
        .expect(403);
    }
    expect([...api.kv.entries.keys()].some((k) => k.startsWith('rl:message-reveal:'))).toBe(false);
  });

  it('fails closed with 503 when the limiter store is down', async () => {
    api.kv.failing = true;
    try {
      const res = await api
        .http()
        .post('/api/v1/messages/reveal')
        .set(await api.principals.user([REVEAL]).bearer())
        .send({ messageIds: [own.publicId] });
      expect(res.status).toBe(503);
      expect(JSON.stringify(res.body)).not.toContain('Quarterly invoice');
    } finally {
      api.kv.failing = false;
    }
  });
});
