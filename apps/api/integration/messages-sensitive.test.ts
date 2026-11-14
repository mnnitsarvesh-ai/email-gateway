/**
 * Sensitive message metadata (step 7.2 WP2, docs/plan/steps/21-email-explorer-details.md §2
 * E5–E9, ADR-0062) against the real MySQL writer and replica and Redis: masked values on every
 * changed route for each tenant system role and API keys (subjects, recipients, matched users,
 * header values, SMTP texts, Rspamd symbol options), the stored headers and their availability
 * states (`available`, `not_parsed`, `none_stored`, `retention_expired`), the audited reveals
 * (exactly the stored values; the `message.revealed` rows are on the writer when the response
 * arrives, one per message for the bulk reveal; an override session's row carries the override),
 * the quarantine recipient rule per role, the reveal limit on the real Redis, and tenant
 * isolation (bulk omits foreign ids, single reveal and headers `404`, foreign recipients cursors
 * `400 cursor_invalid`). Platform roles reach tenant data only through override sessions; their
 * permission sets are covered by the e2e suite (test/messages-sensitive.e2e.test.ts).
 */
// @covers get /api/v1/messages/:messageId/headers
// @covers post /api/v1/messages/reveal
// @covers post /api/v1/messages/:messageId/reveal
import { randomUUID } from 'node:crypto';
import { Prisma } from '@email-gateway/database';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa, uniqueIp } from './support/http';
import {
  deleteMessagesData,
  getAs,
  POLL,
  type SeededMessage,
  seedMessage,
} from './support/messages-data';

const MIN = 60_000;
const DAY = 86_400_000;
const run = randomUUID().slice(0, 8);
const ADDRESSES = [
  `alice.${run}@acme.example`,
  `bob.${run}@acme.example`,
  `carol.${run}@acme.example`,
];
const SUBJECT = `Quarterly invoice ${run}`;
const TENANT_ROLES = [
  'organization_admin',
  'domain_admin',
  'security_analyst',
  'quarantine_reviewer',
  'compliance_auditor',
  'read_only_user',
  'mailbox_user',
] as const;
type TenantRole = (typeof TENANT_ROLES)[number];
const REVEALERS = new Set<TenantRole>([
  'organization_admin',
  'security_analyst',
  'compliance_auditor',
]);

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let message: SeededMessage;
let foreign: SeededMessage;
let notParsed: SeededMessage;
let noneStored: SeededMessage;
let expired: SeededMessage;
let entryPublicId: string;
let matchedUserPublicId: string;
const roles = new Map<TenantRole, Record<string, string>>();
let adminB: Record<string, string>;
let readKey: Record<string, string>;
let revealKey: Record<string, string>;

/** The graph of one message: headers, parse row, SMTP texts, an Rspamd result, a quarantine entry. */
async function seedSensitive(
  org: FixtureOrganization,
  subject: string,
  addresses: readonly string[],
): Promise<SeededMessage> {
  const m = await seedMessage(ctx, org, {
    receivedAt: new Date(Date.now() - 20 * MIN),
    subject,
    recipients: [...addresses],
    quarantine: [{ rcptSeq: 0, status: 'held' }],
  });
  const p = ctx.prisma;
  const at = m.receivedAt;
  const scope = { messageId: m.id, receivedAt: at, organizationId: org.id };
  await p.emailMessageParse.create({
    data: {
      ...scope,
      status: 'parsed',
      parserVersion: 'fixture',
      startedAt: at,
      completedAt: new Date(at.getTime() + 500),
    },
  });
  await p.emailHeader.createMany({
    data: [
      { seq: 0, name: 'From', value: 'Vendor <billing@vendor.example>' },
      { seq: 1, name: 'To', value: `Alice <${addresses[0]}>, ${addresses[1]}` },
      { seq: 2, name: 'Cc', value: addresses[2]! },
      { seq: 3, name: 'Subject', value: subject },
      { seq: 4, name: 'Message-ID', value: `<${run}@vendor.example>` },
      { seq: 5, name: 'Authentication-Results', value: 'mx.acme.example; spf=pass' },
    ].map((h) => ({ ...scope, ...h })),
  });
  const reply = `550 5.1.1 <${addresses[0]}>: Recipient address rejected`;
  await p.emailDelivery.updateMany({
    where: { messageId: m.id, receivedAt: at, organizationId: org.id },
    data: { finalSmtpResponse: reply },
  });
  const delivery = await p.emailDelivery.findFirstOrThrow({
    where: { messageId: m.id, receivedAt: at, organizationId: org.id },
    select: { id: true, recipientId: true },
  });
  await p.deliveryStatusEvent.create({
    data: {
      ...scope,
      deliveryId: delivery.id,
      recipientId: delivery.recipientId,
      source: 'postfix_log',
      signalKey: randomUUID().replace(/-/g, '').padEnd(64, '0'),
      occurredAt: at,
      fromStatus: 'queued',
      toStatus: 'bounced',
      applied: true,
      smtpCode: 550,
      detail: `relay=mx.acme.example said: ${reply}`,
    },
  });
  await p.scanEngineResult.create({
    data: {
      ...scope,
      scanId: m.scanId,
      engine: 'rspamd',
      engineVersion: '3.12.1',
      outcome: 'clean',
      score: new Prisma.Decimal('1.5'),
      requiredScore: new Prisma.Decimal('15'),
      action: 'no action',
      durationMs: 40,
      attempt: 1,
      isFinal: true,
      reasonCodes: ['clean.no_findings'],
      evidence: {
        signals: [
          { name: 'TO_DN_SOME', score: 0, options: [`${addresses[0]}`, `${addresses[1]}`] },
          { name: 'R_SPF_ALLOW', score: -0.2, options: ['+ip4:198.51.100.7'] },
        ],
      },
      completedAt: at,
    },
  });
  return m;
}

/** A bare message for the header availability states. */
async function bare(
  org: FixtureOrganization,
  receivedAt: Date,
  parse: 'parsed' | null,
): Promise<SeededMessage> {
  const m = await seedMessage(ctx, org, { receivedAt, subject: `Bare ${run}` });
  if (parse) {
    await ctx.prisma.emailMessageParse.create({
      data: {
        messageId: m.id,
        receivedAt,
        organizationId: org.id,
        status: parse,
        parserVersion: 'fixture',
        startedAt: receivedAt,
        completedAt: receivedAt,
      },
    });
  }
  return m;
}

const login = async (org: FixtureOrganization, role: string) =>
  bearer((await loginWithMfa(ctx, fx, await fx.createUser(org, { roles: [role] }))).accessToken);

const postAs = (headers: Record<string, string>, path: string, body: unknown) =>
  ctx.http
    .post(`/api/v1${path}`)
    .set(headers)
    .set('X-Forwarded-For', uniqueIp())
    .send(body as object);

/** Every clear sensitive value of the A message (none may appear in a read). */
const CLEAR_VALUES = () => [...ADDRESSES, SUBJECT, matchedUserPublicId];

const expectMasked = (body: unknown, label: string) => {
  const text = JSON.stringify(body);
  for (const value of CLEAR_VALUES()) expect(text, label).not.toContain(value);
};

/** The newest audit row id: rows written after it are the test's own. */
const auditMark = async (): Promise<bigint> =>
  (await ctx.prisma.auditLog.aggregate({ _max: { id: true } }))._max.id ?? 0n;

/** `message.revealed` rows of a message on the writer after `mark`. */
const revealRows = (publicId: string, mark: bigint) =>
  ctx.prisma.auditLog.findMany({
    where: {
      action: 'message.revealed',
      resourceType: 'message',
      resourceId: publicId,
      id: { gt: mark },
    },
    orderBy: { id: 'asc' },
  });

beforeAll(async () => {
  ctx = await createIntegrationApp({ API_MESSAGES_REVEAL_PER_MINUTE: '200' });
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  fx.registerCleanup(() => deleteMessagesData(ctx, [orgA.id, orgB.id]));
  message = await seedSensitive(orgA, SUBJECT, ADDRESSES);
  foreign = await seedSensitive(orgB, `Foreign ${run}`, ADDRESSES);
  const now = Date.now();
  notParsed = await bare(orgA, new Date(now - 10 * MIN), null);
  noneStored = await bare(orgA, new Date(now - 11 * MIN), 'parsed');
  // Older than the 3-month email_headers retention, within the 6-month message retention.
  expired = await bare(orgA, new Date(now - 125 * DAY), 'parsed');
  const user = await fx.createUser(orgA, { roles: ['read_only_user'] });
  matchedUserPublicId = user.publicId;
  await ctx.prisma.emailRecipient.updateMany({
    where: { messageId: message.id, receivedAt: message.receivedAt, rcptSeq: 0 },
    data: { userId: user.id },
  });
  entryPublicId = (
    await ctx.prisma.quarantineMessage.findFirstOrThrow({
      where: { messageId: message.id, organizationId: orgA.id },
      select: { publicId: true },
    })
  ).publicId;
  for (const role of TENANT_ROLES) roles.set(role, await login(orgA, role));
  adminB = await login(orgB, 'organization_admin');
  readKey = apiKeyHeader(
    await fx.createApiKey(orgA, ['message:read', 'delivery:read', 'quarantine:read']),
  );
  revealKey = apiKeyHeader(
    await fx.createApiKey(orgA, ['message:read', 'quarantine:read', 'message:reveal']),
  );
  // Replica visibility of the fixtures (the last rows written: the bare messages).
  const admin = roles.get('organization_admin')!;
  const visible = async (id: string, availability: string): Promise<boolean> => {
    const res = await getAs(ctx, admin, `/messages/${id}/headers`);
    return (res.body as { availability?: string }).availability === availability;
  };
  for (const [id, availability] of [
    [message.publicId, 'available'],
    [notParsed.publicId, 'not_parsed'],
    [noneStored.publicId, 'none_stored'],
    [expired.publicId, 'retention_expired'],
  ] as const) {
    const deadline = Date.now() + POLL.timeout;
    while (!(await visible(id, availability))) {
      if (Date.now() > deadline) throw new Error(`replica never showed ${availability}`);
      await new Promise((resolve) => setTimeout(resolve, POLL.interval));
    }
  }
}, 240_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('masked reads on every changed route (§2 E5, E7, E8, E9)', () => {
  const from = () => new Date(Date.now() - DAY).toISOString();
  const paths = () => [
    ['message:read', `/messages?from=${encodeURIComponent(from())}`],
    ['message:read', `/messages/${message.publicId}`],
    ['message:read', `/messages/${message.publicId}/recipients`],
    ['message:read', `/messages/${message.publicId}/headers`],
    ['message:read', `/messages/${message.publicId}/scans`],
    ['delivery:read', `/messages/${message.publicId}/deliveries`],
    ['delivery:read', `/messages/${message.publicId}/deliveries/events`],
    ['delivery:read', `/deliveries?from=${encodeURIComponent(from())}`],
  ];

  it.each(TENANT_ROLES.map((r) => [r]))('%s: masked values or 403', async (role) => {
    const headers = roles.get(role)!;
    for (const [, path] of paths()) {
      const res = await getAs(ctx, headers, path!);
      if (role === 'mailbox_user') {
        expect(res.status, path).toBe(403);
        continue;
      }
      expect(res.status, `${role} ${path}`).toBe(200);
      expectMasked(res.body, `${role} ${path}`);
    }
  });

  it('API keys see the same masks', async () => {
    for (const headers of [readKey, revealKey]) {
      for (const [permission, path] of paths()) {
        const res = await getAs(ctx, headers, path!);
        if (headers === revealKey && permission === 'delivery:read') {
          expect(res.status, path).toBe(403);
          continue;
        }
        expect(res.status, path).toBe(200);
        expectMasked(res.body, path!);
      }
    }
  });

  it('the masked shapes: subject null/subjectMasked, masked addresses, userId null, masked texts', async () => {
    const admin = roles.get('organization_admin')!;
    const detail = await getAs(ctx, admin, `/messages/${message.publicId}`);
    expect(detail.body).toMatchObject({ subject: null, subjectMasked: true });
    const recipients = await getAs(ctx, admin, `/messages/${message.publicId}/recipients`);
    expect(recipients.body.data).toMatchObject(
      ADDRESSES.map((address, rcptSeq) => ({
        rcptSeq,
        address: `${address[0]}***@acme.example`,
        addressMasked: true,
        userId: null,
      })),
    );
    const deliveries = await getAs(ctx, admin, `/messages/${message.publicId}/deliveries`);
    for (const d of deliveries.body.deliveries) {
      expect(d).toMatchObject({
        rcptSeq: 0,
        recipient: 'a***@acme.example',
        recipientMasked: true,
        finalSmtpResponse: '550 5.1.1 <a***@acme.example>: Recipient address rejected',
      });
    }
    const events = await getAs(ctx, admin, `/messages/${message.publicId}/deliveries/events`);
    expect(events.body.data[0].detail).toBe(
      'relay=mx.acme.example said: 550 5.1.1 <a***@acme.example>: Recipient address rejected',
    );
    const scans = await getAs(ctx, admin, `/messages/${message.publicId}/scans`);
    const rspamd = scans.body.data[0].engines.find(
      (e: { engine: string }) => e.engine === 'rspamd',
    );
    expect(rspamd.symbols).toEqual([
      { name: 'TO_DN_SOME', score: 0, options: ['a***@acme.example', 'b***@acme.example'] },
      { name: 'R_SPF_ALLOW', score: -0.2, options: ['+ip4:198.51.100.7'] },
    ]);
  });
});

describe('GET /messages/{messageId}/headers (§2 E7)', () => {
  it('the stored rows: the safe subset in clear, To/Cc/Subject withheld', async () => {
    const res = await getAs(
      ctx,
      roles.get('read_only_user')!,
      `/messages/${message.publicId}/headers`,
    );
    expect(res.status).toBe(200);
    expect(res.body.availability).toBe('available');
    expect(res.body.storedHeaderNames).toHaveLength(12);
    expect(res.body.headers).toEqual([
      { seq: 0, name: 'From', value: 'Vendor <billing@vendor.example>', masked: false },
      { seq: 1, name: 'To', value: null, masked: true },
      { seq: 2, name: 'Cc', value: null, masked: true },
      { seq: 3, name: 'Subject', value: null, masked: true },
      { seq: 4, name: 'Message-ID', value: `<${run}@vendor.example>`, masked: false },
      { seq: 5, name: 'Authentication-Results', value: 'mx.acme.example; spf=pass', masked: false },
    ]);
  });

  it.each([
    ['not_parsed', () => notParsed],
    ['none_stored', () => noneStored],
    ['retention_expired', () => expired],
  ])('availability %s', async (availability, of) => {
    const res = await getAs(
      ctx,
      roles.get('read_only_user')!,
      `/messages/${of().publicId}/headers`,
    );
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ availability, headers: [] });
  });
});

describe('the audited reveals (§2 E6)', () => {
  it.each(TENANT_ROLES.map((r) => [r]))('%s: reveal only with message:reveal', async (role) => {
    const headers = roles.get(role)!;
    const one = await postAs(headers, `/messages/${message.publicId}/reveal`, {
      fields: ['subject'],
    });
    const many = await postAs(headers, '/messages/reveal', { messageIds: [message.publicId] });
    if (REVEALERS.has(role)) {
      expect([one.status, many.status], role).toEqual([200, 200]);
      expect(one.body.subject).toBe(SUBJECT);
      expect(many.body.data).toEqual([{ id: message.publicId, subject: SUBJECT }]);
    } else {
      expect([one.status, many.status], role).toEqual([403, 403]);
      expectMasked([one.body, many.body], role);
    }
  });

  it('returns exactly the stored values; the audit row is on the writer when the response arrives', async () => {
    const since = await auditMark();
    const res = await postAs(
      roles.get('security_analyst')!,
      `/messages/${message.publicId}/reveal`,
      {
        fields: ['subject', 'headers', 'recipients'],
      },
    );
    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    // Read on the writer immediately (no polling): committed before the response.
    const rows = await revealRows(message.publicId, since);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      organizationId: orgA.id,
      actorType: 'user',
      action: 'message.revealed',
      resourceType: 'message',
      resourceId: message.publicId,
    });
    expect(rows[0]!.metadata).toMatchObject({
      fields: ['subject', 'headers', 'recipients'],
      headerCount: 3,
      recipients: { count: 3, firstRcptSeq: 0, lastRcptSeq: 2 },
    });
    expect(JSON.stringify(rows[0]!.metadata)).not.toMatch(new RegExp(`${run}`));
    // The values equal the stored rows.
    const stored = await ctx.prisma.emailMessage.findFirstOrThrow({
      where: { id: message.id, receivedAt: message.receivedAt },
      select: { subject: true },
    });
    const headers = await ctx.prisma.emailHeader.findMany({
      where: {
        messageId: message.id,
        receivedAt: message.receivedAt,
        name: { in: ['To', 'Cc', 'Subject'] },
      },
      orderBy: { seq: 'asc' },
      select: { seq: true, name: true, value: true },
    });
    const recipients = await ctx.prisma.emailRecipient.findMany({
      where: { messageId: message.id, receivedAt: message.receivedAt },
      orderBy: { rcptSeq: 'asc' },
      select: { rcptSeq: true, address: true, userId: true },
    });
    expect(res.body).toEqual({
      messageId: message.publicId,
      revealedAt: expect.any(String),
      subject: stored.subject,
      headers,
      recipients: {
        data: recipients.map((r) => ({
          rcptSeq: r.rcptSeq,
          address: r.address,
          userId: r.userId === null ? null : matchedUserPublicId,
        })),
        nextCursor: null,
      },
    });
  });

  it('bulk: one audit row per revealed message, foreign and unknown ids omitted', async () => {
    const since = await auditMark();
    const beforeB = await ctx.prisma.auditLog.count({
      where: { organizationId: orgB.id, action: 'message.revealed' },
    });
    const res = await postAs(roles.get('compliance_auditor')!, '/messages/reveal', {
      messageIds: [foreign.publicId, noneStored.publicId, randomUUID(), message.publicId],
    });
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual([
      { id: noneStored.publicId, subject: `Bare ${run}` },
      { id: message.publicId, subject: SUBJECT },
    ]);
    for (const m of [noneStored, message]) {
      const rows = await revealRows(m.publicId, since);
      expect(
        rows.map((r) => r.metadata),
        m.publicId,
      ).toEqual([expect.objectContaining({ fields: ['subject'], bulk: true })]);
    }
    expect(await revealRows(foreign.publicId, since)).toEqual([]);
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: orgB.id, action: 'message.revealed' },
      }),
    ).toBe(beforeB);
  });

  it('pages recipients with recipientsCursor (one audit row per page)', async () => {
    const since = await auditMark();
    const key = revealKey;
    const first = await postAs(key, `/messages/${message.publicId}/reveal`, {
      fields: ['recipients'],
      recipientsLimit: 2,
    });
    expect(first.status).toBe(200);
    expect(first.body.recipients.data.map((r: { address: string }) => r.address)).toEqual(
      ADDRESSES.slice(0, 2),
    );
    const next = await postAs(key, `/messages/${message.publicId}/reveal`, {
      fields: ['recipients'],
      recipientsCursor: first.body.recipients.nextCursor,
      recipientsLimit: 2,
    });
    expect(next.body.recipients).toEqual({
      data: [{ rcptSeq: 2, address: ADDRESSES[2], userId: null }],
      nextCursor: null,
    });
    const rows = await revealRows(message.publicId, since);
    expect(rows.map((r) => [r.actorType, r.metadata])).toEqual([
      [
        'api_key',
        expect.objectContaining({ recipients: { count: 2, firstRcptSeq: 0, lastRcptSeq: 1 } }),
      ],
      [
        'api_key',
        expect.objectContaining({ recipients: { count: 1, firstRcptSeq: 2, lastRcptSeq: 2 } }),
      ],
    ]);
  });

  it('an override session is audited with the override', async () => {
    const operator = await fx.createPlatformUser(['super_admin']);
    const session = await loginWithMfa(ctx, fx, operator);
    const started = await ctx.http
      .post('/api/v1/platform/overrides')
      .set(bearer(session.accessToken))
      .set('X-Forwarded-For', uniqueIp())
      .send({ organizationId: orgA.publicId, reason: 'Reveal audit check (step 7.2)' });
    expect(started.status).toBe(201);
    try {
      const since = await auditMark();
      const res = await postAs(
        bearer(started.body.accessToken as string),
        `/messages/${message.publicId}/reveal`,
        { fields: ['subject'] },
      );
      expect(res.status).toBe(200);
      expect(res.body.subject).toBe(SUBJECT);
      const rows = await revealRows(message.publicId, since);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        organizationId: orgA.id,
        actorType: 'user',
        actorId: operator.publicId,
      });
      expect(rows[0]!.metadata).toMatchObject({
        fields: ['subject'],
        override: { id: started.body.overrideId, reason: 'Reveal audit check (step 7.2)' },
      });
    } finally {
      await ctx.http
        .delete(`/api/v1/platform/overrides/${started.body.overrideId as string}`)
        .set(bearer(session.accessToken))
        .set('X-Forwarded-For', uniqueIp());
    }
  });
});

describe('quarantine recipient rule per role (§2 E8)', () => {
  const window = () => ({
    from: new Date(Date.now() - DAY).toISOString(),
    to: new Date(Date.now() + MIN).toISOString(),
  });
  const expected: Record<TenantRole, 'clear' | 'masked' | 403> = {
    organization_admin: 'clear',
    domain_admin: 'masked',
    security_analyst: 'clear',
    quarantine_reviewer: 'clear',
    compliance_auditor: 'clear',
    read_only_user: 'masked',
    mailbox_user: 403,
  };
  const views = {
    clear: { recipient: ADDRESSES[0], recipientMasked: false },
    masked: { recipient: 'a***@acme.example', recipientMasked: true },
  };

  it.each(TENANT_ROLES.map((r) => [r]))('%s', async (role) => {
    const headers = roles.get(role)!;
    const { from, to } = window();
    const search = await getAs(
      ctx,
      headers,
      `/quarantine/entries?messageId=${message.publicId}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
    );
    const detail = await getAs(ctx, headers, `/quarantine/entries/${entryPublicId}`);
    const want = expected[role];
    if (want === 403) {
      expect([search.status, detail.status]).toEqual([403, 403]);
      return;
    }
    expect([search.status, detail.status], role).toEqual([200, 200]);
    expect(search.body.items, role).toEqual([expect.objectContaining(views[want])]);
    expect(detail.body, role).toMatchObject(views[want]);
  });

  it('API keys: masked with quarantine:read, clear with message:reveal', async () => {
    expect((await getAs(ctx, readKey, `/quarantine/entries/${entryPublicId}`)).body).toMatchObject(
      views.masked,
    );
    expect(
      (await getAs(ctx, revealKey, `/quarantine/entries/${entryPublicId}`)).body,
    ).toMatchObject(views.clear);
  });
});

describe('tenant isolation of the WP2 routes', () => {
  it('B gets 404 for A ids on the headers and single reveal; the bulk reveal omits them', async () => {
    const headers = await getAs(ctx, adminB, `/messages/${message.publicId}/headers`);
    expect([headers.status, headers.body.code]).toEqual([404, 'message_not_found']);
    const one = await postAs(adminB, `/messages/${message.publicId}/reveal`, {
      fields: ['subject', 'recipients'],
    });
    expect([one.status, one.body.code]).toEqual([404, 'message_not_found']);
    const many = await postAs(adminB, '/messages/reveal', { messageIds: [message.publicId] });
    expect(many.status).toBe(200);
    expect(many.body.data).toEqual([]);
    expectMasked([headers.body, one.body, many.body], 'tenant B');
  });

  it('an A recipients cursor is 400 cursor_invalid for B (on A and on B messages)', async () => {
    const first = await postAs(
      roles.get('organization_admin')!,
      `/messages/${message.publicId}/reveal`,
      {
        fields: ['recipients'],
        recipientsLimit: 1,
      },
    );
    const cursor = first.body.recipients.nextCursor as string;
    expect(cursor).toEqual(expect.any(String));
    for (const id of [message.publicId, foreign.publicId]) {
      const res = await postAs(adminB, `/messages/${id}/reveal`, {
        fields: ['recipients'],
        recipientsCursor: cursor,
      });
      expect([res.status, res.body.code], id).toEqual([400, 'cursor_invalid']);
    }
    // And an A cursor on another A message.
    const other = await postAs(
      roles.get('organization_admin')!,
      `/messages/${noneStored.publicId}/reveal`,
      {
        fields: ['recipients'],
        recipientsCursor: cursor,
      },
    );
    expect([other.status, other.body.code]).toEqual([400, 'cursor_invalid']);
  });
});

describe('the reveal limit on the real Redis (API_MESSAGES_REVEAL_PER_MINUTE=2)', () => {
  it('429 rate_limited with Retry-After after two reveals of one principal', async () => {
    const limited = await createIntegrationApp({ API_MESSAGES_REVEAL_PER_MINUTE: '2' });
    try {
      const key = apiKeyHeader(await fx.createApiKey(orgA, ['message:reveal']));
      const call = () =>
        limited.http
          .post('/api/v1/messages/reveal')
          .set(key)
          .set('X-Forwarded-For', uniqueIp())
          .send({ messageIds: [message.publicId] });
      expect((await call()).status).toBe(200);
      expect((await call()).status).toBe(200);
      const res = await call();
      expect(res.status).toBe(429);
      expect(res.body).toMatchObject({ code: 'rate_limited', scope: 'route' });
      expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
      expect(res.headers['ratelimit-remaining']).toBe('0');
    } finally {
      await limited.close();
    }
  });
});
