// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { createMockFetch, mergedFixtures } from '@/server/dev-mocks';
import {
  DATASET_SIZE,
  FIXTURE_DELIVERY_STATUSES,
  FIXTURE_QUARANTINE_STATES,
  IDN_SENDER_DOMAIN,
  SENDER_DOMAINS,
  domainIdFor,
  fixtureDataset,
  fixtureMessageById,
  maskAddress,
  maskAddressesInText,
  quarantineStatesOf,
} from './message-dataset';
import {
  FIXTURE_REVEALS_PER_MINUTE,
  FIXTURE_SAVED_VIEWS_MAX,
  FIXTURE_SEARCH_MAX_MATCHES,
} from './messages';

/** Step 7.2 WP3 dev fixtures: the message dataset, `GET /messages`, reveal and saved views. */
const API = 'http://api.test:3000';
const fetchImpl = createMockFetch(mergedFixtures());
const DAY = 86_400_000;

async function login(email: string): Promise<string> {
  const response = await fetchImpl(`${API}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'any' }),
  });
  const body = (await response.json()) as { accessToken?: string; mfaToken?: string };
  if (body.accessToken) return body.accessToken;
  const verified = await fetchImpl(`${API}/api/v1/auth/mfa/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ mfaToken: body.mfaToken, code: '123456' }),
  });
  return ((await verified.json()) as { accessToken: string }).accessToken;
}
const as = (role: string) => login(`${role}@example.com`);

async function call(token: string, method: string, path: string, body?: unknown) {
  const response = await fetchImpl(`${API}/api/v1${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: body === undefined ? null : JSON.stringify(body),
  });
  const text = await response.text();
  return {
    status: response.status,
    headers: response.headers,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- loose JSON in a test
    body: (text ? JSON.parse(text) : null) as Record<string, any>,
  };
}

const window = (days: number) => {
  const to = new Date(Math.ceil((Date.now() + 60_000) / 60_000) * 60_000);
  return `from=${new Date(to.getTime() - days * DAY).toISOString()}&to=${to.toISOString()}`;
};
type Item = { id: string; subject: string | null; subjectMasked: boolean; domainId: string | null };

describe('message dataset (§2 E14)', () => {
  const data = fixtureDataset();

  it('holds about 1 500 synthetic messages over 31 days, newest first, with stable ids', () => {
    expect(data).toHaveLength(DATASET_SIZE);
    const times = data.map((m) => Date.parse(m.detail.receivedAt));
    expect([...times].sort((a, b) => b - a)).toEqual(times);
    expect((times[0] ?? 0) - (times.at(-1) ?? 0)).toBeLessThan(31 * DAY);
    expect(times.filter((t) => t > Date.now() - 3_600_000).length).toBeGreaterThan(0);
    const first = data[0];
    expect(first && fixtureMessageById(first.detail.id.toUpperCase())).toBe(first);
    for (const m of data) {
      for (const address of [m.detail.envelopeFrom, ...m.recipients].filter(Boolean)) {
        expect(address).toMatch(/@(?:[a-z0-9-]+\.)*(?:example\.test|example\.com)$/);
      }
    }
  });

  it('has ~60 sender domains (an IDN in A-label form), outbound recipient domains and every state', () => {
    expect(SENDER_DOMAINS.length).toBeGreaterThanOrEqual(58);
    const senderDomains = new Set(data.map((m) => m.detail.envelopeFrom.split('@')[1]));
    expect(senderDomains.has(IDN_SENDER_DOMAIN)).toBe(true);
    expect(senderDomains.size).toBeGreaterThan(55);
    const deliveries = new Set(data.flatMap((m) => m.recipientRows.map((r) => r.delivery)));
    for (const status of FIXTURE_DELIVERY_STATUSES)
      expect(deliveries.has(status), status).toBe(true);
    const quarantine = new Set(data.flatMap((m) => m.recipientRows.map((r) => r.quarantine)));
    for (const state of FIXTURE_QUARANTINE_STATES) expect(quarantine.has(state), state).toBe(true);
    expect(data.some((m) => m.detail.direction === 'outbound')).toBe(true);
    expect(data.some((m) => m.detail.envelopeFrom === '')).toBe(true);
    expect(data.some((m) => m.recipients.includes('mailbox_user@example.com'))).toBe(true);
    const scores = data.map((m) => m.detail.riskScore).filter((s): s is number => s !== null);
    expect(Math.min(...scores)).toBeLessThan(100);
    expect(Math.max(...scores)).toBeGreaterThan(900);
  });

  it('has subjects with reply markers, non-ASCII, right-to-left and hostile text', () => {
    const subjects = data.map((m) => m.detail.subject ?? '');
    expect(subjects.some((s) => /^(Re|RE|Fwd|FW|AW|SV)(\[\d\])?: /.test(s))).toBe(true);
    expect(subjects.some((s) => /[^\p{ASCII}]/u.test(s))).toBe(true);
    expect(subjects.some((s) => /\p{Script=Arabic}|\p{Script=Hebrew}/u.test(s))).toBe(true);
    expect(subjects.some((s) => s.includes('<script>'))).toBe(true);
    expect(data.some((m) => m.detail.subject === null)).toBe(true);
  });

  it('masks like the api (maskAddress, maskAddressesInText)', () => {
    expect(maskAddress('finance.team@acme.example')).toBe('f***@acme.example');
    expect(maskAddress('nobody')).toBe('n***');
    expect(maskAddress('')).toBe('');
    expect(maskAddressesInText('550 5.1.1 <jane.doe@alpha-1.example.test>: User unknown')).toBe(
      '550 5.1.1 <j***@alpha-1.example.test>: User unknown',
    );
    expect(maskAddressesInText('"john doe"@example.com and a@b.example')).toBe(
      '"***@example.com and a***@b.example',
    );
    expect(maskAddressesInText('mail for user@localhost')).toBe('mail for user@localhost');
  });
});

describe('GET /messages fixture (§2 E1, E2, E5)', () => {
  it('returns masked subjects and the organization’s domain ids, 24 h by default', async () => {
    const token = await as('security_analyst');
    const page = await call(token, 'GET', '/messages?limit=100');
    expect(page.status).toBe(200);
    const items = page.body.data as Item[];
    expect(items.length).toBeGreaterThan(0);
    for (const item of items) expect(item.subject).toBeNull();
    expect(items.some((item) => item.subjectMasked)).toBe(true);
    const me = await call(token, 'GET', '/auth/me');
    const orgDomains = [0, 1, 2].map((i) => domainIdFor(me.body.organization.id, i));
    expect(
      items.every((item) => item.domainId === null || orgDomains.includes(item.domainId)),
    ).toBe(true);
    const detail = await call(token, 'GET', `/messages/${items[0]?.id}`);
    expect(detail.body.subject).toBeNull();
  });

  it('identifier searches are exact pages in time order (driver without residuals)', async () => {
    const token = await as('security_analyst');
    const target = fixtureDataset().find(
      (m) => m.detail.internetMessageId && m.detail.envelopeFrom,
    );
    if (!target) throw new Error('dataset');
    const bare = (target.detail.internetMessageId ?? '').replace(/^<|>$/g, '');
    const byId = await call(
      token,
      'GET',
      `/messages?${window(31)}&internetMessageId=${encodeURIComponent(bare)}`,
    );
    expect((byId.body.data as Item[]).map((i) => i.id)).toEqual([target.detail.id]);
    expect(byId.body.nextCursor).toBeNull();

    const sender = target.detail.envelopeFrom;
    const expected = fixtureDataset()
      .filter((m) => m.detail.envelopeFrom === sender)
      .map((m) => m.detail.id);
    const bySender = await call(
      token,
      'GET',
      `/messages?${window(31)}&limit=100&sender=${encodeURIComponent(sender.toUpperCase())}`,
    );
    expect((bySender.body.data as Item[]).map((i) => i.id)).toEqual(expected);

    const idn = await call(
      token,
      'GET',
      `/messages?${window(31)}&limit=100&senderDomain=%40${IDN_SENDER_DOMAIN.toUpperCase()}`,
    );
    expect((idn.body.data as Item[]).length).toBeGreaterThan(0);
    expect(
      (idn.body.data as Item[]).every((i) =>
        fixtureMessageById(i.id)?.detail.envelopeFrom.endsWith(`@${IDN_SENDER_DOMAIN}`),
      ),
    ).toBe(true);
  });

  it('subject searches ignore reply markers, case and accents', async () => {
    const token = await as('security_analyst');
    const exact = await call(
      token,
      'GET',
      `/messages?${window(31)}&limit=100&subject=${encodeURIComponent('re: RECHNUNG FUR OKTOBER')}`,
    );
    expect(exact.status).toBe(200);
    const ids = (exact.body.data as Item[]).map((i) => i.id);
    expect(ids.length).toBeGreaterThan(0);
    for (const id of ids)
      expect(fixtureMessageById(id)?.detail.subject).toMatch(/Rechnung für Oktober$/);
  });

  it('refuses a too broad subject prefix (cap 200), simulates the timeout, accepts a narrow one', async () => {
    const token = await as('security_analyst');
    const broad = await call(token, 'GET', `/messages?${window(31)}&subjectPrefix=Weekly`);
    expect(broad.status).toBe(422);
    expect(broad.body).toMatchObject({
      code: 'message_search_too_broad',
      maxMatches: FIXTURE_SEARCH_MAX_MATCHES,
    });
    const slow = await call(token, 'GET', `/messages?${window(31)}&subjectPrefix=zzz-timeout`);
    expect(slow.status).toBe(503);
    expect(slow.body.code).toBe('message_search_timeout');
    const narrow = await call(
      token,
      'GET',
      `/messages?${window(31)}&limit=100&subjectPrefix=Invoice%2044`,
    );
    expect(narrow.status).toBe(200);
    for (const item of narrow.body.data as Item[]) {
      expect(fixtureMessageById(item.id)?.detail.subject).toMatch(/Invoice 44/);
    }
  });

  it('applies the filter-level permissions (403 message_filter_forbidden)', async () => {
    const readOnly = await as('read_only_user');
    const refused = await call(readOnly, 'GET', '/messages?subject=Invoice');
    expect(refused.status).toBe(403);
    expect(refused.body).toMatchObject({
      code: 'message_filter_forbidden',
      filter: 'subject',
      permission: 'message:reveal',
    });
    expect((await call(readOnly, 'GET', '/messages?deliveryStatus=bounced')).status).toBe(200);
    // The exact recipient confirms a masked address: message:reveal too; its domain is open.
    expect(
      (await call(readOnly, 'GET', '/messages?recipient=priya.rao4%40alpha.example.test')).body,
    ).toMatchObject({
      code: 'message_filter_forbidden',
      filter: 'recipient',
      permission: 'message:reveal',
    });
    expect(
      (await call(readOnly, 'GET', '/messages?recipientDomain=alpha.example.test')).status,
    ).toBe(200);
    // Every system role with message:read also holds delivery:read and quarantine:read, so only
    // the subject filters are refused for system roles (domain admins have no message:reveal).
    const domainAdmin = await as('domain_admin');
    expect((await call(domainAdmin, 'GET', '/messages?subjectPrefix=Invoice')).body).toMatchObject({
      code: 'message_filter_forbidden',
      filter: 'subjectPrefix',
    });
    expect((await call(domainAdmin, 'GET', '/messages?quarantineStatus=held')).status).toBe(200);
  });

  it('delivery and quarantine status filters match any recipient', async () => {
    const token = await as('security_analyst');
    const bounced = await call(
      token,
      'GET',
      `/messages?${window(31)}&limit=100&deliveryStatus=bounced`,
    );
    expect((bounced.body.data as Item[]).length).toBeGreaterThan(0);
    for (const item of bounced.body.data as Item[]) {
      expect(fixtureMessageById(item.id)?.recipientRows.some((r) => r.delivery === 'bounced')).toBe(
        true,
      );
    }
    const held = await call(
      token,
      'GET',
      `/messages?${window(31)}&limit=100&quarantineStatus=pending_approval`,
    );
    for (const item of held.body.data as Item[]) {
      const message = fixtureMessageById(item.id);
      expect(message && quarantineStatesOf(message)).toContain('pending_approval');
    }
  });

  it('residual-only filters are budgeted: short pages with a cursor, every row matching', async () => {
    const token = await as('security_analyst');
    let cursor: string | null = null;
    let sawShort = false;
    const ids = new Set<string>();
    for (let n = 0; n < 60; n += 1) {
      const page: Awaited<ReturnType<typeof call>> = await call(
        token,
        'GET',
        `/messages?${window(30)}&limit=50&direction=outbound${cursor ? `&cursor=${cursor}` : ''}`,
      );
      expect(page.status).toBe(200);
      for (const item of page.body.data as Item[]) {
        expect(fixtureMessageById(item.id)?.detail.direction).toBe('outbound');
        expect(ids.has(item.id)).toBe(false);
        ids.add(item.id);
      }
      if ((page.body.data as Item[]).length < 50 && page.body.nextCursor) sawShort = true;
      cursor = page.body.nextCursor;
      if (!cursor) break;
    }
    expect(sawShort).toBe(true);
    expect(cursor).toBeNull();
  });

  it('validates like the api and binds cursors to their filters', async () => {
    const token = await as('security_analyst');
    expect((await call(token, 'GET', '/messages?nope=1')).body.message).toEqual([
      'nope: unknown parameter',
    ]);
    expect(
      (
        await call(
          token,
          'GET',
          '/messages?status=received,persisted,scanning,scanned,delivered,expired',
        )
      ).status,
    ).toBe(400);
    expect((await call(token, 'GET', '/messages?senderDomain=münchen.example')).status).toBe(400);
    expect((await call(token, 'GET', '/messages?subjectPrefix=Re:%20ab')).status).toBe(400);
    expect((await call(token, 'GET', '/messages?internetMessageId=%3C%3E')).status).toBe(400);
    expect((await call(token, 'GET', `/messages?${window(32)}`)).status).toBe(400);
    expect(
      (await call(token, 'GET', '/messages?domainId=01933c3a-1b2c-7d4e-8f00-00000000d001')).body
        .code,
    ).toBe('domain_not_found');
    const first = await call(token, 'GET', `/messages?${window(7)}&limit=5`);
    const next = first.body.nextCursor as string;
    expect((await call(token, 'GET', `/messages?${window(7)}&limit=5&cursor=${next}`)).status).toBe(
      200,
    );
    expect(
      (await call(token, 'GET', `/messages?${window(7)}&limit=5&verdict=spam&cursor=${next}`)).body
        .code,
    ).toBe('cursor_invalid');
  });
});

describe('POST /messages/reveal fixture (§2 E6)', () => {
  it('needs message:reveal; returns subjects in request order, omits unknown ids, no-store', async () => {
    expect(
      (
        await call(await as('read_only_user'), 'POST', '/messages/reveal', {
          messageIds: [fixtureDataset()[0]?.detail.id],
        })
      ).status,
    ).toBe(403);
    const token = await as('compliance_auditor');
    const [a, b] = fixtureDataset().filter((m) => m.detail.subject !== null);
    if (!a || !b) throw new Error('dataset');
    const unknown = '01933c3a-1b2c-7d4e-8f00-00000000ffff';
    const response = await call(token, 'POST', '/messages/reveal', {
      messageIds: [b.detail.id, unknown, a.detail.id.toUpperCase()],
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.body.data).toEqual([
      { id: b.detail.id, subject: b.detail.subject },
      { id: a.detail.id, subject: a.detail.subject },
    ]);
    const audit = await call(
      token,
      'GET',
      `/audit/logs?${window(1)}&limit=100&action=message.revealed&resourceType=message&resourceId=${a.detail.id}`,
    );
    expect(audit.body.data).toHaveLength(1);
    expect(audit.body.data[0]).toMatchObject({
      action: 'message.revealed',
      resourceType: 'message',
      resourceId: a.detail.id,
      actor: { type: 'user' },
      metadata: { fields: ['subject'], bulk: true },
    });
    expect(JSON.stringify(audit.body)).not.toContain(a.detail.subject ?? '<none>');
  });

  it('validates the body strictly (distinct ids, 1–100, no other keys)', async () => {
    const token = await as('security_analyst');
    const id = fixtureDataset()[0]?.detail.id ?? '';
    expect(
      (await call(token, 'POST', '/messages/reveal', { messageIds: [id, id.toUpperCase()] })).body
        .message,
    ).toEqual(['messageIds: ids must be distinct']);
    expect((await call(token, 'POST', '/messages/reveal', { messageIds: [] })).status).toBe(400);
    expect(
      (await call(token, 'POST', '/messages/reveal', { messageIds: [id], extra: 1 })).status,
    ).toBe(400);
  });

  it('limits reveals per user and minute (429 with Retry-After)', async () => {
    const token = await login('mfa.organization_admin@example.com');
    const id = fixtureDataset()[0]?.detail.id ?? '';
    for (let i = 0; i < FIXTURE_REVEALS_PER_MINUTE; i += 1) {
      expect((await call(token, 'POST', '/messages/reveal', { messageIds: [id] })).status).toBe(
        200,
      );
    }
    const limited = await call(token, 'POST', '/messages/reveal', { messageIds: [id] });
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get('retry-after'))).toBeGreaterThan(0);
  });
});

describe('saved views fixture (§2 E4)', () => {
  const definition = {
    version: 1,
    filters: { verdict: 'phishing', direction: 'inbound' },
    sort: '-receivedAt',
    range: { kind: 'relative', preset: '7d' },
    columns: null,
  };

  it('lists the user’s seeded views, creates, renames, conflicts and deletes', async () => {
    const token = await as('security_analyst');
    const list = await call(token, 'GET', '/saved-views?kind=message_explorer&limit=100');
    expect(list.status).toBe(200);
    expect(list.body.data.map((v: { name: string }) => v.name)).toContain('Legacy triage view');
    const created = await call(token, 'POST', '/saved-views', {
      kind: 'message_explorer',
      name: 'Phishing 7d',
      definition,
    });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({
      name: 'Phishing 7d',
      rowVersion: 1,
      kind: 'message_explorer',
    });
    const taken = await call(token, 'POST', '/saved-views', {
      kind: 'message_explorer',
      name: 'PHISHING 7D',
      definition,
    });
    expect(taken.body.code).toBe('saved_view_name_taken');
    const id = created.body.id as string;
    const renamed = await call(token, 'PUT', `/saved-views/${id}`, {
      name: 'Phishing (7 days)',
      definition,
      expectedRowVersion: 1,
    });
    expect(renamed.body).toMatchObject({ name: 'Phishing (7 days)', rowVersion: 2 });
    const stale = await call(token, 'PUT', `/saved-views/${id}`, {
      name: 'x',
      definition,
      expectedRowVersion: 1,
    });
    expect(stale.body).toMatchObject({ code: 'saved_view_conflict', currentRowVersion: 2 });
    expect((await call(token, 'GET', `/saved-views/${id}`)).body.name).toBe('Phishing (7 days)');
    expect((await call(token, 'DELETE', `/saved-views/${id}`)).status).toBe(204);
    expect((await call(token, 'GET', `/saved-views/${id}`)).body.code).toBe('saved_view_not_found');
  });

  it('validates definitions like GET /messages and applies the filter permissions', async () => {
    const token = await as('read_only_user');
    const bad = await call(token, 'POST', '/saved-views', {
      kind: 'message_explorer',
      name: 'Bad',
      definition: { ...definition, filters: { senderDomain: 'not a domain', limit: '5' } },
    });
    expect(bad.status).toBe(400);
    expect(bad.body.message).toEqual(
      expect.arrayContaining([
        'definition.filters.limit: not allowed',
        'definition.filters.senderDomain: must be a domain name (IDNs in A-label form)',
      ]),
    );
    const forbidden = await call(token, 'POST', '/saved-views', {
      kind: 'message_explorer',
      name: 'Subjects',
      definition: { ...definition, filters: { subjectPrefix: 'Invoice' } },
    });
    expect(forbidden.body).toMatchObject({
      code: 'message_filter_forbidden',
      permission: 'message:reveal',
    });
    const tooLong = await call(token, 'POST', '/saved-views', {
      kind: 'message_explorer',
      name: 'Range',
      definition: {
        ...definition,
        range: {
          kind: 'absolute',
          from: '2026-01-01T00:00:00.000Z',
          to: '2026-03-01T00:00:00.000Z',
        },
      },
    });
    expect(tooLong.body.message).toEqual(['definition.range: at most 31 days']);
  });

  it('keeps views per user (another user’s view is 404) and enforces the per-user limit', async () => {
    const owner = await as('compliance_auditor');
    const other = await as('organization_admin');
    const created = await call(owner, 'POST', '/saved-views', {
      kind: 'message_explorer',
      name: 'Mine',
      definition,
    });
    expect((await call(other, 'GET', `/saved-views/${created.body.id}`)).status).toBe(404);
    const existing = (await call(owner, 'GET', '/saved-views?kind=message_explorer&limit=100')).body
      .data.length as number;
    for (let i = existing; i < FIXTURE_SAVED_VIEWS_MAX; i += 1) {
      expect(
        (
          await call(owner, 'POST', '/saved-views', {
            kind: 'message_explorer',
            name: `View ${i}`,
            definition,
          })
        ).status,
      ).toBe(201);
    }
    const limited = await call(owner, 'POST', '/saved-views', {
      kind: 'message_explorer',
      name: 'One more',
      definition,
    });
    expect(limited.body).toMatchObject({
      code: 'saved_view_limit_reached',
      limit: FIXTURE_SAVED_VIEWS_MAX,
    });
  });

  it('refuses platform override sessions (saved_views_member_only)', async () => {
    const operator = await login('mfa.super_admin@example.com');
    const orgs = await call(operator, 'GET', '/organizations?limit=5&kind=customer');
    const target = orgs.body.data[0]?.id as string;
    const started = await call(operator, 'POST', '/platform/overrides', {
      organizationId: target,
      reason: 'Fixture test of saved views',
      durationMinutes: 15,
    });
    expect(started.status).toBe(201);
    const response = await call(
      started.body.accessToken as string,
      'GET',
      '/saved-views?kind=message_explorer',
    );
    expect(response.body.code).toBe('saved_views_member_only');
  });
});

describe('masked recipients in the 7.1 fixtures (§2 E5, E8)', () => {
  it('quarantine entries: clear for deciders and message:reveal, masked for read-only users', async () => {
    const query = `/quarantine/entries?${window(31)}&limit=50`;
    const readOnly = await call(await as('read_only_user'), 'GET', query);
    expect(readOnly.status).toBe(200);
    for (const item of readOnly.body.items as { recipient: string; recipientMasked: boolean }[]) {
      expect(item.recipientMasked).toBe(true);
      expect(item.recipient).toMatch(/^.?\*\*\*@/);
    }
    const analyst = await call(await as('security_analyst'), 'GET', query);
    for (const item of analyst.body.items as { recipient: string; recipientMasked: boolean }[]) {
      expect(item.recipientMasked).toBe(false);
      expect(item.recipient).not.toContain('***');
    }
    const self = await call(
      await as('mailbox_user'),
      'GET',
      `/quarantine/me/entries?${window(31)}`,
    );
    for (const item of self.body.items as { recipientMasked: boolean }[])
      expect(item.recipientMasked).toBe(false);
  });

  it('deliveries of the mail servers page are masked for every caller', async () => {
    const deliveries = await call(
      await as('organization_admin'),
      'GET',
      `/deliveries?${window(31)}&limit=50`,
    );
    expect(deliveries.status).toBe(200);
    for (const item of deliveries.body.data as { recipient: string; recipientMasked: boolean }[]) {
      expect(item.recipientMasked).toBe(true);
      expect(item.recipient).toContain('***@');
    }
  });
});
