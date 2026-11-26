import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { GS_CUSTOMER_ID, GS_DOMAIN, GS_USERS, googleCustomer } from '../datasets/google';
import { syntheticEml } from '../datasets/mail';
import { MS_DOMAIN, MS_TENANT_ID, MS_USERS, microsoftDirectory } from '../datasets/microsoft';
import { GMAIL_MAIL_SCOPES } from './gmail-mail';
import { expireCursors, isLocalCallbackTarget, pushLifecycle, removeMessage } from './mail';
import { runStandalone, startSimulators, type RunningSimulators } from './main';
import { SimTokenRegistry } from './tokens';

// Step API-1 D13: the mail endpoints of the Graph and Gmail simulators, subscriptions with the
// validation handshake and notification push, and the admin API additions. Synthetic data only;
// callbacks go to a receiver on 127.0.0.1.
const NOW = new Date('2026-11-10T12:00:00.000Z');
const ALEX = MS_USERS.alex;
const INBOX_DELTA = (user: string) => `/v1.0/users/${user}/mailFolders('inbox')/messages/delta`;

interface Received {
  path: string;
  query: string;
  contentType: string;
  body: string;
}

let receiver: Server;
let receiverUrl: string;
const received: Received[] = [];
let echo: (token: string, req: IncomingMessage, res: ServerResponse) => void;

beforeAll(async () => {
  receiver = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url ?? '/', 'http://receiver.invalid');
      received.push({
        path: url.pathname,
        query: url.search,
        contentType: req.headers['content-type'] ?? '',
        body: Buffer.concat(chunks).toString('utf8'),
      });
      const token = url.searchParams.get('validationToken');
      if (token !== null) {
        echo(token, req, res);
        return;
      }
      res.writeHead(202);
      res.end();
    });
  });
  await new Promise<void>((resolve) => receiver.listen(0, '127.0.0.1', resolve));
  receiverUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}`;
});

afterAll(async () => {
  receiver.closeAllConnections();
  await new Promise<void>((resolve) => receiver.close(() => resolve()));
});

let sims: RunningSimulators;
let tokens: SimTokenRegistry;
let graphToken: string;
let gmailToken: (subject: string) => string;
let clock = NOW.getTime();

beforeEach(async () => {
  received.length = 0;
  clock = NOW.getTime();
  echo = (token, _req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(token);
  };
  tokens = new SimTokenRegistry({ now: () => clock });
  sims = await startSimulators({
    dataset: {
      microsoft: { directories: [microsoftDirectory(NOW)] },
      google: { customers: [googleCustomer(NOW)] },
    },
    tokens,
    now: () => clock,
  });
  tokens.setGrant(MS_TENANT_ID, 'm365.mailbox_remediation', ['Mail.ReadWrite', 'User.Read.All']);
  graphToken = tokens.issue({
    directoryId: MS_TENANT_ID,
    resource: 'graph',
    profile: 'm365.mailbox_remediation',
    expiresAt: clock + 3_600_000,
  });
  tokens.setGrant(GS_CUSTOMER_ID, 'google.mailbox_remediation', [
    GMAIL_MAIL_SCOPES.modify,
    'https://www.googleapis.com/auth/admin.directory.user.readonly',
  ]);
  gmailToken = (subject) =>
    tokens.issue({
      directoryId: GS_CUSTOMER_ID,
      resource: 'google',
      profile: 'google.mailbox_remediation',
      subject,
      expiresAt: clock + 3_600_000,
    });
});

afterEach(async () => {
  await sims.stop();
});

async function graph(path: string, init: RequestInit = {}, token = graphToken) {
  const url = path.startsWith('http') ? path : `${sims.baseUrl('graph')}${path}`;
  return fetch(url, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...(init.headers ?? {}),
    },
  });
}

async function gmail(subject: string, path: string) {
  return fetch(`${sims.baseUrl('gmail')}/gmail/v1/users/${encodeURIComponent(subject)}${path}`, {
    headers: { Authorization: `Bearer ${gmailToken(subject)}` },
  });
}

type DeltaPage = {
  value: Record<string, unknown>[];
  '@odata.nextLink'?: string;
  '@odata.deltaLink'?: string;
};

async function deltaAll(
  first: string,
  pageSize?: number,
): Promise<{ items: Record<string, unknown>[]; deltaLink: string; pages: number }> {
  const items: Record<string, unknown>[] = [];
  let link = first;
  let pages = 0;
  for (;;) {
    const response = await graph(link, {
      headers: pageSize ? { Prefer: `odata.maxpagesize=${pageSize}` } : {},
    });
    expect(response.status).toBe(200);
    const page = (await response.json()) as DeltaPage;
    pages += 1;
    items.push(...page.value);
    if (page['@odata.deltaLink']) return { items, deltaLink: page['@odata.deltaLink'], pages };
    const next = page['@odata.nextLink'];
    expect(next).toBeDefined();
    link = next ?? '';
  }
}

describe('Graph Inbox delta (D13)', () => {
  it('initial sync pages every current item, then reports only new and removed items', async () => {
    const delivered = [];
    for (let i = 0; i < 5; i += 1) {
      delivered.push(await sims.deliver({ user: `alex@${MS_DOMAIN}`, eml: syntheticEml() }));
    }
    const init = await deltaAll(`${INBOX_DELTA(ALEX)}?changeType=created`, 2);
    expect(init.pages).toBe(3);
    expect(init.items.map((i) => i.id)).toEqual(delivered.map((d) => d.messageId));
    expect(init.items[0]).toMatchObject({
      receivedDateTime: NOW.toISOString(),
      isDraft: false,
      internetMessageId: delivered[0]!.internetMessageId,
    });
    expect(init.deltaLink.startsWith(`${sims.baseUrl('graph')}/v1.0/users/`)).toBe(true);

    // Nothing new.
    let next = await deltaAll(init.deltaLink);
    expect(next.items).toEqual([]);

    const sixth = await sims.deliver({ user: ALEX, eml: syntheticEml() });
    const draft = await sims.deliver({ user: ALEX, eml: syntheticEml(), isDraft: true });
    expect((await fetch(`${sims.baseUrl('graph')}${INBOX_DELTA(ALEX)}`)).status).toBe(401);
    // Remove the first message (moved out of the Inbox).
    expect(removeMessage(sims.script, ALEX, delivered[0]!.messageId)).toBe(true);
    next = await deltaAll(next.deltaLink);
    expect(next.items.map((i) => [i.id, i.isDraft ?? null, i['@removed'] ?? null])).toEqual([
      [sixth.messageId, false, null],
      [draft.messageId, true, null],
      [delivered[0]!.messageId, null, { reason: 'deleted' }],
    ]);
  });

  it('answers 410 syncStateNotFound for expired cursors; a new initial sync works', async () => {
    await sims.deliver({ user: ALEX, eml: syntheticEml() });
    const init = await deltaAll(INBOX_DELTA(ALEX));
    expect(expireCursors(sims.script, ALEX)).toBe(true);
    const expired = await graph(init.deltaLink);
    expect(expired.status).toBe(410);
    expect(((await expired.json()) as { error: { code: string } }).error.code).toBe(
      'syncStateNotFound',
    );
    const again = await deltaAll(INBOX_DELTA(ALEX));
    expect(again.items).toHaveLength(1);
    expect((await graph(again.deltaLink)).status).toBe(200);
  });

  it('honours Prefer odata.maxpagesize, refuses foreign tokens and enforces Mail.ReadWrite', async () => {
    for (let i = 0; i < 3; i += 1) await sims.deliver({ user: ALEX, eml: syntheticEml() });
    const response = await graph(INBOX_DELTA(ALEX), { headers: { Prefer: 'odata.maxpagesize=1' } });
    expect(response.headers.get('preference-applied')).toBe('odata.maxpagesize=1');
    const page = (await response.json()) as DeltaPage;
    expect(page.value).toHaveLength(1);
    // The skip token of one user is refused for another.
    const skip = new URL(page['@odata.nextLink']!).searchParams.get('$skiptoken')!;
    expect((await graph(`${INBOX_DELTA(MS_USERS.blake)}?$skiptoken=${skip}`)).status).toBe(400);
    // `mailFolders/inbox` is accepted too.
    expect((await graph(`/v1.0/users/${ALEX}/mailFolders/inbox/messages/delta`)).status).toBe(200);
    tokens.revokePermission('Mail.ReadWrite', MS_TENANT_ID);
    const denied = await graph(INBOX_DELTA(ALEX));
    expect(denied.status).toBe(403);
    expect((await graph(`/v1.0/users?$top=1`)).status).toBe(200); // User.Read.All kept
  });

  it('serves $value as message/rfc822 and 404 for unknown or removed messages', async () => {
    const eml = syntheticEml({ minBytes: 200_000 });
    const delivered = await sims.deliver({ user: ALEX, eml });
    const response = await graph(`/v1.0/users/${ALEX}/messages/${delivered.messageId}/$value`);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('message/rfc822');
    expect(Number(response.headers.get('content-length'))).toBe(Buffer.byteLength(eml));
    expect(await response.text()).toBe(eml);
    expect((await graph(`/v1.0/users/${ALEX}/messages/AAMkUNKNOWN/$value`)).status).toBe(404);
    const calls = sims.script.calls({ simulator: 'graph', path: `/v1.0/users/${ALEX}/messages/` });
    expect(calls.map((c) => c.status)).toEqual([200, 404]);
  });
});

describe('Graph subscriptions (D13)', () => {
  const body = (overrides: Record<string, unknown> = {}) => ({
    changeType: 'created',
    notificationUrl: `${receiverUrl}/notify`,
    lifecycleNotificationUrl: `${receiverUrl}/notify/lifecycle`,
    resource: `users/${ALEX}/mailFolders('inbox')/messages`,
    expirationDateTime: new Date(NOW.getTime() + 4000 * 60_000).toISOString(),
    clientState: 'EXAMPLE-client-state-value',
    latestSupportedTlsVersion: 'v1_2',
    ...overrides,
  });

  async function create(overrides: Record<string, unknown> = {}) {
    return graph('/v1.0/subscriptions', {
      method: 'POST',
      body: JSON.stringify(body(overrides)),
    });
  }

  it('validates both callback URLs with the handshake, then pushes notifications on delivery', async () => {
    const response = await create();
    expect(response.status).toBe(201);
    const subscription = (await response.json()) as { id: string; expirationDateTime: string };
    const handshakes = received.filter((r) => r.query.startsWith('?validationToken='));
    expect(handshakes.map((r) => r.path)).toEqual(['/notify', '/notify/lifecycle']);
    expect(handshakes[0]?.contentType).toContain('text/plain');
    expect(sims.script.notifications.map((n) => [n.kind, n.ok])).toEqual([
      ['validation', true],
      ['validation', true],
    ]);

    received.length = 0;
    const delivered = await sims.deliver({ user: `alex@${MS_DOMAIN}`, eml: syntheticEml() });
    expect(delivered.notifications.map((n) => [n.kind, n.status])).toEqual([['change', 202]]);
    expect(received).toHaveLength(1);
    const payload = JSON.parse(received[0]!.body) as { value: Record<string, unknown>[] };
    expect(payload.value[0]).toMatchObject({
      subscriptionId: subscription.id,
      changeType: 'created',
      clientState: 'EXAMPLE-client-state-value',
      tenantId: MS_TENANT_ID,
      resource: `Users/${ALEX}/Messages/${delivered.messageId}`,
    });
    // Another user's delivery notifies nobody; drafts are not notified.
    expect(
      (await sims.deliver({ user: MS_USERS.blake, eml: syntheticEml() })).notifications,
    ).toEqual([]);
    expect(
      (await sims.deliver({ user: ALEX, eml: syntheticEml(), isDraft: true })).notifications,
    ).toEqual([]);

    // Renew, push a lifecycle event, delete (404 afterwards).
    const renewed = await graph(`/v1.0/subscriptions/${subscription.id}`, {
      method: 'PATCH',
      body: JSON.stringify({
        expirationDateTime: new Date(NOW.getTime() + 4200 * 60_000).toISOString(),
      }),
    });
    expect(renewed.status).toBe(200);
    const lifecycle = await pushLifecycle(sims.script, subscription.id, 'reauthorizationRequired');
    expect(lifecycle).toMatchObject({ kind: 'lifecycle', status: 202, ok: true });
    expect(JSON.parse(received.at(-1)!.body)).toMatchObject({
      value: [{ lifecycleEvent: 'reauthorizationRequired', subscriptionId: subscription.id }],
    });
    expect(
      (await graph(`/v1.0/subscriptions/${subscription.id}`, { method: 'DELETE' })).status,
    ).toBe(204);
    expect(
      (await graph(`/v1.0/subscriptions/${subscription.id}`, { method: 'DELETE' })).status,
    ).toBe(404);
  });

  it('refuses the subscription when the receiver does not echo the token exactly', async () => {
    echo = (token, _req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(`${token}x`);
    };
    expect((await create()).status).toBe(400);
    echo = (token, _req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(token);
    };
    expect((await create()).status).toBe(400);
    expect(sims.script.notifications.every((n) => n.kind === 'validation' && !n.ok)).toBe(true);
    expect(sims.script.dataset.microsoft?.directories[0]?.subscriptions ?? []).toEqual([]);
  });

  it('validates the body: expiry ≤ 4230 minutes, created only, Inbox resource, local callbacks', async () => {
    const tooLong = new Date(NOW.getTime() + 4231 * 60_000).toISOString();
    expect((await create({ expirationDateTime: tooLong })).status).toBe(400);
    expect((await create({ changeType: 'updated' })).status).toBe(400);
    expect((await create({ resource: `users/${ALEX}/messages` })).status).toBe(400);
    expect((await create({ notificationUrl: 'https://receiver.example.com/notify' })).status).toBe(
      400,
    );
    expect((await create({ resource: `users/nobody/mailFolders('inbox')/messages` })).status).toBe(
      404,
    );
    expect(received).toHaveLength(0);
    const patch = await graph('/v1.0/subscriptions/unknown', {
      method: 'PATCH',
      body: JSON.stringify({ expirationDateTime: tooLong }),
    });
    expect(patch.status).toBe(404);
  });

  it('expired subscriptions receive no notifications; scripted lifecycle removal deletes', async () => {
    const created = (await (await create()).json()) as { id: string };
    await pushLifecycle(sims.script, created.id, 'subscriptionRemoved');
    expect(sims.script.dataset.microsoft?.directories[0]?.subscriptions).toEqual([]);
    const again = (await (await create()).json()) as { id: string };
    expect(again.id).not.toBe(created.id);
    clock += 4100 * 60_000;
    expect((await sims.deliver({ user: ALEX, eml: syntheticEml() })).notifications).toEqual([]);
  });

  it('accepts only local callback targets', () => {
    for (const ok of [
      'http://127.0.0.1:3000/x',
      'http://api:3000/api/v1/provider-notifications/graph',
      'https://gateway.test/n',
      'http://10.1.2.3/n',
      'http://[::1]:80/n',
    ]) {
      expect(isLocalCallbackTarget(new URL(ok)), ok).toBe(true);
    }
    for (const bad of [
      'https://graph.example.com/n',
      'https://203.0.113.5/n',
      'ftp://127.0.0.1/n',
      'http://user:pw@127.0.0.1/n',
      'http://[2001:db8::1]/n',
    ]) {
      expect(isLocalCallbackTarget(new URL(bad)), bad).toBe(false);
    }
  });
});

describe('Gmail mailbox reads (D13)', () => {
  const alex = `alex@${GS_DOMAIN}`;

  it('profile, history paging with the label filter and 404 for expired start ids', async () => {
    const profile = (await (await gmail(alex, '/profile')).json()) as { historyId: string };
    const start = profile.historyId;
    const a = await sims.deliver({ user: alex, eml: syntheticEml() });
    const spam = await sims.deliver({ user: alex, eml: syntheticEml(), labelIds: ['SPAM'] });
    const b = await sims.deliver({ user: GS_USERS.alex, eml: syntheticEml() });
    expect(spam.provider).toBe('google');
    const page1 = (await (
      await gmail(
        alex,
        `/history?startHistoryId=${start}&historyTypes=messageAdded&labelId=INBOX&maxResults=1`,
      )
    ).json()) as {
      history: { messagesAdded: { message: { id: string } }[] }[];
      nextPageToken: string;
      historyId: string;
    };
    expect(page1.history.map((h) => h.messagesAdded[0]!.message.id)).toEqual([a.messageId]);
    expect(page1.historyId).toBe(b.historyId);
    const page2 = (await (
      await gmail(
        alex,
        `/history?startHistoryId=${start}&historyTypes=messageAdded&labelId=INBOX&maxResults=1&pageToken=${page1.nextPageToken}`,
      )
    ).json()) as {
      history: { messagesAdded: { message: { id: string; labelIds: string[] } }[] }[];
      nextPageToken?: string;
    };
    expect(page2.history[0]!.messagesAdded[0]!.message).toMatchObject({
      id: b.messageId,
      labelIds: ['INBOX', 'UNREAD'],
    });
    expect(page2.nextPageToken).toBeUndefined();
    expireCursors(sims.script, alex);
    expect((await gmail(alex, `/history?startHistoryId=${start}`)).status).toBe(404);
    const fresh = (await (await gmail(alex, '/profile')).json()) as { historyId: string };
    expect((await gmail(alex, `/history?startHistoryId=${fresh.historyId}`)).status).toBe(200);
  });

  it('metadata with the requested headers; raw as base64url in Gmail field order, streamed', async () => {
    const eml = syntheticEml({
      messageId: 'gmail-raw-1@mail.example',
      body: 'He wrote "raw": "AAAA" and \\ backslashes',
      minBytes: 300_000,
    });
    const delivered = await sims.deliver({ user: alex, eml });
    const metadata = (await (
      await gmail(
        alex,
        `/messages/${delivered.messageId}?format=metadata&metadataHeaders=Message-ID`,
      )
    ).json()) as Record<string, unknown> & { payload: { headers: unknown[] } };
    expect(metadata.payload.headers).toEqual([
      { name: 'Message-ID', value: '<gmail-raw-1@mail.example>' },
    ]);
    expect(metadata.internalDate).toBe(String(NOW.getTime()));
    expect(metadata.sizeEstimate).toBe(Buffer.byteLength(eml));
    const response = await gmail(alex, `/messages/${delivered.messageId}?format=raw`);
    expect(response.headers.get('content-length')).toBeNull(); // chunked
    const text = await response.text();
    expect(Object.keys(JSON.parse(text) as object)).toEqual([
      'id',
      'threadId',
      'labelIds',
      'snippet',
      'sizeEstimate',
      'raw',
      'historyId',
      'internalDate',
    ]);
    const raw = (JSON.parse(text) as { raw: string }).raw;
    expect(raw).toMatch(/^[A-Za-z0-9_-]+=*$/);
    expect(Buffer.from(raw, 'base64url').toString('utf8')).toBe(eml);
    expect((await gmail(alex, `/messages/${delivered.messageId}?format=full`)).status).toBe(400);
  });

  it('requires the mailbox owner as subject and a Gmail read scope', async () => {
    const response = await fetch(
      `${sims.baseUrl('gmail')}/gmail/v1/users/${encodeURIComponent(alex)}/profile`,
      { headers: { Authorization: `Bearer ${gmailToken(`blake@${GS_DOMAIN}`)}` } },
    );
    expect(response.status).toBe(403);
    tokens.revokePermission(GMAIL_MAIL_SCOPES.modify, GS_CUSTOMER_ID);
    expect((await gmail(alex, '/profile')).status).toBe(403);
  });

  it('Directory users list aliases and suspension', async () => {
    const token = gmailToken(`ato-admin@${GS_DOMAIN}`);
    const response = await fetch(
      `${sims.baseUrl('google-admin')}/admin/directory/v1/users?customer=my_customer&projection=basic&maxResults=500`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    const users = ((await response.json()) as { users: Record<string, unknown>[] }).users;
    expect(users.find((u) => u.id === GS_USERS.erin)).toMatchObject({
      aliases: [`erin.alias@${GS_DOMAIN}`],
      suspended: false,
    });
    expect(users.find((u) => u.id === GS_USERS.casey)).toMatchObject({ suspended: true });
  });
});

describe('standalone admin API additions (D13)', () => {
  let running: Awaited<ReturnType<typeof runStandalone>>;
  let data: string;
  let admin: string;

  beforeAll(async () => {
    running = await runStandalone({
      IDP_SIM_HOST: '127.0.0.1',
      IDP_SIM_PORT: '0',
      IDP_SIM_ADMIN_PORT: '0',
      IDP_SIM_QUIET: 'true',
    });
    data = `http://127.0.0.1:${running.dataPort}`;
    admin = `http://127.0.0.1:${running.adminPort}`;
  });
  afterAll(async () => {
    await running.stop();
  });

  const call = (method: string, path: string, body?: unknown) =>
    fetch(`${admin}${path}`, {
      method,
      ...(body === undefined
        ? {}
        : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
    });
  const stackGraph = (path: string, init: RequestInit = {}) =>
    fetch(`${data}/graph${path}`, {
      ...init,
      headers: {
        Authorization: 'Bearer EXAMPLE-stack-token',
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      },
    });

  it('delivers, lists subscriptions without client state, scripts failures per family', async () => {
    await call('POST', '/admin/dataset', {
      microsoft: { directories: [microsoftDirectory(new Date())] },
      google: { customers: [googleCustomer(new Date())] },
    });
    const created = await stackGraph('/v1.0/subscriptions', {
      method: 'POST',
      body: JSON.stringify({
        changeType: 'created',
        notificationUrl: `${receiverUrl}/stack`,
        resource: `users/${ALEX}/mailFolders('inbox')/messages`,
        expirationDateTime: new Date(Date.now() + 60 * 60_000).toISOString(),
        clientState: 'EXAMPLE-stack-client-state',
      }),
    });
    expect(created.status).toBe(201);
    const delivered = await call(
      'POST',
      `/admin/mailboxes/${encodeURIComponent(`alex@${MS_DOMAIN}`)}/messages`,
      {
        eml: syntheticEml(),
      },
    );
    expect(delivered.status).toBe(201);
    const result = (await delivered.json()) as {
      messageId: string;
      notifications: { status: number }[];
    };
    expect(result.notifications.map((n) => n.status)).toEqual([202]);
    const listed = (await (await call('GET', '/admin/subscriptions')).json()) as {
      subscriptions: Record<string, unknown>[];
    };
    expect(listed.subscriptions[0]).toMatchObject({ hasClientState: true, userId: ALEX });
    expect(JSON.stringify(listed)).not.toContain('EXAMPLE-stack-client-state');
    const notifications = (await (await call('GET', '/admin/notifications')).json()) as {
      notifications: { kind: string }[];
    };
    expect(notifications.notifications.map((n) => n.kind)).toEqual(['validation', 'change']);
    const subscriptionId = listed.subscriptions[0]!.id as string;
    expect(
      (await call('POST', `/admin/subscriptions/${subscriptionId}/lifecycle`, { event: 'nope' }))
        .status,
    ).toBe(400);
    expect(
      (await call('POST', `/admin/subscriptions/${subscriptionId}/lifecycle`, { event: 'missed' }))
        .status,
    ).toBe(200); // no lifecycle URL: recorded with status 0

    expect(
      (await call('POST', '/admin/mailboxes/nobody@nowhere.example/messages', { eml: 'x' })).status,
    ).toBe(404);
    expect((await call('POST', `/admin/mailboxes/${ALEX}/messages`, {})).status).toBe(400);
    expect(
      (await call('DELETE', `/admin/mailboxes/${ALEX}/messages/${result.messageId}`)).status,
    ).toBe(204);
    expect((await call('POST', `/admin/mailboxes/${ALEX}/expire-cursors`)).status).toBe(204);

    expect(
      (await call('POST', '/admin/inject', { family: 'graph', status: 429, retryAfter: '2' }))
        .status,
    ).toBe(204);
    const throttled = await stackGraph(`/v1.0/users/${ALEX}/mailFolders('inbox')/messages/delta`);
    expect(throttled.status).toBe(429);
    expect(throttled.headers.get('retry-after')).toBe('2');
    expect(
      (
        await call('POST', '/admin/inject', {
          family: 'google_directory',
          status: 503,
          retryAfter: '5',
        })
      ).status,
    ).toBe(204);
    const directory = await fetch(
      `${data}/google-admin/admin/directory/v1/users?customer=my_customer`,
      { headers: { Authorization: 'Bearer EXAMPLE-stack-token' } },
    );
    expect(directory.status).toBe(503);
    expect((await call('POST', '/admin/inject', { family: 'unknown', status: 429 })).status).toBe(
      400,
    );
    const calls = (await (
      await call('GET', '/admin/calls?simulator=graph&path=/v1.0/users/')
    ).json()) as { calls: { path: string; status: number }[] };
    expect(calls.calls.map((c) => c.status)).toEqual([429]);
  });
});
