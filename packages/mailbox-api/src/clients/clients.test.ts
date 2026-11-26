import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  expireCursors,
  GS_ADMIN_EMAIL,
  GS_DOMAIN,
  GS_USERS,
  MS_DOMAIN,
  MS_USERS,
  googleCustomer,
  microsoftDirectory,
  removeMessage,
  syntheticEml,
  type MsUser,
} from '@email-gateway/idp-adapters/testing';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { MailboxApiError } from '../errors';
import {
  collectStream,
  createMailboxTestbed,
  TEST_API_CONNECTION_ID,
  type MailboxTestbed,
} from '../testing';

const ALEX = MS_USERS.alex;
const GMAIL_ALEX = `alex@${GS_DOMAIN}`;
const signal = () => new AbortController().signal;

async function failure(promise: Promise<unknown>): Promise<MailboxApiError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(MailboxApiError);
    return error as MailboxApiError;
  }
  throw new Error('expected a MailboxApiError');
}

let receiver: Server;
let receiverUrl: string;
beforeAll(async () => {
  receiver = createServer((req, res) => {
    const token = new URL(req.url ?? '/', 'http://r.invalid').searchParams.get('validationToken');
    req.resume();
    req.on('end', () => {
      if (token !== null) {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(token);
      } else {
        res.writeHead(202);
        res.end();
      }
    });
  });
  await new Promise<void>((resolve) => receiver.listen(0, '127.0.0.1', resolve));
  receiverUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}`;
});
afterAll(async () => {
  receiver.closeAllConnections();
  await new Promise<void>((resolve) => receiver.close(() => resolve()));
});

let tb: MailboxTestbed;
beforeEach(async () => {
  tb = await createMailboxTestbed();
});
afterEach(async () => {
  await tb.stop();
});

/** Pages the Inbox delta to its delta link. */
async function deltaRound(userId: string, link?: string) {
  const messages = [];
  const removed = [];
  let pages = 0;
  let cursor = link;
  for (;;) {
    const page = await tb.graph.inboxDelta(userId, cursor, signal());
    pages += 1;
    messages.push(...page.messages);
    removed.push(...page.removed);
    if (page.deltaLink) return { messages, removed, deltaLink: page.deltaLink, pages };
    cursor = page.nextLink ?? undefined;
  }
}

describe('GraphMailClient', () => {
  it('lists users with proxy addresses and follows same-origin next links', async () => {
    const many = (now: Date) => {
      const directory = microsoftDirectory(now);
      const extra: MsUser[] = Array.from({ length: 1000 }, (_, i) => ({
        id: `cccccccc-0000-4000-8000-${String(i).padStart(12, '0')}`,
        userPrincipalName: `user${i}@${MS_DOMAIN}`,
        mail: `user${i}@${MS_DOMAIN}`,
        displayName: `User ${i}`,
        accountEnabled: i % 2 === 0,
        onPremisesSyncEnabled: null,
        proxyAddresses: [`SMTP:user${i}@${MS_DOMAIN}`, `smtp:alias${i}@${MS_DOMAIN}`],
      }));
      directory.users.push(...extra);
      return { microsoft: { directories: [directory] } };
    };
    await tb.stop();
    tb = await createMailboxTestbed({ dataset: many });
    const first = await tb.graph.listUsers(undefined, signal());
    expect(first.users).toHaveLength(999);
    expect(first.nextLink).not.toBeNull();
    const erin = first.users.find((u) => u.id === MS_USERS.erin);
    expect(erin).toEqual({
      id: MS_USERS.erin,
      mail: null,
      userPrincipalName: `erin@${MS_DOMAIN}`,
      proxyAddresses: [`SMTP:erin@${MS_DOMAIN}`, `smtp:erin.alias@${MS_DOMAIN}`],
      accountEnabled: true,
    });
    const second = await tb.graph.listUsers(first.nextLink!, signal());
    expect(second.users).toHaveLength(8);
    expect(second.nextLink).toBeNull();
    const query = tb.sims.script.calls({ simulator: 'graph', path: '/v1.0/users' })[0]?.query;
    expect(query).toContain('$select=id,mail,userPrincipalName,proxyAddresses,accountEnabled');
    expect(query).toContain('$top=999');
  });

  it('refuses a foreign next link without calling it', async () => {
    tb.sims.script.inject({
      simulator: 'graph',
      path: '/v1.0/users',
      status: 200,
      rawBody: JSON.stringify({
        value: [],
        '@odata.nextLink': 'https://attacker.example.invalid/v1.0/users?$skiptoken=x',
      }),
    });
    expect((await failure(tb.graph.listUsers(undefined, signal()))).code).toBe('blocked_host');
    expect(
      (await failure(tb.graph.listUsers('https://attacker.example.invalid/v1.0/users', signal())))
        .code,
    ).toBe('blocked_host');
    expect(tb.sims.script.calls({ simulator: 'graph' })).toHaveLength(1);
  });

  it('initializes the delta (50 per page), continues with new items and @removed, expires', async () => {
    const delivered = [];
    for (let i = 0; i < 60; i += 1) {
      delivered.push(await tb.sims.deliver({ user: ALEX, eml: syntheticEml() }));
    }
    const init = await deltaRound(ALEX);
    expect(init.pages).toBe(2);
    expect(init.messages).toHaveLength(60);
    expect(init.messages[0]).toEqual({
      id: delivered[0]!.messageId,
      internetMessageId: delivered[0]!.internetMessageId,
      receivedDateTime: tb.clock.now(),
      isDraft: false,
    });
    const first = tb.sims.script.calls({ simulator: 'graph', path: `/v1.0/users/${ALEX}/` })[0];
    expect(first?.query).toContain('changeType=created');
    expect(first?.query).toContain('$select=id,internetMessageId,receivedDateTime,isDraft');

    tb.clock.advance(60_000);
    const fresh = await tb.sims.deliver({ user: `alex@${MS_DOMAIN}`, eml: syntheticEml() });
    removeMessage(tb.sims.script, ALEX, delivered[1]!.messageId);
    const next = await deltaRound(ALEX, init.deltaLink);
    expect(next.messages.map((m) => m.id)).toEqual([fresh.messageId]);
    expect(next.messages[0]?.receivedDateTime).toEqual(tb.clock.now());
    expect(next.removed).toEqual([delivered[1]!.messageId]);

    expireCursors(tb.sims.script, ALEX);
    const expired = await failure(tb.graph.inboxDelta(ALEX, next.deltaLink, signal()));
    expect(expired.code).toBe('cursor_expired');
    expect(expired.retryable).toBe(false);
    expect(expired.status).toBe(410);
    expect(expired.providerCode).toBe('syncStateNotFound');
  });

  it('maps a scripted 410 syncStateNotFound to cursor_expired and checks returned links', async () => {
    tb.sims.script.inject({
      simulator: 'graph',
      path: /\/messages\/delta$/,
      status: 410,
      code: 'syncStateNotFound',
    });
    expect((await failure(tb.graph.inboxDelta(ALEX, undefined, signal()))).code).toBe(
      'cursor_expired',
    );
    tb.sims.script.inject({
      simulator: 'graph',
      path: /\/messages\/delta$/,
      status: 200,
      rawBody: JSON.stringify({ value: [] }),
    });
    expect((await failure(tb.graph.inboxDelta(ALEX, undefined, signal()))).code).toBe(
      'unexpected_response',
    );
  });

  it('streams MIME content and enforces the byte cap', async () => {
    const eml = syntheticEml({ minBytes: 300_000 });
    const delivered = await tb.sims.deliver({ user: ALEX, eml });
    const stream = await tb.graph.messageMime(ALEX, delivered.messageId, 1_000_000, signal());
    expect(stream.contentLength).toBe(Buffer.byteLength(eml));
    expect((await collectStream(stream.body)).toString('utf8')).toBe(eml);
    const tooLarge = await failure(
      tb.graph.messageMime(ALEX, delivered.messageId, 100_000, signal()),
    );
    expect(tooLarge.code).toBe('response_too_large');
    expect((await failure(tb.graph.messageMime(ALEX, 'AAMkGONE', 1_000_000, signal()))).code).toBe(
      'not_found',
    );
  });

  it('creates, renews and deletes subscriptions with the exact D9 body (handshake passes)', async () => {
    const expiry = new Date(tb.clock.ms() + 4230 * 60_000);
    const subscription = await tb.graph.createSubscription(
      {
        userId: ALEX,
        notificationUrl: `${receiverUrl}/api/v1/provider-notifications/graph`,
        lifecycleNotificationUrl: `${receiverUrl}/api/v1/provider-notifications/graph/lifecycle`,
        expirationDateTime: expiry,
        clientState: 'EXAMPLE-client-state',
      },
      signal(),
    );
    expect(subscription.expirationDateTime).toEqual(expiry);
    expect(Object.keys(subscription).sort()).toEqual(['expirationDateTime', 'id']);
    const stored = tb.sims.script.dataset.microsoft?.directories[0]?.subscriptions?.[0];
    expect(stored).toMatchObject({
      resource: `users/${ALEX}/mailFolders('inbox')/messages`,
      changeType: 'created',
      clientState: 'EXAMPLE-client-state',
      latestSupportedTlsVersion: 'v1_2',
    });
    expect(tb.sims.script.notifications.map((n) => [n.kind, n.ok])).toEqual([
      ['validation', true],
      ['validation', true],
    ]);
    const delivered = await tb.sims.deliver({ user: ALEX, eml: syntheticEml() });
    expect(delivered.notifications.map((n) => n.status)).toEqual([202]);
    const renewed = await tb.graph.renewSubscription(
      subscription.id,
      new Date(tb.clock.ms() + 3000 * 60_000),
      signal(),
    );
    expect(renewed.id).toBe(subscription.id);
    expect(await tb.graph.deleteSubscription(subscription.id, signal())).toBe('deleted');
    expect(await tb.graph.deleteSubscription(subscription.id, signal())).toBe('not_found');
    expect(
      (
        await failure(
          tb.graph.createSubscription(
            {
              userId: ALEX,
              notificationUrl: `${receiverUrl}/n`,
              lifecycleNotificationUrl: `${receiverUrl}/n/lifecycle`,
              expirationDateTime: new Date(tb.clock.ms() + 5000 * 60_000),
              clientState: 'EXAMPLE-client-state',
            },
            signal(),
          ),
        )
      ).code,
    ).toBe('bad_request');
  });

  it('reports missing Mail.ReadWrite as missing_permission', async () => {
    await tb.stop();
    tb = await createMailboxTestbed({ microsoftPermissions: ['User.Read.All'] });
    expect((await failure(tb.graph.inboxDelta(ALEX, undefined, signal()))).code).toBe(
      'missing_permission',
    );
    expect((await tb.graph.listUsers(undefined, signal())).users.length).toBeGreaterThan(0);
  });
});

describe('GmailClient', () => {
  it('reads the profile and pages INBOX history (500 per page); 404 → cursor_expired', async () => {
    const start = (await tb.gmail.profile(GMAIL_ALEX, signal())).historyId;
    const ids: string[] = [];
    for (let i = 0; i < 501; i += 1) {
      ids.push((await tb.sims.deliver({ user: GMAIL_ALEX, eml: syntheticEml() })).messageId);
    }
    await tb.sims.deliver({ user: GMAIL_ALEX, eml: syntheticEml(), labelIds: ['SPAM'] });
    const page1 = await tb.gmail.history(GMAIL_ALEX, start, undefined, signal());
    expect(page1.added).toHaveLength(500);
    expect(page1.added[0]).toEqual({
      id: ids[0],
      threadId: ids[0],
      labelIds: ['INBOX', 'UNREAD'],
      inInbox: true,
    });
    expect(page1.nextPageToken).not.toBeNull();
    // The page's highest record id: a resumable start id once the page is processed.
    expect(page1.lastRecordId).toBe(String(Number(start) + 500));
    const page2 = await tb.gmail.history(GMAIL_ALEX, start, page1.nextPageToken!, signal());
    expect(page2.added.map((a) => a.id)).toEqual([ids[500]]);
    expect(page2.nextPageToken).toBeNull();
    expect(page2.historyId).toBe(String(Number(start) + 502));
    expect(page2.lastRecordId).toBe(String(Number(start) + 501));
    const query = tb.sims.script
      .calls({ simulator: 'gmail', path: '/gmail/v1/users/' })
      .at(-1)?.query;
    expect(query).toContain('historyTypes=messageAdded');
    expect(query).toContain('labelId=INBOX');
    expect(query).toContain('maxResults=500');
    expireCursors(tb.sims.script, GMAIL_ALEX);
    const expired = await failure(tb.gmail.history(GMAIL_ALEX, start, undefined, signal()));
    expect(expired.code).toBe('cursor_expired');
    expect(expired.status).toBe(404);
    expect((await failure(tb.gmail.history(GMAIL_ALEX, 'abc', undefined, signal()))).code).toBe(
      'bad_request',
    );
  });

  it('reads metadata first, then the raw message through the extractor (cap enforced)', async () => {
    const eml = syntheticEml({
      messageId: 'gmail-copy-1@mail.example',
      body: 'text with "raw": "QUFB" inside',
      minBytes: 400_000,
    });
    const delivered = await tb.sims.deliver({ user: GMAIL_ALEX, eml });
    const metadata = await tb.gmail.messageMetadata(GMAIL_ALEX, delivered.messageId, signal());
    expect(metadata).toEqual({
      id: delivered.messageId,
      threadId: delivered.messageId,
      labelIds: ['INBOX', 'UNREAD'],
      messageId: '<gmail-copy-1@mail.example>',
      internalDate: tb.clock.now(),
      sizeEstimate: Buffer.byteLength(eml),
      historyId: delivered.historyId,
    });
    const raw = await tb.gmail.messageRaw(GMAIL_ALEX, delivered.messageId, 1_000_000, signal());
    expect((await collectStream(raw.body)).toString('utf8')).toBe(eml);
    const capped = await tb.gmail.messageRaw(GMAIL_ALEX, delivered.messageId, 100_000, signal());
    const error = await failure(collectStream(capped.body));
    expect(error.code).toBe('response_too_large');
    // Every Gmail call impersonated the mailbox.
    expect(
      tb.sims.script
        .calls({ simulator: 'gmail' })
        .every((c) => c.subject === GMAIL_ALEX && c.status === 200),
    ).toBe(true);
  });
});

describe('GoogleDirectoryClient', () => {
  it('lists users with aliases, suspension and archive flags as the delegated admin', async () => {
    const page = await tb.directory.listUsers(undefined, signal());
    expect(page.nextPageToken).toBeNull();
    expect(page.users.find((u) => u.id === GS_USERS.erin)).toEqual({
      id: GS_USERS.erin,
      primaryEmail: `erin@${GS_DOMAIN}`,
      aliases: [`erin.alias@${GS_DOMAIN}`],
      suspended: false,
      archived: false,
    });
    expect(page.users.find((u) => u.id === GS_USERS.casey)?.suspended).toBe(true);
    const call = tb.sims.script.calls({ simulator: 'google-admin' })[0];
    expect(call?.subject).toBe(GS_ADMIN_EMAIL);
    expect(call?.query).toBe('?customer=my_customer&projection=basic&maxResults=500');
  });

  it('pages with nextPageToken', async () => {
    await tb.stop();
    tb = await createMailboxTestbed({
      dataset: (now) => {
        const customer = googleCustomer(now);
        for (let i = 0; i < 600; i += 1) {
          customer.users.push({
            id: `2000000000000000${String(i).padStart(5, '0')}`,
            primaryEmail: `user${i}@${GS_DOMAIN}`,
            aliases: [],
            suspended: false,
            orgUnitPath: '/Staff',
            changePasswordAtNextLogin: false,
            isAdmin: false,
          });
        }
        return { google: { customers: [customer] } };
      },
    });
    const first = await tb.directory.listUsers(undefined, signal());
    expect(first.users).toHaveLength(500);
    const second = await tb.directory.listUsers(first.nextPageToken!, signal());
    expect(second.users).toHaveLength(109);
    expect(second.nextPageToken).toBeNull();
  });
});

describe('call discipline: tokens, budgets, throttling, redaction (D9, D10.6, D10.7)', () => {
  it('drops the token on 401 and retries once', async () => {
    await tb.graph.listUsers(undefined, signal());
    tb.sims.tokens.invalidate(tb.graphToken.peek()!);
    await tb.graph.listUsers(undefined, signal());
    expect(tb.graphToken.invalidations).toBe(1);
    expect(tb.graphToken.issued).toBe(2);
  });

  it('takes the per-connection budget per family before each call; exhausted → rate_budget', async () => {
    await tb.graph.listUsers(undefined, signal());
    await tb.gmail.profile(GMAIL_ALEX, signal());
    await tb.directory.listUsers(undefined, signal());
    expect(tb.budget.takes).toEqual([
      { integrationId: `mbx:${TEST_API_CONNECTION_ID}`, family: 'graph' },
      { integrationId: `mbx:${TEST_API_CONNECTION_ID}`, family: 'gmail' },
      { integrationId: `mbx:${TEST_API_CONNECTION_ID}`, family: 'google_directory' },
    ]);
    tb.budget.exhausted.add('gmail');
    const calls = tb.sims.script.calls().length;
    const error = await failure(tb.gmail.profile(GMAIL_ALEX, signal()));
    expect(error.code).toBe('rate_budget');
    expect(error.retryable).toBe(true);
    expect(tb.sims.script.calls()).toHaveLength(calls);
    // Other families are unaffected.
    await tb.graph.listUsers(undefined, signal());
  });

  it('429 Retry-After pauses the connection-family (capped at 600 s) for later calls', async () => {
    tb.sims.script.inject({
      simulator: 'graph',
      path: '/v1.0/users',
      status: 429,
      retryAfter: '2',
    });
    const throttled = await failure(tb.graph.listUsers(undefined, signal()));
    expect(throttled).toMatchObject({ code: 'throttled', status: 429, retryAfterMs: 2000 });
    expect(tb.throttle.events).toEqual([
      {
        apiConnectionPublicId: TEST_API_CONNECTION_ID,
        family: 'graph',
        retryAfterMs: 2000,
        status: 429,
        code: 'throttled',
      },
    ]);
    const calls = tb.sims.script.calls().length;
    const paused = await failure(tb.graph.inboxDelta(ALEX, undefined, signal()));
    expect(paused).toMatchObject({ code: 'throttle_paused', retryable: true, retryAfterMs: 2000 });
    expect(tb.sims.script.calls()).toHaveLength(calls); // no provider call while paused
    // Gmail is another family: not paused.
    await tb.gmail.profile(GMAIL_ALEX, signal());
    tb.clock.advance(2_000);
    await tb.graph.listUsers(undefined, signal());

    tb.sims.script.inject({
      simulator: 'gmail',
      path: '/gmail/',
      status: 429,
      retryAfter: '86400',
    });
    expect((await failure(tb.gmail.profile(GMAIL_ALEX, signal()))).retryAfterMs).toBe(600_000);
    expect(tb.throttle.events.at(-1)?.retryAfterMs).toBe(600_000);
  });

  it('503 pauses only with Retry-After; Google rate-limit 403 pauses as throttled', async () => {
    tb.sims.script.inject({ simulator: 'google-admin', path: '/admin/directory/', status: 503 });
    const plain = await failure(tb.directory.listUsers(undefined, signal()));
    expect(plain.code).toBe('provider_unavailable');
    expect(tb.throttle.events).toEqual([]);
    tb.sims.script.inject({
      simulator: 'google-admin',
      path: '/admin/directory/',
      status: 503,
      retryAfter: '5',
    });
    await failure(tb.directory.listUsers(undefined, signal()));
    expect(tb.throttle.events.at(-1)).toMatchObject({
      family: 'google_directory',
      status: 503,
      code: 'provider_unavailable',
      retryAfterMs: 5000,
    });
    tb.sims.script.inject({
      simulator: 'gmail',
      path: '/gmail/',
      status: 403,
      reason: 'userRateLimitExceeded',
    });
    expect((await failure(tb.gmail.profile(GMAIL_ALEX, signal()))).code).toBe('throttled');
    expect(tb.throttle.events.at(-1)).toMatchObject({ family: 'gmail', status: 403 });
  });

  it('never puts a token, delta link, address or body into errors or log lines', async () => {
    await tb.sims.deliver({ user: ALEX, eml: syntheticEml({ subject: 'EXAMPLE-subject-marker' }) });
    const init = await deltaRound(ALEX);
    const errors: unknown[] = [];
    for (const status of [400, 401, 403, 404, 410, 429, 500, 503]) {
      tb.sims.script.inject({
        simulator: 'graph',
        path: /\/messages\/delta$/,
        status,
        times: status === 401 ? 2 : 1,
        retryAfter: '1',
      });
      try {
        await tb.graph.inboxDelta(ALEX, init.deltaLink, signal());
      } catch (error) {
        errors.push(error);
      }
      tb.clock.advance(5_000);
    }
    expect(errors).toHaveLength(8);
    const token = tb.graphToken.peek() ?? '';
    const deltaToken = new URL(init.deltaLink).searchParams.get('$deltatoken')!;
    const dump = [
      tb.logger.text(),
      ...errors.map((e) => JSON.stringify(e)),
      ...errors.map((e) => (e instanceof Error ? `${e.message} ${e.stack ?? ''}` : '')),
    ].join('\n');
    for (const secret of [
      token,
      'EXAMPLE-sim-token',
      deltaToken,
      'Bearer',
      ALEX,
      'EXAMPLE-subject-marker',
    ]) {
      expect(dump, secret).not.toContain(secret);
    }
  });
});
