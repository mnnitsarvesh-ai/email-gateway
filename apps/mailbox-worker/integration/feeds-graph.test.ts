import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { GetObjectCommand } from '@aws-sdk/client-s3';
import {
  microsoftDirectory,
  MS_DOMAIN,
  MS_TENANT_ID,
  MS_USERS,
  startSimulators,
  syntheticEml,
  type MsDirectory,
  type RunningSimulators,
} from '@email-gateway/idp-adapters/testing';
import { clientStateHash, deriveClientState, ingestKeyForCopy } from '@email-gateway/mailbox-api';
import { M365_MAILBOX_REMEDIATION_PROFILE } from '@email-gateway/provider-integrations';
import type { MailboxComponents } from '../src/components';
import { loadOrgApiModeState } from '../src/domain/api-mode-state';
import { loadConnectionContext } from '../src/domain/connections';
import { MAILBOX_SELECT } from '../src/feeds/feed-runner';
import { RedisRateBudget, RedisThrottleGate } from '../src/runtime/redis-stores';
import {
  Clock,
  Fixtures,
  SimAccessTokens,
  type TestConnection,
  type TestOrg,
} from './support/harness';
import { NotifyReceiver } from './support/notify-receiver';

/**
 * Design §9.3 (mailbox-worker feeds and inventory, Microsoft 365, D10, D11.1) against the
 * in-process Graph simulator with the real MySQL writer, Redis and MinIO: inventory (upsert,
 * aliases, discovered adoption, disabled, deleted, limit), Graph delta initialization without
 * backfill, ingest (MIME in S3, registry rows, `received.v1` outbox, pending copy) finalized by the
 * copies role, too-large messages, expired cursors, notification-driven sync through a
 * subscription (create, renew, lifecycle, delete), dedupe in both orders with the call log proving
 * no MIME fetch, 429 `Retry-After` pausing the connection family across two worker instances,
 * per-connection budgets isolating two organizations, and revocation.
 */
const fx = new Fixtures();
const clock = new Clock();
const S = fx.suffix;
const OTHER_TENANT = '22222222-3333-4444-8555-666666666666';
const OTHER_DOMAIN = `other-${S}.it-apimode.example`;
const SECRET = 'e'.repeat(64);
let sims: RunningSimulators;
let tokens: SimAccessTokens;
let receiver: NotifyReceiver;
let comps: MailboxComponents;
let org: TestOrg;
let conn: TestConnection;
let sourceId: bigint;

function directoryAs(tenantId: string, domain: string): MsDirectory {
  const json = JSON.stringify(microsoftDirectory(clock.now()))
    .split(MS_TENANT_ID)
    .join(tenantId)
    .split(MS_DOMAIN)
    .join(domain);
  return JSON.parse(json) as MsDirectory;
}

const mailboxOf = (organizationId: bigint, address: string) =>
  fx.prisma.apiMailbox.findFirstOrThrow({
    where: { organizationId, primaryAddress: address },
    select: MAILBOX_SELECT,
  });

async function sync(c: MailboxComponents, organizationId: bigint, address: string) {
  const mailbox = await mailboxOf(organizationId, address);
  const ctx = await loadConnectionContext(fx.prisma, mailbox.apiConnectionId);
  const state = await loadOrgApiModeState(fx.prisma, organizationId);
  return c.feeds!.syncMailbox(mailbox, ctx, state);
}

const valueCalls = () => sims.script.calls({ simulator: 'graph', path: /\/\$value$/ }).length;

const ALEX = `alex@${MS_DOMAIN}`;
const BLAKE = `blake@${MS_DOMAIN}`;

beforeAll(async () => {
  sims = await startSimulators({
    dataset: {
      microsoft: {
        directories: [microsoftDirectory(clock.now()), directoryAs(OTHER_TENANT, OTHER_DOMAIN)],
      },
    },
    now: clock.ms,
  });
  for (const tenant of [MS_TENANT_ID, OTHER_TENANT]) {
    sims.tokens.setGrant(
      tenant,
      M365_MAILBOX_REMEDIATION_PROFILE.key,
      M365_MAILBOX_REMEDIATION_PROFILE.permissions,
    );
  }
  tokens = new SimAccessTokens(() => sims, clock);
  receiver = new NotifyReceiver(fx.prisma, clock.now);
  await receiver.start();
  comps = fx.components(
    fx.config(sims, {
      API_MODE_GRAPH_NOTIFICATION_URL: receiver.url,
      API_MODE_NOTIFICATION_SECRET: SECRET,
    }),
    { clock, tokens },
  );
  org = await fx.organization('graph');
  await fx.domain(org, MS_DOMAIN, 'api');
  conn = await fx.connection(org, 'microsoft_365', {
    tenantId: MS_TENANT_ID,
    domains: [MS_DOMAIN],
    feeds: { enabled: true, mode: 'poll' },
  });
  tokens.directories.set(conn.providerConnectionPublicId, MS_TENANT_ID);
  sourceId = await fx.journalSource(org, conn);
});

afterAll(async () => {
  await receiver?.stop();
  await sims?.stop();
  await fx.cleanup();
});

describe('inventory (D11.1)', () => {
  it('upserts in-scope users with aliases, adopts discovered mailboxes, disables and counts', async () => {
    // A mailbox only seen in a journal envelope before the inventory.
    const message = await fx.journalCopy(org, sourceId, {
      eml: syntheticEml({ to: [BLAKE] }),
      recipients: [BLAKE],
      messageId: null,
      from: 'sender@sender.example',
      receivedAt: clock.now(),
    });
    await comps.copies.handle(fx.copyScanned(org.id, message, { completedAt: clock.now() }));
    const discovered = await mailboxOf(org.id, BLAKE);
    expect(discovered.status).toBe('discovered');

    const report = await comps.inventory!.run(conn.apiConnectionId);
    expect(report).toMatchObject({ result: 'ok', users: 6, adopted: 1, disabled: 1 });
    const mailboxes = await fx.prisma.apiMailbox.findMany({
      where: { organizationId: org.id },
      include: { addresses: true },
    });
    const by = new Map(mailboxes.map((m) => [m.primaryAddress, m]));
    expect([...by.keys()].sort()).toEqual(
      ['alex', 'blake', 'casey', 'drew', 'erin', 'gale'].map((u) => `${u}@${MS_DOMAIN}`),
    );
    expect(by.get(BLAKE)!.id).toBe(discovered.id);
    expect(by.get(BLAKE)!.providerUserId).toBe(MS_USERS.blake);
    expect(by.get(`gale@${MS_DOMAIN}`)!.status).toBe('disabled');
    expect(
      by
        .get(`erin@${MS_DOMAIN}`)!
        .addresses.map((a) => `${a.kind}:${a.address}`)
        .sort(),
    ).toEqual([`alias:erin.alias@${MS_DOMAIN}`, `primary:erin@${MS_DOMAIN}`]);
    // Feeds are enabled: active in-scope mailboxes start pending, disabled ones stay off.
    expect(by.get(ALEX)!.feedStatus).toBe('pending');
    expect(by.get(`gale@${MS_DOMAIN}`)!.feedStatus).toBe('off');
    const row = await fx.prisma.apiModeConnection.findUniqueOrThrow({
      where: { id: conn.apiConnectionId },
    });
    expect(row).toMatchObject({ inventoryStatus: 'ok', mailboxesTotal: 5, lastErrorCode: null });
  });

  it('marks users no longer listed deleted and refuses inventories above the limit', async () => {
    const directory = sims.script.dataset.microsoft!.directories[0]!;
    const drew = directory.users.find((u) => u.id === MS_USERS.drew)!;
    directory.users = directory.users.filter((u) => u.id !== MS_USERS.drew);
    expect(await comps.inventory!.run(conn.apiConnectionId)).toMatchObject({
      result: 'ok',
      deleted: 1,
    });
    expect((await mailboxOf(org.id, `drew@${MS_DOMAIN}`)).status).toBe('deleted');
    directory.users.push(drew);
    expect(await comps.inventory!.run(conn.apiConnectionId)).toMatchObject({
      result: 'ok',
      deleted: 0,
    });
    expect((await mailboxOf(org.id, `drew@${MS_DOMAIN}`)).status).toBe('active');

    const limited = fx.components(fx.config(sims, { API_MODE_MAX_MAILBOXES_PER_CONNECTION: '3' }), {
      clock,
      tokens,
    });
    expect(await limited.inventory!.run(conn.apiConnectionId)).toEqual({ result: 'limit' });
    const row = await fx.prisma.apiModeConnection.findUniqueOrThrow({
      where: { id: conn.apiConnectionId },
    });
    expect(row).toMatchObject({ inventoryStatus: 'failed', lastErrorCode: 'inventory_limit' });
    expect(
      await fx.prisma.apiMailbox.count({
        where: { organizationId: org.id, status: { not: 'deleted' } },
      }),
    ).toBe(6);
    await comps.inventory!.run(conn.apiConnectionId);
  });
});

describe('Graph delta feed (D10.3)', () => {
  it('initializes without backfill, then ingests new Inbox mail into the registry and S3', async () => {
    await sims.deliver({
      user: ALEX,
      eml: syntheticEml({ to: [ALEX], subject: 'Before the feed' }),
    });
    expect(await sync(comps, org.id, ALEX)).toBe('initialized');
    expect(valueCalls()).toBe(0);
    let alex = await mailboxOf(org.id, ALEX);
    expect(alex.feedStatus).toBe('active');
    expect(alex.feedCursor).toBeTruthy();
    expect(alex.feedStartedAt).not.toBeNull();

    clock.advance(1_000);
    const id = `${crypto.randomUUID()}@sender.example`;
    const delivered = await sims.deliver({
      user: ALEX,
      eml: syntheticEml({ messageId: id, to: [ALEX], subject: 'New mail' }),
    });
    clock.advance(1_000);
    expect(await sync(comps, org.id, ALEX)).toBe('ok');
    expect(valueCalls()).toBe(1);
    alex = await mailboxOf(org.id, ALEX);
    const ingestKey = ingestKeyForCopy({
      connectionPublicId: conn.apiConnectionPublicId,
      mailboxPublicId: alex.publicId,
      providerMessageId: delivered.messageId,
    });
    const identity = await fx.prisma.messageIdentity.findFirstOrThrow({
      where: { organizationId: org.id, ingestKey },
    });
    const message = await fx.prisma.emailMessage.findFirstOrThrow({ where: { id: identity.id } });
    expect(message).toMatchObject({
      ingestSource: 'mailbox_api',
      status: 'persisted',
      direction: 'inbound',
      internetMessageId: `<${id}>`,
      subject: 'New mail',
      recipientCount: 1,
      clientIp: null,
    });
    const object = await fx.s3.send(
      new GetObjectCommand({ Bucket: fx.bucket, Key: message.emlObjectKey }),
    );
    const body = Buffer.from(await object.Body!.transformToByteArray());
    expect(fx.prisma && body.length).toBe(message.sizeBytes);
    expect(message.emlObjectKey).toMatch(
      new RegExp(`^org/${org.id.toString()}/eml/\\d{4}/\\d{2}/\\d{2}/[0-9a-f]{32}\\.eml$`),
    );
    const recipients = await fx.prisma.emailRecipient.findMany({
      where: { messageId: identity.id },
    });
    expect(recipients.map((r) => [r.address, r.status])).toEqual([[ALEX, 'journaled']]);
    expect(
      await fx.prisma.emailMessageStatusHistory.count({ where: { messageId: identity.id } }),
    ).toBe(2);
    const event = await fx.prisma.emailEvent.findFirstOrThrow({
      where: { messageId: identity.id },
    });
    expect(event.details).toMatchObject({
      mailboxApi: {
        connectionId: conn.apiConnectionPublicId,
        mailboxId: alex.publicId,
        provider: 'microsoft_365',
      },
    });
    const outbox = await fx.prisma.messageOutbox.findFirstOrThrow({
      where: { organizationId: org.id, aggregateId: identity.id.toString() },
    });
    expect(outbox.eventType).toBe('mail.message.received.v1');
    expect(outbox.payload).toMatchObject({ ingestSource: 'mailbox_api', recipientCount: 1 });
    const [copy] = await fx.prisma.apiMessageCopy.findMany({ where: { messageId: identity.id } });
    expect(copy).toMatchObject({
      source: 'graph',
      status: 'pending',
      seenApi: true,
      seenJournal: false,
      providerMessageId: delivered.messageId,
      deliveredBasis: 'graph_received',
      mailboxId: alex.id,
    });
    expect(copy!.providerDeliveredAt?.toISOString()).toBe(delivered.receivedAt);
    const claim = await fx.prisma.apiCopyDedupeKey.findFirstOrThrow({
      where: { mailboxId: alex.id, copyId: copy!.id },
    });
    expect(claim.claimedBy).toBe('graph');

    // The email-worker's copy_scanned.v1 finalizes the pending copy.
    const completedAt = new Date(Date.parse(delivered.receivedAt) + 45_000);
    await comps.copies.handle(
      fx.copyScanned(
        org.id,
        { id: identity.id, publicId: identity.publicId, receivedAt: identity.receivedAt },
        {
          completedAt,
          ingestSource: 'mailbox_api',
          verdict: 'malware',
          riskScore: 990,
        },
      ),
    );
    const finalized = await fx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id: copy!.id } });
    expect(finalized).toMatchObject({
      status: 'scanned',
      verdict: 'malware',
      riskScore: 990,
      lagMs: 45_000,
    });

    // A replayed page is idempotent: no second fetch, no second row.
    await fx.prisma.apiMailbox.update({
      where: { id: alex.id },
      data: { feedCursor: alex.feedCursor },
    });
    expect(await sync(comps, org.id, ALEX)).toBe('ok');
    expect(await fx.prisma.apiMessageCopy.count({ where: { mailboxId: alex.id } })).toBe(1);
  });

  it('records messages above the size cap as too_large without content', async () => {
    const small = fx.components(fx.config(sims, { API_MODE_MAX_MESSAGE_BYTES: '65536' }), {
      clock,
      tokens,
    });
    await sims.deliver({ user: ALEX, eml: syntheticEml({ to: [ALEX], minBytes: 200_000 }) });
    expect(await sync(small, org.id, ALEX)).toBe('ok');
    const copies = await fx.prisma.apiMessageCopy.findMany({
      where: { mailboxId: (await mailboxOf(org.id, ALEX)).id, status: 'too_large' },
    });
    expect(copies).toHaveLength(1);
    expect(await fx.prisma.emailMessage.count({ where: { id: copies[0]!.messageId } })).toBe(0);
    await comps.counters.flush(fx.organizationIds);
    const counters = await fx.prisma.apiModeCounter.findMany({
      where: { apiConnectionId: conn.apiConnectionId },
    });
    expect(counters.reduce((n, c) => n + c.tooLarge, 0)).toBe(1);
    expect(counters.reduce((n, c) => n + c.feedCopies, 0)).toBe(1);
    expect(counters.reduce((n, c) => n + c.providerRequests, 0)).toBeGreaterThan(0);
  });

  it('re-initializes an expired cursor without backfill and records the gap', async () => {
    const { expireCursors } = await import('@email-gateway/idp-adapters/testing');
    await sims.deliver({ user: BLAKE, eml: syntheticEml({ to: [BLAKE] }) });
    expect(await sync(comps, org.id, BLAKE)).toBe('initialized');
    await sims.deliver({ user: BLAKE, eml: syntheticEml({ to: [BLAKE] }) });
    expireCursors(sims.script, BLAKE);
    const before = valueCalls();
    expect(await sync(comps, org.id, BLAKE)).toBe('reset');
    expect(valueCalls()).toBe(before);
    const blake = await mailboxOf(org.id, BLAKE);
    expect(blake.feedStatus).toBe('active');
    const row = await fx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: blake.id } });
    expect(row.lastGapAt).not.toBeNull();
    await comps.counters.flush(fx.organizationIds);
    const counters = await fx.prisma.apiModeCounter.findMany({
      where: { apiConnectionId: conn.apiConnectionId },
    });
    expect(counters.reduce((n, c) => n + c.cursorResets, 0)).toBe(1);
  });
});

describe('dedupe of journal and feed copies (D7 step 6, D10.3 a)', () => {
  it('journal first: the feed sees the duplicate and fetches nothing', async () => {
    const casey = `casey@${MS_DOMAIN}`;
    expect(await sync(comps, org.id, casey)).toBe('initialized');
    const id = `${crypto.randomUUID()}@sender.example`;
    const eml = syntheticEml({ messageId: id, to: [casey] });
    const message = await fx.journalCopy(org, sourceId, {
      eml,
      recipients: [casey],
      messageId: id,
      from: 'sender@sender.example',
      receivedAt: clock.now(),
    });
    await comps.copies.handle(fx.copyScanned(org.id, message, { completedAt: clock.now() }));
    const delivered = await sims.deliver({ user: casey, eml });
    const before = valueCalls();
    expect(await sync(comps, org.id, casey)).toBe('ok');
    expect(valueCalls()).toBe(before);
    const copies = await fx.prisma.apiMessageCopy.findMany({
      where: { mailboxId: (await mailboxOf(org.id, casey)).id },
    });
    expect(copies).toHaveLength(1);
    expect(copies[0]).toMatchObject({
      source: 'journal',
      seenJournal: true,
      seenApi: true,
      providerMessageId: delivered.messageId,
    });
  });

  it('feed first: the journal copy marks the feed copy seen_journal', async () => {
    const erin = `erin@${MS_DOMAIN}`;
    expect(await sync(comps, org.id, erin)).toBe('initialized');
    const id = `${crypto.randomUUID()}@sender.example`;
    const eml = syntheticEml({ messageId: id, to: [erin] });
    await sims.deliver({ user: erin, eml });
    expect(await sync(comps, org.id, erin)).toBe('ok');
    const message = await fx.journalCopy(org, sourceId, {
      eml,
      recipients: [erin],
      messageId: id,
      from: 'sender@sender.example',
      receivedAt: clock.now(),
    });
    await comps.copies.handle(fx.copyScanned(org.id, message, { completedAt: clock.now() }));
    const copies = await fx.prisma.apiMessageCopy.findMany({
      where: { mailboxId: (await mailboxOf(org.id, erin)).id },
    });
    expect(copies).toHaveLength(1);
    expect(copies[0]).toMatchObject({ source: 'graph', seenJournal: true, seenApi: true });
  });
});

describe('change notifications (D10.4)', () => {
  it('creates a subscription, syncs on a pushed notification, renews and re-creates it', async () => {
    await fx.prisma.apiModeConnection.update({
      where: { id: conn.apiConnectionId },
      data: { feedMode: 'notify' },
    });
    expect(await sync(comps, org.id, ALEX)).toBe('ok');
    let alex = await fx.prisma.apiMailbox.findUniqueOrThrow({
      where: { id: (await mailboxOf(org.id, ALEX)).id },
    });
    expect(alex.subscriptionId).toBeTruthy();
    expect(alex.clientStateVersion).toBe(1);
    expect(alex.clientStateHash).toBe(clientStateHash(deriveClientState(SECRET, alex.publicId, 1)));
    expect(sims.script.notifications.some((n) => n.kind === 'validation' && n.ok)).toBe(true);
    // Notifications as hints: the safety poll applies.
    expect(alex.nextSyncAt!.getTime() - clock.ms()).toBe(3_600_000);

    // A delivery pushes a change notification; the receiver (the api's role) requests a sync.
    await sims.deliver({ user: ALEX, eml: syntheticEml({ to: [ALEX] }) });
    expect(receiver.received.at(-1)).toMatchObject({
      subscriptionId: alex.subscriptionId,
      matched: true,
    });
    alex = await fx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: alex.id } });
    expect(alex.syncRequestedAt).not.toBeNull();
    // The claim loop picks the requested mailbox before its next poll.
    const before = valueCalls();
    expect(await comps.feeds!.tick()).toBeTypeOf('boolean');
    expect(valueCalls()).toBe(before + 1);
    alex = await fx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: alex.id } });
    expect(alex.syncRequestedAt).toBeNull();
    expect(alex.leaseUntil).toBeNull();

    // Renewal before expiry (PATCH), keeping the client state.
    clock.advance((4230 - 700) * 60_000);
    const patches = () => sims.script.calls({ simulator: 'graph', method: 'PATCH' }).length;
    const p0 = patches();
    expect(await sync(comps, org.id, ALEX)).toBe('ok');
    expect(patches()).toBe(p0 + 1);
    const renewed = await fx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: alex.id } });
    expect(renewed.subscriptionId).toBe(alex.subscriptionId);
    expect(renewed.subscriptionExpiresAt!.getTime()).toBeGreaterThan(
      alex.subscriptionExpiresAt!.getTime(),
    );

    // Graph removed it (lifecycle): the next sync creates a new one with a new client state.
    const { pushLifecycle } = await import('@email-gateway/idp-adapters/testing');
    await pushLifecycle(sims.script, renewed.subscriptionId!, 'subscriptionRemoved');
    expect(receiver.received.at(-1)).toMatchObject({
      lifecycleEvent: 'subscriptionRemoved',
      matched: true,
    });
    expect(await sync(comps, org.id, ALEX)).toBe('ok');
    const recreated = await fx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: alex.id } });
    expect(recreated.subscriptionId).not.toBe(renewed.subscriptionId);
    expect(recreated.clientStateVersion).toBe(2);

    // Back to poll mode: the subscription is deleted at Graph and cleared.
    await fx.prisma.apiModeConnection.update({
      where: { id: conn.apiConnectionId },
      data: { feedMode: 'poll' },
    });
    const deletes = () => sims.script.calls({ simulator: 'graph', method: 'DELETE' }).length;
    const d0 = deletes();
    expect(await sync(comps, org.id, ALEX)).toBe('ok');
    expect(deletes()).toBe(d0 + 1);
    const cleared = await fx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: alex.id } });
    expect(cleared).toMatchObject({ subscriptionId: null, clientStateHash: null });
  });
});

describe('throttling and budgets (D10.6, N7)', () => {
  it('a 429 Retry-After pauses the connection family for every worker instance', async () => {
    const second = fx.components(fx.config(sims), { clock, tokens });
    sims.script.inject({
      simulator: 'graph',
      path: /\/messages\/delta$/,
      status: 429,
      retryAfter: '2',
      times: 1,
    });
    expect(await sync(comps, org.id, ALEX)).toBe('throttled');
    const alex = await mailboxOf(org.id, ALEX);
    expect(alex.feedStatus).toBe('throttled');
    const row = await fx.prisma.apiModeConnection.findUniqueOrThrow({
      where: { id: conn.apiConnectionId },
    });
    expect(row.throttledUntil!.getTime()).toBe(clock.ms() + 2_000);
    expect(
      await fx.redis.pttl(RedisThrottleGate.key(conn.apiConnectionPublicId, 'graph')),
    ).toBeGreaterThan(0);

    // Another instance honours the pause before any call of the family.
    const calls = sims.script.calls({ simulator: 'graph' }).length;
    expect(await sync(second, org.id, BLAKE)).toBe('throttled');
    expect(sims.script.calls({ simulator: 'graph' }).length).toBe(calls);

    // After Retry-After the family is usable again.
    await new Promise((r) => setTimeout(r, 2_200));
    clock.advance(3_000);
    expect(await sync(second, org.id, BLAKE)).toBe('ok');
    expect((await mailboxOf(org.id, BLAKE)).feedStatus).toBe('active');
    await comps.counters.flush(fx.organizationIds);
    const counters = await fx.prisma.apiModeCounter.findMany({
      where: { apiConnectionId: conn.apiConnectionId },
    });
    expect(counters.reduce((n, c) => n + c.throttled429, 0)).toBe(1);
  });

  it('per-connection budgets isolate two organizations', async () => {
    const other = await fx.organization('graph-other');
    await fx.domain(other, OTHER_DOMAIN, 'api');
    const otherConn = await fx.connection(other, 'microsoft_365', {
      tenantId: OTHER_TENANT,
      domains: [OTHER_DOMAIN],
      feeds: { enabled: true },
    });
    tokens.directories.set(otherConn.providerConnectionPublicId, OTHER_TENANT);
    await comps.inventory!.run(otherConn.apiConnectionId);
    const fixedMs = clock.ms();
    const budget = new RedisRateBudget(
      fx.redis as never,
      { graph: 3, gmail: 10, google_directory: 5 },
      () => fixedMs,
    );
    const limited = fx.components(fx.config(sims), { clock, tokens, budget });
    // Organization A's connection has spent its budget for this second.
    const key = RedisRateBudget.key(
      conn.apiConnectionPublicId,
      'graph',
      Math.floor(fixedMs / 1000),
    );
    await fx.redis.set(key, '100', 'EX', 30);
    const deltaCalls = (userId: string) =>
      sims.script.calls({ simulator: 'graph', path: `/v1.0/users/${userId}/mailFolders` }).length;
    const aBefore = deltaCalls(MS_USERS.casey);
    expect(await sync(limited, org.id, `casey@${MS_DOMAIN}`)).toBe('deferred');
    expect(deltaCalls(MS_USERS.casey)).toBe(aBefore);
    expect(await sync(limited, other.id, `casey@${OTHER_DOMAIN}`)).toBe('initialized');
  });
});

describe('revocation (D4)', () => {
  it('stops the feeds, clears cursors and subscriptions, and makes the inventory unavailable', async () => {
    await fx.prisma.providerConnectionGrant.update({
      where: { id: conn.grantId },
      data: { status: 'revoked' },
    });
    expect(await sync(comps, org.id, ALEX)).toBe('revoked');
    const mailboxes = await fx.prisma.apiMailbox.findMany({
      where: { apiConnectionId: conn.apiConnectionId, providerUserId: { not: null } },
    });
    for (const m of mailboxes.filter((x) => x.status === 'active')) {
      expect(m).toMatchObject({
        feedStatus: 'revoked',
        feedCursor: null,
        subscriptionId: null,
        clientStateHash: null,
      });
    }
    expect(await comps.inventory!.run(conn.apiConnectionId)).toEqual({ result: 'unavailable' });
    const row = await fx.prisma.apiModeConnection.findUniqueOrThrow({
      where: { id: conn.apiConnectionId },
    });
    expect(row.inventoryStatus).toBe('unavailable');
    // Journal detect scanning continues without the grant.
    const message = await fx.journalCopy(org, sourceId, {
      eml: syntheticEml({ to: [ALEX] }),
      recipients: [ALEX],
      messageId: null,
      from: 'sender@sender.example',
      receivedAt: clock.now(),
    });
    await comps.copies.handle(fx.copyScanned(org.id, message, { completedAt: clock.now() }));
    expect(await fx.prisma.apiMessageCopy.count({ where: { messageId: message.id } })).toBe(1);
  });
});
