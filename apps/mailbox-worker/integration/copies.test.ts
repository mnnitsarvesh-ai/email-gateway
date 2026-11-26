import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  syntheticEml,
  startSimulators,
  type RunningSimulators,
} from '@email-gateway/idp-adapters/testing';
import { copyMessageIdHash } from '@email-gateway/mailbox-api';
import type { MailboxComponents } from '../src/components';
import { COPIES_CONSUMER } from '../src/copies/copies.handler';
import {
  Clock,
  Fixtures,
  SimAccessTokens,
  type TestConnection,
  type TestOrg,
} from './support/harness';

/**
 * Design §9.3 (mailbox-worker, copies role, D7) on the real MySQL writer, Redis and MinIO: journal
 * copy fan-out to api/hybrid recipients only, discovered mailboxes, internal recipients skipped,
 * in-flight feed claim takeover, a recorded feed copy marked `seen_journal`, no Message-ID, the
 * hybrid inline link, lag from the top Received header and its fallback, counters, idempotent
 * redelivery, organizations without API mode and copies without an API connection.
 */
const fx = new Fixtures();
const clock = new Clock();
let sims: RunningSimulators;
let comps: MailboxComponents;
let org: TestOrg;
let conn: TestConnection;
let sourceId: bigint;
const S = fx.suffix;
const API = `api-${S}.it-apimode.example`;
const HYBRID = `hybrid-${S}.it-apimode.example`;
const INLINE = `inline-${S}.it-apimode.example`;

beforeAll(async () => {
  sims = await startSimulators({ dataset: {}, now: clock.ms });
  const tokens = new SimAccessTokens(() => sims, clock);
  comps = fx.components(fx.config(sims), { clock, tokens });
  org = await fx.organization('copies');
  await fx.domain(org, API, 'api');
  await fx.domain(org, HYBRID, 'hybrid');
  await fx.domain(org, INLINE, null);
  conn = await fx.connection(org, 'microsoft_365', {
    tenantId: 'tenant-copies',
    domains: [API, HYBRID],
  });
  sourceId = await fx.journalSource(org, conn);
});

afterAll(async () => {
  await sims?.stop();
  await fx.cleanup();
});

const copiesOf = (messageId: bigint) =>
  fx.prisma.apiMessageCopy.findMany({ where: { messageId }, orderBy: { mailboxId: 'asc' } });

async function journal(
  recipients: string[],
  options: { messageId?: string | null; from?: string; topReceivedAt?: Date | null } = {},
) {
  const receivedAt = clock.now();
  const messageId =
    options.messageId === undefined ? `${crypto.randomUUID()}@sender.example` : options.messageId;
  const from = options.from ?? 'sender@sender.example';
  const eml = syntheticEml({
    messageId,
    from,
    to: recipients,
    ...(options.topReceivedAt === null
      ? {}
      : { receivedAt: options.topReceivedAt ?? new Date(receivedAt.getTime() - 120_000) }),
  });
  return fx.journalCopy(org, sourceId, { eml, recipients, messageId, from, receivedAt });
}

describe('copies role: journal copies (D7)', () => {
  it('fans out to api/hybrid recipients only, discovers mailboxes, measures the lag from Received', async () => {
    const message = await journal([
      `alex@${API}`,
      `blake@${HYBRID}`,
      `casey@${INLINE}`,
      'someone@other.example',
    ]);
    const completedAt = new Date(message.receivedAt.getTime() + 30_000);
    const event = fx.copyScanned(org.id, message, {
      completedAt,
      verdict: 'phishing',
      riskScore: 812,
    });
    expect(await comps.copies.handle(event)).toBe('handled');

    const copies = await copiesOf(message.id);
    expect(copies).toHaveLength(2);
    const mailboxes = await fx.prisma.apiMailbox.findMany({
      where: { organizationId: org.id },
      include: { addresses: true },
      orderBy: { id: 'asc' },
    });
    expect(mailboxes.map((m) => m.primaryAddress).sort()).toEqual([
      `alex@${API}`,
      `blake@${HYBRID}`,
    ]);
    for (const m of mailboxes) {
      expect(m.status).toBe('discovered');
      expect(m.providerUserId).toBeNull();
      expect(m.apiConnectionId).toBe(conn.apiConnectionId);
      expect(m.journalLastSeenAt?.getTime()).toBe(message.receivedAt.getTime());
      expect(m.addresses.map((a) => [a.address, a.kind])).toEqual([[m.primaryAddress, 'primary']]);
    }
    for (const copy of copies) {
      expect(copy).toMatchObject({
        source: 'journal',
        seenJournal: true,
        seenApi: false,
        direction: 'inbound',
        status: 'scanned',
        verdict: 'phishing',
        riskScore: 812,
        verdictAuthority: 'copy',
        deliveredBasis: 'received_header',
        lagMs: 150_000,
      });
      expect(copy.messageIdHash).toMatch(/^[0-9a-f]{64}$/);
      expect(copy.verdictAt?.getTime()).toBe(completedAt.getTime());
    }
    expect(await fx.prisma.apiCopyDedupeKey.count({ where: { organizationId: org.id } })).toBe(2);
    const ledger = await fx.prisma.messageIdempotency.count({
      where: { consumer: COPIES_CONSUMER, eventId: event.eventId },
    });
    expect(ledger).toBe(1);

    await comps.counters.flush(fx.organizationIds);
    const counters = await fx.prisma.apiModeCounter.findMany({
      where: { apiConnectionId: conn.apiConnectionId },
    });
    expect(counters.reduce((n, c) => n + c.journalCopies, 0)).toBe(2);
    expect(counters.reduce((n, c) => n + c.lagCount, 0)).toBe(2);
    expect(counters.reduce((n, c) => n + c.lagLe300s, 0)).toBe(2);
  });

  it('redelivery has one effect (ledger)', async () => {
    const message = await journal([`drew@${API}`]);
    const event = fx.copyScanned(org.id, message, { completedAt: clock.now() });
    expect(await comps.copies.handle(event)).toBe('handled');
    expect(await comps.copies.handle(event)).toBe('duplicate');
    expect(await copiesOf(message.id)).toHaveLength(1);
  });

  it('skips internal recipients (counter only, API-3 hook)', async () => {
    const message = await journal([`erin@${API}`], { from: `frank@${HYBRID}` });
    expect(
      await comps.copies.handle(fx.copyScanned(org.id, message, { completedAt: clock.now() })),
    ).toBe('handled');
    expect(await copiesOf(message.id)).toHaveLength(0);
    await comps.counters.flush(fx.organizationIds);
    const counters = await fx.prisma.apiModeCounter.findMany({
      where: { apiConnectionId: conn.apiConnectionId },
    });
    expect(counters.reduce((n, c) => n + c.skippedInternal, 0)).toBeGreaterThanOrEqual(1);
  });

  it('records copies without a Message-ID (no dedupe) and falls back to the ingest time', async () => {
    const message = await journal([`gale@${API}`], { messageId: null, topReceivedAt: null });
    await comps.copies.handle(
      fx.copyScanned(org.id, message, {
        completedAt: new Date(message.receivedAt.getTime() + 5_000),
      }),
    );
    const [copy] = await copiesOf(message.id);
    expect(copy).toMatchObject({ messageIdHash: null, deliveredBasis: 'ingest', lagMs: 5_000 });
    expect(copy!.providerDeliveredAt?.getTime()).toBe(message.receivedAt.getTime());
  });

  it('takes over an in-flight feed claim and records the journal copy', async () => {
    const id = `${crypto.randomUUID()}@sender.example`;
    // The address resolves to a known mailbox; a Graph claim for this Message-ID is in flight.
    const first = await journal([`harper@${API}`]);
    await comps.copies.handle(fx.copyScanned(org.id, first, { completedAt: clock.now() }));
    const mailbox = await fx.prisma.apiMailbox.findFirstOrThrow({
      where: { primaryAddress: `harper@${API}` },
    });
    const hash = copyMessageIdHash(org.id, id)!;
    await fx.prisma.apiCopyDedupeKey.create({
      data: {
        organizationId: org.id,
        mailboxId: mailbox.id,
        messageIdHash: hash,
        claimedBy: 'graph',
        claimExpiresAt: new Date(clock.ms() + 600_000),
      },
    });
    const message = await journal([`harper@${API}`], { messageId: id });
    await comps.copies.handle(fx.copyScanned(org.id, message, { completedAt: clock.now() }));
    const [copy] = await copiesOf(message.id);
    expect(copy).toBeDefined();
    const claim = await fx.prisma.apiCopyDedupeKey.findUniqueOrThrow({
      where: { mailboxId_messageIdHash: { mailboxId: mailbox.id, messageIdHash: hash } },
    });
    expect(claim).toMatchObject({ claimedBy: 'journal', copyId: copy!.id, claimExpiresAt: null });
  });

  it('marks a recorded feed copy seen_journal instead of writing a second row', async () => {
    const id = `${crypto.randomUUID()}@sender.example`;
    const mailbox = await fx.prisma.apiMailbox.findFirstOrThrow({
      where: { primaryAddress: `harper@${API}` },
    });
    // A feed copy of the same Message-ID (registry message of another ingest), already recorded.
    const feedMessage = await journal([`unrelated@${INLINE}`], { messageId: id });
    const feedCopy = await fx.prisma.apiMessageCopy.create({
      data: {
        receivedAt: feedMessage.receivedAt,
        publicId: crypto.randomUUID(),
        organizationId: org.id,
        apiConnectionId: conn.apiConnectionId,
        mailboxId: mailbox.id,
        messageId: feedMessage.id,
        source: 'graph',
        seenApi: true,
        status: 'scanned',
        providerMessageId: 'AAMkFeed',
      },
    });
    await fx.prisma.apiCopyDedupeKey.create({
      data: {
        organizationId: org.id,
        mailboxId: mailbox.id,
        messageIdHash: copyMessageIdHash(org.id, id)!,
        claimedBy: 'graph',
        copyId: feedCopy.id,
        copyReceivedAt: feedCopy.receivedAt,
      },
    });
    const message = await journal([`harper@${API}`], { messageId: id });
    await comps.copies.handle(fx.copyScanned(org.id, message, { completedAt: clock.now() }));
    expect(await copiesOf(message.id)).toHaveLength(0);
    const after = await fx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id: feedCopy.id } });
    expect(after).toMatchObject({ seenJournal: true, seenApi: true, source: 'graph' });
  });

  it('links hybrid copies to the inline gateway message (verdict authority inline)', async () => {
    const id = `${crypto.randomUUID()}@sender.example`;
    const inlineId = await fx.gatewayMessage(org, {
      messageId: id,
      recipient: `ivy@${HYBRID}`,
      receivedAt: new Date(clock.ms() - 60_000),
      finalVerdict: 'clean',
    });
    const message = await journal([`ivy@${HYBRID}`, `jo@${API}`], { messageId: id });
    await comps.copies.handle(
      fx.copyScanned(org.id, message, { completedAt: clock.now(), verdict: 'spam' }),
    );
    const copies = await copiesOf(message.id);
    const byAddress = new Map<string, (typeof copies)[number]>();
    for (const c of copies) {
      const m = await fx.prisma.apiMailbox.findUniqueOrThrow({ where: { id: c.mailboxId } });
      byAddress.set(m.primaryAddress, c);
    }
    expect(byAddress.get(`ivy@${HYBRID}`)).toMatchObject({
      verdictAuthority: 'inline',
      verdict: 'clean',
      inlineMessageId: inlineId,
    });
    expect(byAddress.get(`jo@${API}`)).toMatchObject({ verdictAuthority: 'copy', verdict: 'spam' });
  });

  it('records scan and parse failures without a lag', async () => {
    const message = await journal([`kim@${API}`]);
    await comps.copies.handle(
      fx.copyScanned(org.id, message, { completedAt: clock.now(), outcome: 'parse_failed' }),
    );
    const [copy] = await copiesOf(message.id);
    expect(copy).toMatchObject({
      status: 'parse_failed',
      verdict: null,
      riskScore: null,
      lagMs: null,
    });
  });
});

describe('copies role: skipped events still write the ledger row (reconciled queue)', () => {
  it('acks organizations without API mode', async () => {
    const other = await fx.organization('inline-only');
    await fx.domain(other, `inl-${S}.it-apimode.example`, null);
    const c = await fx.connection(other, 'microsoft_365', {
      tenantId: 'tenant-inline',
      domains: [`inl-${S}.it-apimode.example`],
    });
    const src = await fx.journalSource(other, c);
    const eml = syntheticEml({ to: [`x@inl-${S}.it-apimode.example`] });
    const message = await fx.journalCopy(other, src, {
      eml,
      recipients: [`x@inl-${S}.it-apimode.example`],
      messageId: null,
      from: 'sender@sender.example',
      receivedAt: clock.now(),
    });
    const event = fx.copyScanned(other.id, message, { completedAt: clock.now() });
    expect(await comps.copies.handle(event)).toBe('handled');
    expect(await copiesOf(message.id)).toHaveLength(0);
    expect(
      await fx.prisma.messageIdempotency.count({
        where: { consumer: COPIES_CONSUMER, eventId: event.eventId },
      }),
    ).toBe(1);
    expect(await comps.copies.handle(event)).toBe('duplicate');
  });

  it('acks an api domain of an organization without the feature', async () => {
    const other = await fx.organization('unentitled', { entitled: false });
    await fx.domain(other, `une-${S}.it-apimode.example`, 'api');
    const c = await fx.connection(other, 'microsoft_365', {
      tenantId: 'tenant-une',
      domains: [`une-${S}.it-apimode.example`],
    });
    const src = await fx.journalSource(other, c);
    const message = await fx.journalCopy(other, src, {
      eml: syntheticEml({ to: [`x@une-${S}.it-apimode.example`] }),
      recipients: [`x@une-${S}.it-apimode.example`],
      messageId: null,
      from: 'sender@sender.example',
      receivedAt: clock.now(),
    });
    await comps.copies.handle(fx.copyScanned(other.id, message, { completedAt: clock.now() }));
    expect(await copiesOf(message.id)).toHaveLength(0);
    expect(await fx.prisma.apiMailbox.count({ where: { organizationId: other.id } })).toBe(0);
  });

  it('acks copies whose intake source has no provider connection (smtp_bcc)', async () => {
    const src = await fx.journalSource(org, null, 'smtp_bcc');
    const message = await fx.journalCopy(org, src, {
      eml: syntheticEml({ to: [`lee@${API}`] }),
      recipients: [`lee@${API}`],
      messageId: null,
      from: 'sender@sender.example',
      receivedAt: clock.now(),
    });
    await comps.copies.handle(fx.copyScanned(org.id, message, { completedAt: clock.now() }));
    expect(await copiesOf(message.id)).toHaveLength(0);
    expect(await fx.prisma.apiMailbox.count({ where: { primaryAddress: `lee@${API}` } })).toBe(0);
  });

  it('refuses an invalid payload as non-retryable', async () => {
    const message = await journal([`max@${API}`]);
    const event = fx.copyScanned(org.id, message, { completedAt: clock.now() });
    (event.payload as { outcome: string }).outcome = 'bogus';
    await expect(comps.copies.handle(event)).rejects.toMatchObject({ name: 'NonRetryableError' });
  });
});
