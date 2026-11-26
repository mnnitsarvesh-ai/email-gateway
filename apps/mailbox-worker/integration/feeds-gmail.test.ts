import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  expireCursors,
  googleCustomer,
  GS_ADMIN_EMAIL,
  GS_CUSTOMER_ID,
  GS_DOMAIN,
  GS_USERS,
  startSimulators,
  syntheticEml,
  type RunningSimulators,
} from '@email-gateway/idp-adapters/testing';
import { GOOGLE_MAILBOX_REMEDIATION_PROFILE } from '@email-gateway/provider-integrations';
import type { MailboxComponents } from '../src/components';
import { loadOrgApiModeState } from '../src/domain/api-mode-state';
import { loadConnectionContext } from '../src/domain/connections';
import { MAILBOX_SELECT } from '../src/feeds/feed-runner';
import {
  Clock,
  Fixtures,
  SimAccessTokens,
  type TestConnection,
  type TestOrg,
} from './support/harness';

/**
 * Design §9.3 (mailbox-worker, Google Workspace, D10.5, D11.1) against the in-process Gmail and
 * Directory simulators: Directory inventory with the delegated administrator as token subject,
 * history initialization from the profile (no backfill), continue (metadata, raw decoded through
 * the streaming extractor, token subject = the mailbox), expired history ids (404) re-initialized,
 * metadata-first dedupe proving no raw fetch, and the size pre-check from `sizeEstimate`.
 */
const fx = new Fixtures();
const clock = new Clock();
let sims: RunningSimulators;
let tokens: SimAccessTokens;
let comps: MailboxComponents;
let org: TestOrg;
let conn: TestConnection;
let sourceId: bigint;
const ALEX = `alex@${GS_DOMAIN}`;
const BLAKE = `blake@${GS_DOMAIN}`;

const mailboxOf = (address: string) =>
  fx.prisma.apiMailbox.findFirstOrThrow({
    where: { organizationId: org.id, primaryAddress: address },
    select: MAILBOX_SELECT,
  });

async function sync(c: MailboxComponents, address: string) {
  const mailbox = await mailboxOf(address);
  const ctx = await loadConnectionContext(fx.prisma, mailbox.apiConnectionId);
  return c.feeds!.syncMailbox(mailbox, ctx, await loadOrgApiModeState(fx.prisma, org.id));
}

const rawCalls = () =>
  sims.script
    .calls({ simulator: 'gmail', path: /\/messages\// })
    .filter((c) => c.query?.includes('format=raw')).length;

beforeAll(async () => {
  sims = await startSimulators({
    dataset: { google: { customers: [googleCustomer(clock.now())] } },
    now: clock.ms,
  });
  sims.tokens.setGrant(
    GS_CUSTOMER_ID,
    GOOGLE_MAILBOX_REMEDIATION_PROFILE.key,
    GOOGLE_MAILBOX_REMEDIATION_PROFILE.permissions,
  );
  tokens = new SimAccessTokens(() => sims, clock);
  comps = fx.components(fx.config(sims), { clock, tokens });
  org = await fx.organization('gmail');
  await fx.domain(org, GS_DOMAIN, 'hybrid');
  conn = await fx.connection(org, 'google_workspace', {
    tenantId: GS_CUSTOMER_ID,
    domains: [GS_DOMAIN],
    subjectEmail: GS_ADMIN_EMAIL,
    feeds: { enabled: true },
  });
  tokens.directories.set(conn.providerConnectionPublicId, GS_CUSTOMER_ID);
  sourceId = await fx.journalSource(org, conn, 'google_workspace_copy');
});

afterAll(async () => {
  await sims?.stop();
  await fx.cleanup();
});

describe('Google Directory inventory (D11.1)', () => {
  it('lists users as the delegated administrator; suspended users are disabled', async () => {
    const report = await comps.inventory!.run(conn.apiConnectionId);
    expect(report.result).toBe('ok');
    expect(tokens.requests.filter((r) => r.resource === 'google').map((r) => r.subject)).toContain(
      GS_ADMIN_EMAIL.toLowerCase(),
    );
    const mailboxes = await fx.prisma.apiMailbox.findMany({
      where: { organizationId: org.id },
      include: { addresses: true },
    });
    const by = new Map(mailboxes.map((m) => [m.primaryAddress, m]));
    expect(by.get(`casey@${GS_DOMAIN}`)!.status).toBe('disabled');
    expect(by.get(ALEX)!.providerUserId).toBe(GS_USERS.alex);
    expect(
      by
        .get(`erin@${GS_DOMAIN}`)!
        .addresses.map((a) => a.address)
        .sort(),
    ).toEqual([`erin.alias@${GS_DOMAIN}`, `erin@${GS_DOMAIN}`]);
    // frank is on the unverified (not linked) domain.
    expect([...by.keys()].some((a) => a.startsWith('frank@'))).toBe(false);
  });
});

describe('Gmail history feed (D10.5)', () => {
  it('initializes from the profile, then ingests Inbox additions with the mailbox as token subject', async () => {
    await sims.deliver({
      user: ALEX,
      eml: syntheticEml({ to: [ALEX], subject: 'Before the feed' }),
    });
    expect(await sync(comps, ALEX)).toBe('initialized');
    expect(rawCalls()).toBe(0);
    const id = `${crypto.randomUUID()}@sender.example`;
    const delivered = await sims.deliver({
      user: ALEX,
      eml: syntheticEml({ messageId: id, to: [ALEX], subject: 'Gmail mail' }),
    });
    // Not in the Inbox: ignored.
    await sims.deliver({ user: ALEX, eml: syntheticEml({ to: [ALEX] }), labelIds: ['SENT'] });
    expect(await sync(comps, ALEX)).toBe('ok');
    expect(rawCalls()).toBe(1);
    expect(tokens.requests.some((r) => r.subject === ALEX)).toBe(true);
    const alex = await mailboxOf(ALEX);
    expect(alex.feedCursor).toBe(String(Number(delivered.historyId) + 1));
    const copies = await fx.prisma.apiMessageCopy.findMany({ where: { mailboxId: alex.id } });
    expect(copies).toHaveLength(1);
    expect(copies[0]).toMatchObject({
      source: 'gmail',
      status: 'pending',
      deliveredBasis: 'gmail_internal',
      providerMessageId: delivered.messageId,
    });
    const message = await fx.prisma.emailMessage.findFirstOrThrow({
      where: { id: copies[0]!.messageId },
    });
    expect(message).toMatchObject({
      ingestSource: 'mailbox_api',
      internetMessageId: `<${id}>`,
      subject: 'Gmail mail',
    });
    expect(message.sizeBytes).toBe(delivered.sizeBytes);
  });

  it('re-initializes an expired history id (404) without backfill', async () => {
    expect(await sync(comps, BLAKE)).toBe('initialized');
    await sims.deliver({ user: BLAKE, eml: syntheticEml({ to: [BLAKE] }) });
    expireCursors(sims.script, BLAKE);
    const before = rawCalls();
    expect(await sync(comps, BLAKE)).toBe('reset');
    expect(rawCalls()).toBe(before);
    const row = await fx.prisma.apiMailbox.findUniqueOrThrow({
      where: { id: (await mailboxOf(BLAKE)).id },
    });
    expect(row.lastGapAt).not.toBeNull();
    expect(row.feedStatus).toBe('active');
  });

  it('deduplicates metadata first: a journal copy of the same Message-ID means no raw fetch', async () => {
    const id = `${crypto.randomUUID()}@sender.example`;
    const eml = syntheticEml({ messageId: id, to: [ALEX] });
    const message = await fx.journalCopy(org, sourceId, {
      eml,
      recipients: [ALEX],
      messageId: id,
      from: 'sender@sender.example',
      receivedAt: clock.now(),
    });
    await comps.copies.handle(fx.copyScanned(org.id, message, { completedAt: clock.now() }));
    const delivered = await sims.deliver({ user: ALEX, eml });
    const before = rawCalls();
    expect(await sync(comps, ALEX)).toBe('ok');
    expect(rawCalls()).toBe(before);
    const [copy] = await fx.prisma.apiMessageCopy.findMany({ where: { messageId: message.id } });
    expect(copy).toMatchObject({
      source: 'journal',
      seenApi: true,
      providerMessageId: delivered.messageId,
    });
  });

  it('pre-checks sizeEstimate: too_large without a raw fetch', async () => {
    const small = fx.components(fx.config(sims, { API_MODE_MAX_MESSAGE_BYTES: '65536' }), {
      clock,
      tokens,
    });
    await sims.deliver({ user: ALEX, eml: syntheticEml({ to: [ALEX], minBytes: 120_000 }) });
    const before = rawCalls();
    expect(await sync(small, ALEX)).toBe('ok');
    expect(rawCalls()).toBe(before);
    const tooLarge = await fx.prisma.apiMessageCopy.findMany({
      where: { mailboxId: (await mailboxOf(ALEX)).id, status: 'too_large' },
    });
    expect(tooLarge).toHaveLength(1);
    expect(tooLarge[0]!.source).toBe('gmail');
  });
});

describe('Gmail history backlog beyond the page cap', () => {
  it('resumes after the processed pages instead of replaying them (no stall at the cap)', async () => {
    const ERIN = `erin@${GS_DOMAIN}`;
    const capped = fx.components(fx.config(sims), { clock, tokens, maxPagesPerSync: 1 });
    expect(await sync(capped, ERIN)).toBe('initialized');
    const start = BigInt((await mailboxOf(ERIN)).feedCursor!);
    // A backlog of 500 Inbox records (one full history page) delivered before the feed started:
    // only the metadata is read (no raw fetch), then the new mail on page 2.
    const earlier = new Date(clock.ms() - 3_600_000).toISOString();
    for (let i = 0; i < 500; i += 1) {
      await sims.deliver({ user: ERIN, eml: syntheticEml({ to: [ERIN] }), receivedAt: earlier });
    }
    clock.advance(1_000);
    const id = `${crypto.randomUUID()}@sender.example`;
    const fresh = await sims.deliver({
      user: ERIN,
      eml: syntheticEml({ messageId: id, to: [ERIN], subject: 'After the backlog' }),
    });
    const before = rawCalls();

    // Run 1 reaches the cap after page 1: the cursor is page 1's last record, another run is due.
    expect(await sync(capped, ERIN)).toBe('ok');
    const afterFirst = await fx.prisma.apiMailbox.findUniqueOrThrow({
      where: { id: (await mailboxOf(ERIN)).id },
    });
    expect(BigInt(afterFirst.feedCursor!)).toBe(start + 500n);
    expect(afterFirst.syncRequestedAt).not.toBeNull();
    expect(rawCalls()).toBe(before);

    // Run 2 starts after page 1 and reaches the new mail (it never re-reads the backlog).
    const historyCalls = () => sims.script.calls({ simulator: 'gmail', path: /\/history$/ }).length;
    const historyBefore = historyCalls();
    expect(await sync(capped, ERIN)).toBe('ok');
    expect(historyCalls() - historyBefore).toBe(1);
    expect(rawCalls()).toBe(before + 1);
    const erin = await mailboxOf(ERIN);
    expect(erin.feedCursor).toBe(fresh.historyId);
    const copies = await fx.prisma.apiMessageCopy.findMany({ where: { mailboxId: erin.id } });
    expect(copies.map((c) => c.providerMessageId)).toEqual([fresh.messageId]);
  });
});
