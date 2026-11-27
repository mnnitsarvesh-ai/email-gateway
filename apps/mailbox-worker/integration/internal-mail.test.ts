import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  messageLocation,
  microsoftDirectory,
  MS_DOMAIN,
  MS_TENANT_ID,
  startSimulators,
  syntheticEml,
  type RunningSimulators,
} from '@email-gateway/idp-adapters/testing';
import { M365_MAILBOX_REMEDIATION_PROFILE } from '@email-gateway/provider-integrations';
import type { MailboxComponents } from '../src/components';
import { clawbackConfig } from './support/clawback';
import {
  Clock,
  Fixtures,
  SimAccessTokens,
  type TestConnection,
  type TestOrg,
} from './support/harness';
import { actionsOfCopy, cancelOpenActions, copiesOf, drain, riskRow } from './support/remediation';

/**
 * Design note 37 §9.3 (mailbox-worker, internal mail; C8, ADR-0104): internal journal recipients
 * recorded per mailbox with `direction = internal` and remediated by the R4 decision (P1 move
 * executed on the Graph simulator), internal mail disabled → `skipped_internal` (journal) and
 * `skip internal_mail_disabled` (feed copies), outbound-only journal messages recognised (no copy,
 * no mailbox discovery), mixed messages record their internal recipients only, a second journal
 * report of the same internal message is a duplicate, journal copies stay `journaled` and are
 * never delivered, counters `internal_copies`. Synthetic `it-apiclaw-*` organizations only.
 */
const fx = new Fixtures('it-apiclaw');
const clock = new Clock();
let sims: RunningSimulators;
let comps: MailboxComponents;
let org: TestOrg;
let conn: TestConnection;
let sourceId: bigint;
const ALEX = `alex@${MS_DOMAIN}`;
const BLAKE = `blake@${MS_DOMAIN}`;
const CASEY = `casey@${MS_DOMAIN}`;
const FOLDER = 'Email Gateway Quarantine';
let scan = 30_000n;

/** An internal journal message (org sender) with a hard-blocked malware risk row. */
async function internal(
  recipients: string[],
  input: {
    messageId?: string;
    deliver?: boolean;
    from?: string;
    verdict?: 'malware' | 'clean';
  } = {},
) {
  const messageId = input.messageId ?? `${crypto.randomUUID()}@${MS_DOMAIN}`;
  const from = input.from ?? ALEX;
  const eml = syntheticEml({ messageId, from, to: recipients });
  const delivered = new Map<string, string>();
  if (input.deliver !== false) {
    for (const to of recipients.filter((r) => r.endsWith(`@${MS_DOMAIN}`))) {
      delivered.set(to, (await sims.deliver({ user: to, eml })).messageId);
    }
  }
  const message = await fx.journalCopy(org, sourceId, {
    eml,
    recipients,
    messageId,
    from,
    receivedAt: clock.now(),
  });
  scan += 1n;
  const malware = (input.verdict ?? 'malware') === 'malware';
  await riskRow(fx, org.id, message, {
    scanId: scan,
    level: malware ? 'critical' : 'none',
    verdict: malware ? 'malware' : 'clean',
    score: malware ? 990 : 10,
    hardBlocks: malware ? ['hb.malware_attachment'] : [],
  });
  const event = fx.copyScanned(org.id, message, {
    completedAt: clock.now(),
    verdict: malware ? 'malware' : 'clean',
    riskScore: malware ? 990 : 10,
    scanId: scan.toString(),
  });
  expect(await comps.copies.handle(event)).toBe('handled');
  return { message, messageId, delivered, copies: await copiesOf(fx, message.id) };
}

async function setInternalMail(enabled: boolean | null): Promise<void> {
  await fx.prisma.apiModeOrgSetting.deleteMany({ where: { organizationId: org.id } });
  if (enabled !== null) {
    await fx.prisma.apiModeOrgSetting.create({
      data: { organizationId: org.id, internalMailEnabled: enabled },
    });
  }
}

beforeAll(async () => {
  sims = await startSimulators({
    dataset: { microsoft: { directories: [microsoftDirectory(clock.now())] } },
    now: clock.ms,
  });
  sims.tokens.setGrant(
    MS_TENANT_ID,
    M365_MAILBOX_REMEDIATION_PROFILE.key,
    M365_MAILBOX_REMEDIATION_PROFILE.permissions,
  );
  const tokens = new SimAccessTokens(() => sims, clock);
  comps = fx.components(clawbackConfig(fx, sims), { clock, tokens });
  org = await fx.organization('internal');
  await fx.domain(org, MS_DOMAIN, 'api');
  conn = await fx.connection(org, 'microsoft_365', {
    tenantId: MS_TENANT_ID,
    domains: [MS_DOMAIN],
  });
  tokens.directories.set(conn.providerConnectionPublicId, MS_TENANT_ID);
  sourceId = await fx.journalSource(org, conn);
  expect((await comps.inventory!.run(conn.apiConnectionId)).result).toBe('ok');
});

beforeEach(async () => {
  await cancelOpenActions(fx, fx.organizationIds);
  await setInternalMail(null);
});

afterAll(async () => {
  await sims?.stop();
  await fx.cleanup();
});

describe('internal (east-west) journal mail (C8)', () => {
  it('records internal recipients per mailbox and remediates them (P1 move executed)', async () => {
    const sent = await internal([BLAKE, CASEY]);
    expect(sent.copies).toHaveLength(2);
    for (const copy of sent.copies) {
      expect(copy).toMatchObject({
        direction: 'internal',
        source: 'journal',
        status: 'scanned',
        remediationState: 'pending',
        remediationAction: 'move_quarantine',
      });
    }
    await drain(comps);
    for (const copy of await copiesOf(fx, sent.message.id)) {
      expect(copy.remediationState).toBe('remediated');
      const [action] = await actionsOfCopy(fx, copy.id);
      expect(action).toMatchObject({ trigger: 'policy', status: 'succeeded' });
    }
    for (const [to, id] of sent.delivered) {
      expect(messageLocation(sims.script, to, id)?.folder?.displayName).toBe(FOLDER);
    }
    // The sender is never a target (journal recipients only).
    expect(sent.copies.map((c) => c.mailboxId)).not.toContain(
      (await fx.prisma.apiMailbox.findFirstOrThrow({ where: { primaryAddress: ALEX } })).id,
    );
    // N1: journal copies are never delivered (no delivery event for the message).
    const outbox = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: org.id, aggregateId: sent.message.id.toString() },
      select: { eventType: true },
    });
    expect(outbox.filter((o) => o.eventType.startsWith('mail.delivery.'))).toHaveLength(0);
    const message = await fx.prisma.emailMessage.findFirstOrThrow({
      where: { id: sent.message.id },
    });
    expect(message.status).toBe('journaled');
    await comps.counters.flush(fx.organizationIds);
    const counters = await fx.prisma.apiModeCounter.findMany({
      where: { apiConnectionId: conn.apiConnectionId },
    });
    expect(counters.reduce((n, c) => n + c.internalCopies, 0)).toBeGreaterThanOrEqual(2);
  });

  it('a second journal report of the same internal message is a duplicate (no second row)', async () => {
    const first = await internal([BLAKE], { deliver: false, verdict: 'clean' });
    expect(first.copies).toHaveLength(1);
    const second = await internal([BLAKE], {
      messageId: first.messageId,
      deliver: false,
      verdict: 'clean',
    });
    expect(second.copies).toHaveLength(0);
    const blake = await fx.prisma.apiMailbox.findFirstOrThrow({ where: { primaryAddress: BLAKE } });
    const rows = await fx.prisma.apiMessageCopy.findMany({
      where: {
        organizationId: org.id,
        mailboxId: blake.id,
        messageIdHash: first.copies[0]!.messageIdHash,
      },
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.seenJournal).toBe(true);
  });

  it('internal mail disabled: journal recipients counted skipped_internal, feed copies skipped', async () => {
    await setInternalMail(false);
    const skipped = await internal([CASEY], { deliver: false });
    expect(skipped.copies).toHaveLength(0);
    // A feed copy of an internal message (recorded by the feed with direction internal) is
    // decided with `skip internal_mail_disabled` (C8.5).
    const feedMessage = await fx.journalCopy(org, sourceId, {
      eml: syntheticEml({ from: ALEX, to: [BLAKE] }),
      recipients: [BLAKE],
      messageId: `${crypto.randomUUID()}@${MS_DOMAIN}`,
      from: ALEX,
      receivedAt: clock.now(),
    });
    await fx.prisma.emailMessage.updateMany({
      where: { id: feedMessage.id },
      data: { ingestSource: 'mailbox_api' },
    });
    const blake = await fx.prisma.apiMailbox.findFirstOrThrow({ where: { primaryAddress: BLAKE } });
    await fx.prisma.$executeRaw`
      INSERT INTO api_message_copies
        (received_at, public_id, organization_id, api_connection_id, mailbox_id, message_id,
         source, seen_journal, seen_api, direction, status, created_at, updated_at)
      VALUES (${feedMessage.receivedAt}, ${crypto.randomUUID()}, ${org.id},
              ${conn.apiConnectionId}, ${blake.id}, ${feedMessage.id}, 'graph', 0, 1, 'internal',
              'pending', NOW(3), NOW(3))`;
    scan += 1n;
    await riskRow(fx, org.id, feedMessage, {
      scanId: scan,
      level: 'critical',
      verdict: 'malware',
      score: 990,
      hardBlocks: ['hb.malware_attachment'],
    });
    await comps.copies.handle(
      fx.copyScanned(org.id, feedMessage, {
        completedAt: clock.now(),
        ingestSource: 'mailbox_api',
        verdict: 'malware',
        riskScore: 990,
        scanId: scan.toString(),
      }),
    );
    const [feedCopy] = await copiesOf(fx, feedMessage.id);
    expect(feedCopy).toMatchObject({ direction: 'internal', remediationState: 'skipped' });
    expect((await actionsOfCopy(fx, feedCopy!.id))[0]).toMatchObject({
      status: 'skipped',
      reasonCode: 'internal_mail_disabled',
    });
    await comps.counters.flush(fx.organizationIds);
    const counters = await fx.prisma.apiModeCounter.findMany({
      where: { apiConnectionId: conn.apiConnectionId },
    });
    expect(counters.reduce((n, c) => n + c.skippedInternal, 0)).toBeGreaterThanOrEqual(1);
  });

  it('outbound-only messages are not recorded and discover no mailbox; mixed record internal only', async () => {
    const before = await fx.prisma.apiMailbox.count({ where: { organizationId: org.id } });
    const outbound = await internal(['partner@partner-org.example'], { deliver: false });
    expect(outbound.copies).toHaveLength(0);
    expect(await fx.prisma.apiMailbox.count({ where: { organizationId: org.id } })).toBe(before);
    const mixed = await internal([BLAKE, 'partner@partner-org.example'], {
      deliver: false,
      verdict: 'clean',
    });
    expect(mixed.copies).toHaveLength(1);
    expect(mixed.copies[0]).toMatchObject({ direction: 'internal' });
    // Inbound mail from an external sender keeps direction inbound.
    const inbound = await internal([CASEY], {
      deliver: false,
      verdict: 'clean',
      from: 'sender@sender.example',
    });
    expect(inbound.copies[0]).toMatchObject({ direction: 'inbound' });
  });
});
