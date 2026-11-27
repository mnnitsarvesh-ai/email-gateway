import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  googleCustomer,
  GS_ADMIN_EMAIL,
  GS_CUSTOMER_ID,
  GS_DOMAIN,
  messageLocation,
  startSimulators,
  syntheticEml,
  type RunningSimulators,
} from '@email-gateway/idp-adapters/testing';
import { REMEDIATION_PRESETS } from '@email-gateway/mailbox-api';
import { GOOGLE_MAILBOX_REMEDIATION_PROFILE } from '@email-gateway/provider-integrations';
import type { MailboxComponents } from '../src/components';
import { loadConnectionContext } from '../src/domain/connections';
import {
  Clock,
  Fixtures,
  SimAccessTokens,
  type TestConnection,
  type TestOrg,
} from './support/harness';
import {
  actionsOfCopy,
  cancelOpenActions,
  copiesOf,
  drain,
  policy,
  queueAdminAction,
  queueRestore,
  remediationConfig,
  riskRow,
} from './support/remediation';

/**
 * Design note 36 §9.3 (mailbox-worker, Google Workspace) against the in-process Gmail and
 * Directory simulators: the hidden quarantine label ensured once per mailbox, `modify` out of the
 * Inbox, Junk (`SPAM`) through the Strict preset with the entry on an alias recipient, soft delete
 * to Trash, the hard-delete fallback to Trash (`hard_delete_unsupported_provider`, no entry, no
 * `DELETE`), tag and remove_tag labels, and a self-service restore of a Junk entry (R10.3).
 * Gmail token subject = the mailbox. Synthetic `it-apirem-*` organizations only.
 */
const fx = new Fixtures('it-apirem');
const clock = new Clock();
let sims: RunningSimulators;
let tokens: SimAccessTokens;
let comps: MailboxComponents;
let org: TestOrg;
let conn: TestConnection;
let sourceId: bigint;
const LABEL = 'Email Gateway/Quarantine';
const TAG = 'Email Gateway: Suspicious';
const ALEX = `alex@${GS_DOMAIN}`;
const BLAKE = `blake@${GS_DOMAIN}`;
/** drew has Gmail disabled in the synthetic customer; gale is a plain mailbox. */
const GALE = `gale@${GS_DOMAIN}`;
const ERIN = `erin@${GS_DOMAIN}`;
const ERIN_ALIAS = `erin.alias@${GS_DOMAIN}`;
let scan = 5000n;

const labelPosts = () =>
  sims.script.calls({ simulator: 'gmail', method: 'POST', path: /\/labels$/ }).length;

async function journal(
  c: MailboxComponents,
  to: string,
  input: {
    verdict: 'malware' | 'phishing' | 'suspicious' | 'spam';
    hardBlocks?: string[];
    deliverTo?: string;
  },
) {
  const messageId = `${crypto.randomUUID()}@sender.example`;
  const eml = syntheticEml({ messageId, to: [to] });
  const delivered = (await sims.deliver({ user: input.deliverTo ?? to, eml })).messageId;
  const message = await fx.journalCopy(org, sourceId, {
    eml,
    recipients: [to],
    messageId,
    from: 'sender@sender.example',
    receivedAt: clock.now(),
  });
  scan += 1n;
  await riskRow(fx, org.id, message, {
    scanId: scan,
    level: input.hardBlocks ? 'critical' : 'medium',
    verdict: input.verdict,
    score: input.hardBlocks ? 990 : 500,
    hardBlocks: input.hardBlocks ?? [],
  });
  await c.copies.handle(
    fx.copyScanned(org.id, message, {
      completedAt: clock.now(),
      verdict: input.verdict,
      riskScore: input.hardBlocks ? 990 : 500,
      scanId: scan.toString(),
    }),
  );
  const [copy] = await copiesOf(fx, message.id);
  return { message, copy: copy!, delivered, messageId };
}

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
  comps = fx.components(remediationConfig(fx, sims), { clock, tokens });
  org = await fx.organization('gmail');
  await fx.domain(org, GS_DOMAIN, 'api');
  conn = await fx.connection(org, 'google_workspace', {
    tenantId: GS_CUSTOMER_ID,
    domains: [GS_DOMAIN],
    subjectEmail: GS_ADMIN_EMAIL,
  });
  tokens.directories.set(conn.providerConnectionPublicId, GS_CUSTOMER_ID);
  sourceId = await fx.journalSource(org, conn, 'google_workspace_copy');
  expect((await comps.inventory!.run(conn.apiConnectionId)).result).toBe('ok');
});

beforeEach(async () => {
  await cancelOpenActions(fx, fx.organizationIds);
  await fx.prisma.apiRemediationPolicy.deleteMany({ where: { organizationId: org.id } });
  comps.policies.invalidate();
});

afterAll(async () => {
  await sims?.stop();
  await fx.cleanup();
});

describe('remediate role on Gmail (R3, R5.4)', () => {
  it('ensures the hidden quarantine label once per mailbox and moves the message out of the Inbox', async () => {
    const first = await journal(comps, ALEX, {
      verdict: 'malware',
      hardBlocks: ['hb.malware_attachment'],
    });
    expect(first.copy.remediationState).toBe('pending');
    const before = labelPosts();
    await drain(comps);
    const [action] = await actionsOfCopy(fx, first.copy.id);
    expect(action).toMatchObject({ status: 'succeeded', reasonCode: null });
    expect(action!.providerRefs).toEqual({
      before: [first.delivered],
      after: [first.delivered],
      container: 'quarantine_folder',
    });
    const location = messageLocation(sims.script, ALEX, first.delivered)!;
    expect(location.labelIds).not.toContain('INBOX');
    expect(location.labelNames).toEqual([LABEL]);
    expect(labelPosts()).toBe(before + 1);
    const mailbox = await fx.prisma.apiMailbox.findFirstOrThrow({
      where: { organizationId: org.id, primaryAddress: ALEX },
    });
    expect(mailbox.quarantineContainerId).not.toBeNull();
    expect(location.labelIds).toContain(mailbox.quarantineContainerId);
    const ctx = await loadConnectionContext(fx.prisma, conn.apiConnectionId);
    const labels = await comps
      .runtime!.clientsFor(ctx!)
      .gmail!.listLabels(ALEX, AbortSignal.timeout(10_000));
    expect(labels.find((l) => l.name === LABEL)).toMatchObject({
      labelListVisibility: 'labelHide',
      messageListVisibility: 'hide',
    });
    // The copy's provider id is the located Gmail id (journal copies have none at first).
    expect(
      (await fx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id: first.copy.id } }))
        .providerMessageId,
    ).toBe(first.delivered);
    const entry = await fx.prisma.quarantineMessage.findFirstOrThrow({
      where: { apiCopyId: first.copy.id },
    });
    expect(entry).toMatchObject({
      location: 'mailbox',
      mailboxContainer: 'quarantine_folder',
      status: 'held',
    });
    // Token subject = the mailbox.
    expect(tokens.requests.some((r) => r.subject === ALEX)).toBe(true);

    const second = await journal(comps, ALEX, {
      verdict: 'phishing',
      hardBlocks: ['hb.known_phishing'],
    });
    await drain(comps);
    expect((await actionsOfCopy(fx, second.copy.id))[0]!.status).toBe('succeeded');
    expect(labelPosts()).toBe(before + 1);
  });

  it('moves spam to Junk with the Strict preset; the entry carries the alias recipient', async () => {
    await policy(fx, org.id, 'enforce', REMEDIATION_PRESETS.strict.document);
    const spam = await journal(comps, ERIN_ALIAS, { verdict: 'spam', deliverTo: ERIN });
    const [pending] = await actionsOfCopy(fx, spam.copy.id);
    expect(pending).toMatchObject({ action: 'move_junk', status: 'pending' });
    await drain(comps);
    expect(messageLocation(sims.script, ERIN, spam.delivered)!.labelIds).toContain('SPAM');
    expect(messageLocation(sims.script, ERIN, spam.delivered)!.labelIds).not.toContain('INBOX');
    const entry = await fx.prisma.quarantineMessage.findFirstOrThrow({
      where: { apiCopyId: spam.copy.id },
    });
    expect(entry).toMatchObject({
      mailboxContainer: 'junk',
      reason: 'spam',
      recipientAddress: ERIN_ALIAS,
      explanationText:
        'Removed from the mailbox by the API-mode remediation policy (rule strict-spam-junk)',
    });

    // Self-service restore of the Junk entry (R10.3): back in the Inbox, entry released.
    const { releaseLogId, actionId } = await queueRestore(fx, {
      entryId: entry.id,
      mode: 'self',
      now: clock.now(),
    });
    await drain(comps);
    const restore = await fx.prisma.apiRemediationAction.findUniqueOrThrow({
      where: { id: actionId },
    });
    expect(restore).toMatchObject({ status: 'succeeded', trigger: 'end_user' });
    const location = messageLocation(sims.script, ERIN, spam.delivered)!;
    expect(location.labelIds).toContain('INBOX');
    expect(location.labelIds).not.toContain('SPAM');
    expect(
      await fx.prisma.quarantineMessage.findUniqueOrThrow({ where: { id: entry.id } }),
    ).toMatchObject({
      status: 'released',
      terminalReason: 'released',
    });
    expect(
      (await fx.prisma.quarantineReleaseLog.findUniqueOrThrow({ where: { id: releaseLogId } }))
        .status,
    ).toBe('restored');
  });

  it('soft-deletes to Trash on an admin request (entry deleted_items)', async () => {
    const msg = await journal(comps, BLAKE, { verdict: 'spam' });
    expect(await actionsOfCopy(fx, msg.copy.id)).toHaveLength(0);
    await queueAdminAction(fx, msg.copy.id, 'soft_delete', clock.now());
    await drain(comps);
    expect(messageLocation(sims.script, BLAKE, msg.delivered)!.labelIds).toContain('TRASH');
    const entry = await fx.prisma.quarantineMessage.findFirstOrThrow({
      where: { apiCopyId: msg.copy.id },
    });
    expect(entry).toMatchObject({
      mailboxContainer: 'deleted_items',
      explanationText: 'Removed from the mailbox by an API-mode remediation.',
    });
  });

  it('falls back to Trash for a hard delete (hard_delete_unsupported_provider, no entry, no DELETE)', async () => {
    const hd = fx.components(
      remediationConfig(fx, sims, { API_MODE_HARD_DELETE_ENABLED: 'true' }),
      {
        clock,
        tokens,
      },
    );
    await policy(fx, org.id, 'enforce', {
      v: 1,
      rules: [{ id: 'purge-malware', when: { verdicts: ['malware'] }, action: 'hard_delete' }],
    });
    const msg = await journal(hd, GALE, {
      verdict: 'malware',
      hardBlocks: ['hb.malware_attachment'],
    });
    const [decided] = await actionsOfCopy(fx, msg.copy.id);
    expect(decided).toMatchObject({ action: 'hard_delete', status: 'pending' });
    expect(decided!.decision).toMatchObject({ notes: ['hard_delete_falls_back_to_trash'] });
    await drain(hd);
    const [action] = await actionsOfCopy(fx, msg.copy.id);
    expect(action).toMatchObject({
      status: 'succeeded',
      action: 'hard_delete',
      reasonCode: 'hard_delete_unsupported_provider',
    });
    expect(action!.providerRefs).toMatchObject({ container: 'deleted_items' });
    const location = messageLocation(sims.script, GALE, msg.delivered)!;
    expect(location).toMatchObject({ state: 'present' });
    expect(location.labelIds).toContain('TRASH');
    expect(sims.script.calls({ simulator: 'gmail', method: 'DELETE' })).toHaveLength(0);
    expect(await fx.prisma.quarantineMessage.count({ where: { apiCopyId: msg.copy.id } })).toBe(0);
    expect(
      (await fx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id: msg.copy.id } }))
        .remediationAction,
    ).toBe('hard_delete');

    // A pending hard delete is cancelled by a worker without the setting (R-I2, re-checked).
    const queued = await journal(hd, GALE, { verdict: 'malware' });
    await drain(comps);
    expect((await actionsOfCopy(fx, queued.copy.id))[0]).toMatchObject({
      status: 'cancelled',
      reasonCode: 'hard_delete_disabled',
    });
    expect(messageLocation(sims.script, GALE, queued.delivered)!.labelIds).toContain('INBOX');

    // Without the platform setting the same rule is skipped at decision time.
    const off = await journal(comps, GALE, { verdict: 'malware' });
    expect((await actionsOfCopy(fx, off.copy.id))[0]).toMatchObject({
      status: 'skipped',
      reasonCode: 'hard_delete_disabled',
    });
  });

  it('adds the tag label and removes it again', async () => {
    const msg = await journal(comps, BLAKE, { verdict: 'suspicious' });
    await drain(comps);
    const [tag] = await actionsOfCopy(fx, msg.copy.id);
    expect(tag).toMatchObject({ action: 'tag', status: 'succeeded' });
    let location = messageLocation(sims.script, BLAKE, msg.delivered)!;
    expect(location.labelNames).toContain(TAG);
    expect(location.labelIds).toContain('INBOX');
    await queueAdminAction(fx, msg.copy.id, 'remove_tag', clock.now(), tag!.id);
    await drain(comps);
    location = messageLocation(sims.script, BLAKE, msg.delivered)!;
    expect(location.labelNames).not.toContain(TAG);
    expect((await actionsOfCopy(fx, msg.copy.id)).map((a) => a.status)).toEqual([
      'succeeded',
      'succeeded',
    ]);
  });
});
