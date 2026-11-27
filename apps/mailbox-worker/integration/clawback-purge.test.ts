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
import { subjectKeyOf } from '@email-gateway/mailbox-api';
import { M365_MAILBOX_REMEDIATION_PROFILE } from '@email-gateway/provider-integrations';
import type { MailboxComponents } from '../src/components';
import { claimDueActions } from '../src/remediation/claims';
import {
  adminClawback,
  approve,
  clawbackConfig,
  requestCancel,
  settle,
  submit,
  user,
} from './support/clawback';
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
  queueRestore,
  riskRow,
} from './support/remediation';

/**
 * Design note 37 §9.3 (mailbox-worker, search and purge; C4–C6, ADR-0103): an admin search by
 * Message-ID → `ready` → submit below the threshold → `queued` → executed (Junk, entries
 * `manual`, `trigger = purge`); above the threshold → `pending_approval` → the requester and an
 * API key cannot approve → a second user approves → executed; approval expiry; cancel mid-run
 * (pending actions cancelled, the in-progress one finishes); `too_broad` and `no_match`;
 * escalation (tag → move), `already_remediated`, `restored_after_signal` and the re-arm of a
 * skipped policy row; the per-connection pending cap. The api's writes (create, submit, approve,
 * cancel) are mimicked with the same pure rules. Synthetic `it-apiclaw-*` organizations only.
 */
const fx = new Fixtures('it-apiclaw');
const clock = new Clock();
const S = fx.suffix;
let sims: RunningSimulators;
let comps: MailboxComponents;
let small: MailboxComponents;
let capped: MailboxComponents;
let org: TestOrg;
let conn: TestConnection;
let sourceId: bigint;
let requester: { id: bigint; publicId: string };
let approver: { id: bigint; publicId: string };
const USERS = ['alex', 'blake', 'casey', 'drew', 'erin'].map((u) => `${u}@${MS_DOMAIN}`);
let scan = 50_000n;

/** One journal message to `recipients` (delivered), its risk row, handled by the copies role. */
async function journal(
  recipients: string[],
  input: {
    verdict?: 'clean' | 'malware' | 'suspicious';
    from?: string;
    deliver?: boolean;
  } = {},
) {
  const messageId = `${crypto.randomUUID()}@sender.example`;
  const eml = syntheticEml({ messageId, to: recipients });
  const delivered = new Map<string, string>();
  if (input.deliver !== false) {
    for (const to of recipients)
      delivered.set(to, (await sims.deliver({ user: to, eml })).messageId);
  }
  const message = await fx.journalCopy(org, sourceId, {
    eml,
    recipients,
    messageId,
    from: input.from ?? 'sender@sender.example',
    receivedAt: clock.now(),
  });
  const verdict = input.verdict ?? 'clean';
  scan += 1n;
  await riskRow(fx, org.id, message, {
    scanId: scan,
    level: verdict === 'malware' ? 'critical' : verdict === 'suspicious' ? 'medium' : 'none',
    verdict,
    score: verdict === 'malware' ? 990 : verdict === 'suspicious' ? 500 : 10,
    hardBlocks: verdict === 'malware' ? ['hb.malware_attachment'] : [],
  });
  await comps.copies.handle(
    fx.copyScanned(org.id, message, {
      completedAt: clock.now(),
      verdict,
      riskScore: verdict === 'malware' ? 990 : verdict === 'suspicious' ? 500 : 10,
      scanId: scan.toString(),
    }),
  );
  const copies = await copiesOf(fx, message.id);
  return { message, messageId, delivered, copies, hash: copies[0]?.messageIdHash ?? null };
}

const reload = (id: bigint) => fx.prisma.apiClawback.findUniqueOrThrow({ where: { id } });
const targetsOf = (clawbackId: bigint) =>
  fx.prisma.apiClawbackTarget.findMany({ where: { clawbackId }, orderBy: { id: 'asc' } });

/** Materializes a freshly created clawback (one claim). */
async function materialize(c: MailboxComponents, id: bigint) {
  clock.advance(c.config.API_MODE_CLAWBACK_TICK_MS + 1);
  await c.clawback.tick();
  return reload(id);
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
  small = fx.components(
    clawbackConfig(fx, sims, {
      API_MODE_CLAWBACK_MAX_TARGETS: '4',
      API_MODE_CLAWBACK_QUEUE_BATCH: '4',
    }),
    { clock, tokens },
  );
  capped = fx.components(
    clawbackConfig(fx, sims, { API_MODE_CLAWBACK_MAX_PENDING_PER_CONNECTION: '2' }),
    { clock, tokens },
  );
  org = await fx.organization('purge');
  await fx.domain(org, MS_DOMAIN, 'api');
  conn = await fx.connection(org, 'microsoft_365', {
    tenantId: MS_TENANT_ID,
    domains: [MS_DOMAIN],
  });
  tokens.directories.set(conn.providerConnectionPublicId, MS_TENANT_ID);
  sourceId = await fx.journalSource(org, conn);
  expect((await comps.inventory!.run(conn.apiConnectionId)).result).toBe('ok');
  requester = await user(fx, org.id, `it-req-${S}@${MS_DOMAIN}`);
  approver = await user(fx, org.id, `it-appr-${S}@${MS_DOMAIN}`);
});

beforeEach(async () => {
  await cancelOpenActions(fx, fx.organizationIds);
  comps.policies.invalidate();
});

afterAll(async () => {
  await sims?.stop();
  await fx.cleanup();
});

describe('admin search and purge (C4, C5, C6)', () => {
  it('Message-ID search across 3 mailboxes → ready → submit move_junk below the threshold → executed', async () => {
    const sent = await journal(USERS.slice(0, 3));
    const created = await adminClawback(fx, org.id, {
      keys: { messageIdHashes: [sent.hash!] },
      now: clock.now(),
      requestedBy: requester.id,
    });
    const ready = await materialize(comps, created.id);
    expect(ready).toMatchObject({
      status: 'ready',
      targetsTotal: 3,
      targetsEligible: 3,
      mailboxesEligible: 3,
    });
    expect((await targetsOf(created.id)).every((t) => t.status === 'matched')).toBe(true);
    // A ready clawback waits for the submit (nothing is queued).
    await materialize(comps, created.id);
    expect(await fx.prisma.apiRemediationAction.count({ where: { clawbackId: created.id } })).toBe(
      0,
    );
    const submitted = await submit(fx, created.id, {
      mode: 'explicit',
      action: 'move_junk',
      submittedBy: requester.id,
      threshold: 50,
      now: clock.now(),
    });
    expect(submitted).toMatchObject({ status: 'queued', requiresApproval: false });
    await settle(comps, clock);
    expect(await reload(created.id)).toMatchObject({
      status: 'completed',
      targetsSucceeded: 3,
    });
    for (const t of await targetsOf(created.id)) {
      expect(t).toMatchObject({ status: 'succeeded', plannedAction: 'move_junk' });
      const action = await fx.prisma.apiRemediationAction.findUniqueOrThrow({
        where: { id: t.actionId! },
      });
      expect(action).toMatchObject({
        trigger: 'purge',
        action: 'move_junk',
        clawbackId: created.id,
        requestedByType: 'user',
        requestedByUserId: requester.id,
      });
      const entry = await fx.prisma.quarantineMessage.findFirstOrThrow({
        where: { apiRemediationActionId: action.id },
      });
      // An explicit purge of a clean copy → reason manual (C5.5).
      expect(entry).toMatchObject({ reason: 'manual', mailboxContainer: 'junk' });
      expect(entry.explanationText).toBe(
        `Removed from the mailbox by clawback ${created.publicId} (admin)`,
      );
    }
    for (const [to, id] of sent.delivered) {
      expect(messageLocation(sims.script, to, id)?.folder?.wellKnownName).toBe('junkemail');
    }
  });

  it('above the threshold → pending_approval; requester and API keys refused; a second user approves', async () => {
    const sent = await journal(USERS.slice(0, 3));
    const created = await adminClawback(fx, org.id, {
      keys: { messageIdHashes: [sent.hash!] },
      now: clock.now(),
      requestedBy: requester.id,
    });
    await materialize(comps, created.id);
    const pending = await submit(fx, created.id, {
      mode: 'explicit',
      action: 'soft_delete',
      submittedBy: requester.id,
      threshold: 2,
      now: clock.now(),
    });
    expect(pending).toMatchObject({
      status: 'pending_approval',
      approvalStatus: 'pending',
      requiresApproval: true,
    });
    expect(pending.approvalReasons).toEqual(['mailbox_threshold']);
    // Nothing is queued while the approval is pending.
    await settle(comps, clock, 3);
    expect(await fx.prisma.apiRemediationAction.count({ where: { clawbackId: created.id } })).toBe(
      0,
    );
    expect(await approve(fx, created.id, { userId: requester.id }, clock.now())).toMatchObject({
      allowed: false,
      reason: 'requester',
    });
    expect(
      await approve(fx, created.id, { userId: approver.id, type: 'api_key' }, clock.now()),
    ).toMatchObject({ allowed: false, reason: 'api_key' });
    expect(await approve(fx, created.id, { userId: approver.id }, clock.now())).toEqual({
      allowed: true,
    });
    await settle(comps, clock);
    expect(await reload(created.id)).toMatchObject({
      status: 'completed',
      approvalStatus: 'approved',
      approvedByUserId: approver.id,
      targetsSucceeded: 3,
    });
  });

  it('a pending approval expires (status expired, system audit)', async () => {
    const sent = await journal([USERS[3]!], { deliver: false });
    const created = await adminClawback(fx, org.id, {
      keys: { messageIdHashes: [sent.hash!] },
      now: clock.now(),
      requestedBy: requester.id,
    });
    await materialize(comps, created.id);
    await submit(fx, created.id, {
      mode: 'explicit',
      action: 'move_quarantine',
      submittedBy: requester.id,
      threshold: 0,
      ttlHours: 1,
      now: clock.now(),
    });
    clock.advance(2 * 3_600_000);
    await comps.clawback.tick();
    expect(await reload(created.id)).toMatchObject({
      status: 'expired',
      approvalStatus: 'expired',
    });
    const audit = await fx.prisma.auditLog.findFirstOrThrow({
      where: { organizationId: org.id, action: 'api_mode.clawback_expired' },
    });
    expect(audit).toMatchObject({ actorType: 'system', resourceId: created.publicId });
    expect(await approve(fx, created.id, { userId: approver.id }, clock.now())).toMatchObject({
      allowed: false,
      code: 'api_mode_purge_approval_not_pending',
    });
  });

  it('cancel mid-run: pending actions cancelled, the in-progress action finishes', async () => {
    const sent = await journal(USERS.slice(0, 3));
    const created = await adminClawback(fx, org.id, {
      keys: { messageIdHashes: [sent.hash!] },
      now: clock.now(),
      requestedBy: requester.id,
    });
    await materialize(comps, created.id);
    await submit(fx, created.id, {
      mode: 'explicit',
      action: 'move_junk',
      submittedBy: requester.id,
      threshold: 50,
      now: clock.now(),
    });
    await materialize(comps, created.id); // queues the three targets
    expect((await targetsOf(created.id)).map((t) => t.status)).toEqual([
      'queued',
      'queued',
      'queued',
    ]);
    const [claim] = await claimDueActions(fx.prisma, {
      now: clock.now(),
      batch: 1,
      leaseSeconds: 120,
      perConnection: 2,
      organizationIds: fx.organizationIds,
    });
    expect(claim).toBeDefined();
    await requestCancel(fx, created.id, clock.now());
    await materialize(comps, created.id);
    const actions = await fx.prisma.apiRemediationAction.findMany({
      where: { clawbackId: created.id },
      orderBy: { id: 'asc' },
    });
    expect(actions.map((a) => a.status).sort()).toEqual(['cancelled', 'cancelled', 'in_progress']);
    expect((await reload(created.id)).status).toBe('running');
    // The cancelled copies have their state recomputed (nothing queued anymore).
    for (const a of actions.filter((x) => x.status === 'cancelled')) {
      const [copy] = await fx.prisma.apiMessageCopy.findMany({ where: { id: a.copyId } });
      expect(copy!.remediationState).toBe('none');
    }
    expect(await comps.remediation!.execute(claim!)).toBe('succeeded');
    await materialize(comps, created.id);
    const done = await reload(created.id);
    expect(done).toMatchObject({
      status: 'cancelled',
      targetsSucceeded: 1,
      targetsCancelled: 2,
    });
  });

  it('too_broad above the target limit; no_match without a hit', async () => {
    const sender = `bulk-${S}@sender.example`;
    for (let i = 0; i < 5; i++) await journal([USERS[i]!], { from: sender, deliver: false });
    const broad = await adminClawback(fx, org.id, {
      keys: { senderSubject: { sender, subjectKey: subjectKeyOf('Synthetic journal copy') } },
      now: clock.now(),
      windowDays: 1,
      requestedBy: requester.id,
    });
    expect(await materialize(small, broad.id)).toMatchObject({
      status: 'too_broad',
      targetsTotal: 0,
    });
    expect(await targetsOf(broad.id)).toHaveLength(0);
    const none = await adminClawback(fx, org.id, {
      keys: { messageIdHashes: ['f'.repeat(64)] },
      now: clock.now(),
      requestedBy: requester.id,
    });
    expect(await materialize(comps, none.id)).toMatchObject({ status: 'no_match' });
  });
});

describe('target planning (C5.3) and queueing (C5.4)', () => {
  it('escalates a tag, keeps a stronger remediation, skips a copy restored after the signal, re-arms a skipped policy row', async () => {
    const tagged = await journal([USERS[0]!], { verdict: 'suspicious' });
    const quarantined = await journal([USERS[1]!], { verdict: 'malware' });
    const restored = await journal([USERS[2]!], { verdict: 'malware' });
    // Two in-flight actions per connection: three passes run all three.
    for (let i = 0; i < 3; i++) await drain(comps);
    expect((await copiesOf(fx, tagged.message.id))[0]).toMatchObject({
      remediationState: 'remediated',
      remediationAction: 'tag',
    });
    await fx.prisma.apiModeConnection.update({
      where: { id: conn.apiConnectionId },
      data: { remediationPaused: true },
    });
    const skipped = await journal([USERS[3]!], { verdict: 'malware' });
    await fx.prisma.apiModeConnection.update({
      where: { id: conn.apiConnectionId },
      data: { remediationPaused: false },
    });
    const [skippedRow] = await actionsOfCopy(fx, skipped.copies[0]!.id);
    expect(skippedRow).toMatchObject({ status: 'skipped', reasonCode: 'remediation_paused' });

    // The clawback's signal time is now; the restore below completes after it.
    const created = await adminClawback(fx, org.id, {
      keys: {
        messageIdHashes: [tagged.hash!, quarantined.hash!, restored.hash!, skipped.hash!],
      },
      now: clock.now(),
      requestedBy: requester.id,
    });
    clock.advance(1000);
    const entry = await fx.prisma.quarantineMessage.findFirstOrThrow({
      where: { apiCopyId: restored.copies[0]!.id },
    });
    await queueRestore(fx, { entryId: entry.id, mode: 'operator', now: clock.now() });
    await drain(comps);
    expect((await copiesOf(fx, restored.message.id))[0]!.remediationState).toBe('restored');

    await materialize(comps, created.id);
    await submit(fx, created.id, {
      mode: 'explicit',
      action: 'move_quarantine',
      submittedBy: requester.id,
      threshold: 50,
      now: clock.now(),
    });
    await settle(comps, clock);
    const byCopy = new Map((await targetsOf(created.id)).map((t) => [t.copyId, t]));
    expect(byCopy.get(tagged.copies[0]!.id)).toMatchObject({
      status: 'succeeded',
      plannedAction: 'move_quarantine',
    });
    expect(byCopy.get(quarantined.copies[0]!.id)).toMatchObject({
      status: 'skipped',
      reasonCode: 'already_remediated',
    });
    expect(byCopy.get(restored.copies[0]!.id)).toMatchObject({
      status: 'skipped',
      reasonCode: 'restored_after_signal',
    });
    const rearmed = byCopy.get(skipped.copies[0]!.id)!;
    expect(rearmed).toMatchObject({ status: 'succeeded', actionId: skippedRow!.id });
    expect(
      await fx.prisma.apiRemediationAction.findUniqueOrThrow({ where: { id: skippedRow!.id } }),
    ).toMatchObject({ status: 'succeeded', trigger: 'purge', clawbackId: created.id });
    // The tag stays (C-I3: escalation adds the move, it never replaces the history).
    const taggedActions = await actionsOfCopy(fx, tagged.copies[0]!.id);
    expect(taggedActions.map((a) => [a.action, a.status])).toEqual([
      ['tag', 'succeeded'],
      ['move_quarantine', 'succeeded'],
    ]);
    expect(await reload(created.id)).toMatchObject({
      status: 'completed',
      targetsSucceeded: 2,
      targetsSkipped: 2,
    });
  });

  it('never more than API_MODE_CLAWBACK_MAX_PENDING_PER_CONNECTION pending purge actions', async () => {
    const sent = await journal(USERS.slice(0, 3));
    const created = await adminClawback(fx, org.id, {
      keys: { messageIdHashes: [sent.hash!] },
      now: clock.now(),
      requestedBy: requester.id,
    });
    await materialize(capped, created.id);
    await submit(fx, created.id, {
      mode: 'explicit',
      action: 'move_junk',
      submittedBy: requester.id,
      threshold: 50,
      now: clock.now(),
    });
    await materialize(capped, created.id);
    expect((await targetsOf(created.id)).map((t) => t.status).sort()).toEqual([
      'matched',
      'queued',
      'queued',
    ]);
    await drain(capped);
    await materialize(capped, created.id);
    await settle(capped, clock);
    expect(await reload(created.id)).toMatchObject({ status: 'completed', targetsSucceeded: 3 });
  });
});
