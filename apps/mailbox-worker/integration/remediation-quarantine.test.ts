import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  messageLocation,
  microsoftDirectory,
  MS_DOMAIN,
  MS_TENANT_ID,
  removeMessage,
  startSimulators,
  syntheticEml,
  type RunningSimulators,
} from '@email-gateway/idp-adapters/testing';
import { remediationActionKey } from '@email-gateway/mailbox-api';
import { M365_MAILBOX_REMEDIATION_PROFILE } from '@email-gateway/provider-integrations';
import type { MailboxComponents } from '../src/components';
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
  queueAdminAction,
  queueRestore,
  remediationConfig,
  riskRow,
} from './support/remediation';

/**
 * Design note 36 §9.3 (mailbox-worker part of R9–R11, R14): mailbox-located quarantine entries
 * released as a restore to the Inbox (entry `released`, release log `restored`, generation + 1,
 * a re-remediation with a fresh key and entry round), a failed restore back to `held`
 * (`restore_failed`), the approved-mode re-check (new `release_approval` request, refusal), a
 * restore whose entry left `releasing` (`stale`), an entry delete's soft delete, the expiry of
 * mailbox entries by the health leader without a mailbox change or lifecycle edge, the four
 * `remediation.*` health checks with the `api_mode_unhealthy` alert, and the retention prune.
 * Graph simulator; synthetic `it-apirem-*` organizations only.
 */
const fx = new Fixtures('it-apirem');
const clock = new Clock();
let sims: RunningSimulators;
let comps: MailboxComponents;
let org: TestOrg;
let conn: TestConnection;
let sourceId: bigint;
const FOLDER = 'Email Gateway Quarantine';
const USERS = ['alex', 'blake', 'casey', 'drew', 'erin'].map((u) => `${u}@${MS_DOMAIN}`);
let scan = 9000n;
let next = 0;

/** A hard-blocked malware journal copy delivered to a mailbox and moved to the quarantine folder. */
async function quarantined(options: { hardBlocks?: string[] } = {}) {
  const to = USERS[next++ % USERS.length]!;
  const messageId = `${crypto.randomUUID()}@sender.example`;
  const eml = syntheticEml({ messageId, to: [to] });
  const delivered = (await sims.deliver({ user: to, eml })).messageId;
  const message = await fx.journalCopy(org, sourceId, {
    eml,
    recipients: [to],
    messageId,
    from: 'sender@sender.example',
    receivedAt: clock.now(),
  });
  scan += 1n;
  const hardBlocks = options.hardBlocks ?? ['hb.malware_attachment'];
  await riskRow(fx, org.id, message, {
    scanId: scan,
    level: 'critical',
    verdict: 'malware',
    score: 990,
    hardBlocks,
  });
  await comps.copies.handle(
    fx.copyScanned(org.id, message, {
      completedAt: clock.now(),
      verdict: 'malware',
      riskScore: 990,
      scanId: scan.toString(),
    }),
  );
  await drain(comps);
  const [copy] = await copiesOf(fx, message.id);
  const [action] = await actionsOfCopy(fx, copy!.id);
  expect(action!.status).toBe('succeeded');
  const entry = await fx.prisma.quarantineMessage.findFirstOrThrow({
    where: { apiCopyId: copy!.id },
  });
  return { to, copy: copy!, action: action!, entry, delivered, messageId };
}

const entryOf = (id: bigint) => fx.prisma.quarantineMessage.findUniqueOrThrow({ where: { id } });
const logOf = (id: bigint) => fx.prisma.quarantineReleaseLog.findUniqueOrThrow({ where: { id } });
const actionRow = (id: bigint) =>
  fx.prisma.apiRemediationAction.findUniqueOrThrow({ where: { id } });
const entryActions = async (entryId: bigint) =>
  (
    await fx.prisma.quarantineAction.findMany({
      where: { quarantineMessageId: entryId },
      orderBy: { id: 'asc' },
    })
  ).map((a) => [a.action, a.result]);

async function quarantineSettings(settings: Record<string, unknown>): Promise<void> {
  await fx.prisma.quarantineSettings.upsert({
    where: { organizationId: org.id },
    create: { organizationId: org.id, settings: settings as never, settingsSha256: 'c'.repeat(64) },
    update: { settings: settings as never },
  });
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
  comps = fx.components(
    remediationConfig(fx, sims, { API_MODE_REMEDIATION_LOCATE_ATTEMPTS: '2' }),
    { clock, tokens },
  );
  org = await fx.organization('quarantine');
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
  await fx.prisma.quarantineSettings.deleteMany({ where: { organizationId: org.id } });
});

afterAll(async () => {
  await sims?.stop();
  await fx.cleanup();
});

describe('release of a mailbox entry = restore to the Inbox (R10.3)', () => {
  it('restores, releases the entry, advances the generation, and a re-remediation gets a new key', async () => {
    const q = await quarantined();
    expect(q.entry).toMatchObject({ status: 'held', lifecycleRound: 0 });
    const { releaseLogId, actionId } = await queueRestore(fx, {
      entryId: q.entry.id,
      mode: 'operator',
      now: clock.now(),
    });
    await drain(comps);
    const restore = await actionRow(actionId);
    expect(restore).toMatchObject({
      status: 'succeeded',
      action: 'restore_inbox',
      trigger: 'release',
      reversesActionId: q.action.id,
    });
    expect(restore.providerRefs).toMatchObject({ container: 'inbox' });
    const location = messageLocation(sims.script, q.to, q.delivered)!;
    expect(location.folder!.wellKnownName).toBe('inbox');
    expect(await entryOf(q.entry.id)).toMatchObject({
      status: 'released',
      terminalReason: 'released',
      decidedByType: 'user',
    });
    expect((await entryOf(q.entry.id)).releasedAt).not.toBeNull();
    expect(await logOf(releaseLogId)).toMatchObject({ status: 'restored', blockedReason: null });
    expect(await entryActions(q.entry.id)).toEqual([
      ['mailbox_remediated', 'held'],
      ['release', 'queued'],
      ['mailbox_restored', 'restored'],
    ]);
    expect((await actionRow(q.action.id)).reversedByActionId).toBe(actionId);
    const copy = await fx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id: q.copy.id } });
    expect(copy).toMatchObject({
      remediationState: 'restored',
      remediationGeneration: 1,
      lastActionId: actionId,
      providerMessageId: location.currentId,
    });
    // No delivery or lifecycle change for a copy (N1 as amended by ADR-0102).
    expect(
      (await fx.prisma.emailMessage.findFirstOrThrow({ where: { id: q.copy.messageId } })).status,
    ).toBe('journaled');
    expect(
      await fx.prisma.messageOutbox.count({
        where: { organizationId: org.id, eventType: 'mail.quarantine.release_requested.v1' },
      }),
    ).toBe(0);

    // A later remediation of the same copy is a new generation: fresh key, new entry round.
    const again = await queueAdminAction(fx, q.copy.id, 'move_quarantine', clock.now());
    expect((await actionRow(again)).actionKey).toBe(
      remediationActionKey(q.copy.publicId, 'move_quarantine', 1),
    );
    await drain(comps);
    expect(await actionRow(again)).toMatchObject({ status: 'succeeded', generation: 1 });
    const entries = await fx.prisma.quarantineMessage.findMany({
      where: { apiCopyId: q.copy.id },
      orderBy: { id: 'asc' },
    });
    expect(entries.map((e) => [e.lifecycleRound, e.status])).toEqual([
      [0, 'released'],
      [1, 'held'],
    ]);
    expect(messageLocation(sims.script, q.to, q.delivered)!.folder!.displayName).toBe(FOLDER);
  });

  it('a restore that cannot find the message fails: entry back to held, log restore_failed', async () => {
    const q = await quarantined();
    const current = messageLocation(sims.script, q.to, q.delivered)!.currentId!;
    expect(removeMessage(sims.script, q.to, current)).toBe(true);
    const { releaseLogId, actionId } = await queueRestore(fx, {
      entryId: q.entry.id,
      mode: 'operator',
      now: clock.now(),
    });
    await drain(comps);
    expect(await actionRow(actionId)).toMatchObject({ status: 'pending', locateAttempts: 1 });
    expect((await entryOf(q.entry.id)).status).toBe('releasing');
    clock.advance(61_000);
    await drain(comps);
    expect(await actionRow(actionId)).toMatchObject({
      status: 'failed',
      reasonCode: 'message_not_found',
    });
    expect((await entryOf(q.entry.id)).status).toBe('held');
    expect(await logOf(releaseLogId)).toMatchObject({
      status: 'restore_failed',
      blockedReason: 'message_not_found',
    });
    expect((await entryActions(q.entry.id)).at(-1)).toEqual([
      'mailbox_restore_failed',
      'message_not_found',
    ]);
    const copy = await fx.prisma.apiMessageCopy.findFirstOrThrow({ where: { id: q.copy.id } });
    expect(copy).toMatchObject({ remediationState: 'remediated', remediationGeneration: 0 });
    await comps.counters.flush(fx.organizationIds);
    const counters = await fx.prisma.apiModeCounter.findMany({
      where: { apiConnectionId: conn.apiConnectionId },
    });
    expect(counters.reduce((n, c) => n + c.restoresFailed, 0)).toBe(1);
  });

  it('re-checks an approved restore: uncovered reasons → new approval request; covered → restored', async () => {
    await quarantineSettings({
      release: { allowHardBlocks: true },
      approvals: { requestTtlHours: 24 },
    });
    const uncovered = await quarantined();
    const queued = await queueRestore(fx, {
      entryId: uncovered.entry.id,
      mode: 'approved',
      now: clock.now(),
      approval: { reasons: ['scan_failed'], approved: ['scan_failed'] },
    });
    const calls = sims.script.calls({ simulator: 'graph' }).length;
    await drain(comps);
    expect(await actionRow(queued.actionId)).toMatchObject({
      status: 'cancelled',
      reasonCode: 'approval_required',
    });
    expect(sims.script.calls({ simulator: 'graph' }).length).toBe(calls);
    const entry = await entryOf(uncovered.entry.id);
    expect(entry.status).toBe('pending_approval');
    const request = await fx.prisma.quarantineApprovalRequest.findUniqueOrThrow({
      where: { id: entry.approvalRequestId! },
    });
    expect(request).toMatchObject({ kind: 'release_approval', status: 'pending' });
    expect(request.approvalReasons).toEqual(['hard_block']);
    expect(request.expiresAt.getTime()).toBe(clock.ms() + 24 * 3_600_000);
    expect(await logOf(queued.releaseLogId)).toMatchObject({
      status: 'approval_required',
      approvalRequestId: request.id,
    });
    expect((await entryActions(entry.id)).at(-1)).toEqual(['release_blocked', 'approval_required']);
    expect(
      messageLocation(sims.script, uncovered.to, uncovered.delivered)!.folder!.displayName,
    ).toBe(FOLDER);

    const covered = await quarantined();
    const ok = await queueRestore(fx, {
      entryId: covered.entry.id,
      mode: 'approved',
      now: clock.now(),
      approval: { reasons: ['hard_block'], approved: ['hard_block'] },
    });
    await drain(comps);
    expect((await actionRow(ok.actionId)).status).toBe('succeeded');
    expect((await entryOf(covered.entry.id)).status).toBe('released');
    expect((await logOf(ok.releaseLogId)).status).toBe('restored');
  });

  it('refuses an approved restore when hard-block releases are disabled', async () => {
    const q = await quarantined();
    await quarantineSettings({ release: { allowHardBlocks: false } });
    const queued = await queueRestore(fx, {
      entryId: q.entry.id,
      mode: 'approved',
      now: clock.now(),
      approval: { reasons: ['hard_block'], approved: ['hard_block'] },
    });
    await drain(comps);
    expect(await actionRow(queued.actionId)).toMatchObject({
      status: 'cancelled',
      reasonCode: 'refused',
    });
    expect((await entryOf(q.entry.id)).status).toBe('held');
    expect(await logOf(queued.releaseLogId)).toMatchObject({
      status: 'refused',
      blockedReason: 'quarantine_hard_block_release_disabled',
    });
  });

  it('cancels a restore whose entry left releasing (log stale) and leaves the mailbox alone', async () => {
    const q = await quarantined();
    const queued = await queueRestore(fx, {
      entryId: q.entry.id,
      mode: 'operator',
      now: clock.now(),
    });
    await fx.prisma.quarantineMessage.update({
      where: { id: q.entry.id },
      data: { status: 'rejected', rowVersion: { increment: 1 } },
    });
    await drain(comps);
    expect(await actionRow(queued.actionId)).toMatchObject({
      status: 'cancelled',
      reasonCode: 'entry_not_releasing',
    });
    expect(await logOf(queued.releaseLogId)).toMatchObject({ status: 'stale' });
    expect((await entryOf(q.entry.id)).status).toBe('rejected');
    expect(messageLocation(sims.script, q.to, q.delivered)!.folder!.displayName).toBe(FOLDER);
  });

  it("an entry delete's soft delete completes without changing the entry (R10.4)", async () => {
    const q = await quarantined();
    await fx.prisma.quarantineMessage.update({
      where: { id: q.entry.id },
      data: { status: 'deleted', terminalReason: 'deleted', rowVersion: { increment: 1 } },
    });
    const id = await queueAdminAction(fx, q.copy.id, 'soft_delete', clock.now());
    await fx.prisma.apiRemediationAction.update({
      where: { id },
      data: { quarantineEntryId: q.entry.id },
    });
    await drain(comps);
    expect((await actionRow(id)).status).toBe('succeeded');
    expect(messageLocation(sims.script, q.to, q.delivered)!.folder!.wellKnownName).toBe(
      'recoverableitemsdeletions',
    );
    expect(await fx.prisma.quarantineMessage.count({ where: { apiCopyId: q.copy.id } })).toBe(1);
    expect((await entryOf(q.entry.id)).status).toBe('deleted');
  });
});

describe('health leader (R11.4, R14, §3.1)', () => {
  it('expires due mailbox entries without a mailbox change or lifecycle edge', async () => {
    const held = await quarantined();
    const waiting = await quarantined();
    const request = await fx.prisma.quarantineApprovalRequest.create({
      data: {
        organizationId: org.id,
        quarantineMessageId: waiting.entry.id,
        kind: 'release_approval',
        status: 'pending',
        approvalReasons: ['hard_block'],
        requestedByType: 'system',
        expiresAt: new Date(clock.ms() + 3_600_000),
      },
    });
    await fx.prisma.quarantineMessage.update({
      where: { id: waiting.entry.id },
      data: { status: 'pending_approval', approvalRequestId: request.id },
    });
    const past = new Date(clock.ms() - 1_000);
    await fx.prisma.quarantineMessage.updateMany({
      where: { id: { in: [held.entry.id, waiting.entry.id] } },
      data: { expiresAt: past },
    });
    const calls = sims.script.calls({ simulator: 'graph' }).length;
    const report = await comps.maintenance.runOnce();
    expect(report.mailboxEntriesExpired).toBe(2);
    for (const q of [held, waiting]) {
      expect(await entryOf(q.entry.id)).toMatchObject({
        status: 'expired',
        terminalReason: 'expired',
        decidedByType: 'system',
      });
      expect((await entryActions(q.entry.id)).at(-1)).toEqual(['expire', 'expired']);
      expect(messageLocation(sims.script, q.to, q.delivered)!.folder!.displayName).toBe(FOLDER);
      expect(
        (await fx.prisma.emailMessage.findFirstOrThrow({ where: { id: q.copy.messageId } })).status,
      ).toBe('journaled');
    }
    expect(
      (await fx.prisma.quarantineApprovalRequest.findUniqueOrThrow({ where: { id: request.id } }))
        .status,
    ).toBe('expired');
    expect(sims.script.calls({ simulator: 'graph' }).length).toBe(calls);
    expect((await comps.maintenance.runOnce()).mailboxEntriesExpired).toBe(0);
  });

  it('evaluates the four remediation checks and alerts api_mode_unhealthy on a failing rate', async () => {
    const health = async () => {
      await comps.health.runOnce();
      const row = await fx.prisma.apiModeConnection.findUniqueOrThrow({
        where: { id: conn.apiConnectionId },
      });
      const checks = new Map(
        (row.healthChecks as { checks: { code: string; status: string }[] }).checks.map((c) => [
          c.code,
          c.status,
        ]),
      );
      return { row, checks };
    };
    await fx.prisma.apiModeConnection.update({
      where: { id: conn.apiConnectionId },
      data: { healthStatus: 'unknown', healthAlertedAt: null },
    });
    await fx.prisma.messageOutbox.deleteMany({ where: { organizationId: org.id } });
    await fx.prisma.notificationAlertWindow.deleteMany({ where: { organizationId: org.id } });
    let h = await health();
    expect(h.checks.get('remediation.paused')).toBe('pass');
    expect(h.checks.get('remediation.access')).toBe('pass');
    expect(h.checks.get('remediation.backlog')).toBe('pass');

    // 40 failed against the successes of this suite's hour → fail (> 50 %).
    await fx.prisma.apiModeConnection.update({
      where: { id: conn.apiConnectionId },
      data: { healthStatus: 'healthy', healthAlertedAt: null },
    });
    await fx.prisma.notificationAlertWindow.deleteMany({ where: { organizationId: org.id } });
    await fx.prisma.messageOutbox.deleteMany({ where: { organizationId: org.id } });
    await comps.counters.add(conn.apiConnectionId, { remediation_failed: 40 });
    await comps.counters.flush(fx.organizationIds);
    h = await health();
    expect(h.checks.get('remediation.failures_1h')).toBe('fail');
    expect(h.row.healthStatus).toBe('failing');
    const audit = await fx.prisma.auditLog.findFirstOrThrow({
      where: { organizationId: org.id, action: 'api_mode.health_changed' },
      orderBy: { id: 'desc' },
    });
    expect((audit.metadata as { failingChecks: string[] }).failingChecks).toContain(
      'remediation.failures_1h',
    );
    const alerts = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: org.id, eventType: 'notification.alert_requested.v1' },
    });
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.payload).toMatchObject({ kind: 'api_mode_unhealthy' });

    // Paused → warn; an old pending admin action → backlog fail; no grant → access warn.
    await fx.prisma.apiModeConnection.update({
      where: { id: conn.apiConnectionId },
      data: { remediationPaused: true },
    });
    const q = await fx.prisma.apiMessageCopy.findFirstOrThrow({
      where: { organizationId: org.id, remediationState: 'remediated' },
    });
    const old = await queueAdminAction(fx, q.id, 'tag', clock.now());
    await fx.prisma.apiRemediationAction.update({
      where: { id: old },
      data: {
        createdAt: new Date(clock.ms() - 61 * 60_000),
        nextAttemptAt: new Date(clock.ms() + 86_400_000),
      },
    });
    await fx.prisma.providerConnectionGrant.update({
      where: { id: conn.grantId },
      data: { status: 'revoked' },
    });
    try {
      h = await health();
    } finally {
      await fx.prisma.providerConnectionGrant.update({
        where: { id: conn.grantId },
        data: { status: 'active' },
      });
      await fx.prisma.apiModeConnection.update({
        where: { id: conn.apiConnectionId },
        data: { remediationPaused: false },
      });
    }
    // The leader's gauges: api_mode_remediation_backlog / _oldest_pending_seconds{provider}.
    const backlog = await comps.health.remediationBacklog(clock.now());
    expect(backlog.get('microsoft_365')!.count).toBe(1);
    expect(backlog.get('microsoft_365')!.oldestSeconds).toBeGreaterThanOrEqual(61 * 60);
    expect(backlog.get('google_workspace')).toEqual({ count: 0, oldestSeconds: 0 });
    expect(h.checks.get('remediation.paused')).toBe('warn');
    expect(h.checks.get('remediation.backlog')).toBe('fail');
    expect(h.checks.get('remediation.access')).toBe('warn');
  });

  it('prunes terminal actions past the retention whose entry is terminal or absent', async () => {
    const released = await quarantined();
    const { actionId } = await queueRestore(fx, {
      entryId: released.entry.id,
      mode: 'operator',
      now: clock.now(),
    });
    await drain(comps);
    expect((await entryOf(released.entry.id)).status).toBe('released');
    const kept = await quarantined();
    const recent = await quarantined();
    const old = new Date(clock.ms() - 401 * 86_400_000);
    await fx.prisma.apiRemediationAction.updateMany({
      where: { id: { in: [released.action.id, actionId, kept.action.id] } },
      data: { completedAt: old },
    });
    const report = await comps.maintenance.runOnce();
    expect(report.remediationActions).toBeGreaterThanOrEqual(2);
    expect(
      await fx.prisma.apiRemediationAction.count({
        where: { id: { in: [released.action.id, actionId] } },
      }),
    ).toBe(0);
    // A held entry keeps its action; recent actions are kept.
    expect(await fx.prisma.apiRemediationAction.count({ where: { id: kept.action.id } })).toBe(1);
    expect(await fx.prisma.apiRemediationAction.count({ where: { id: recent.action.id } })).toBe(1);
  });
});
