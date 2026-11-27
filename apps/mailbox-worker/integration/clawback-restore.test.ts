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
import {
  adminClawback,
  approve,
  clawbackConfig,
  hex,
  lateSignal,
  messageUrl,
  requestRestore,
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
import { cancelOpenActions, copiesOf, riskRow } from './support/remediation';

/**
 * Design note 37 §9.3 (mailbox-worker, bulk restore; C7): a purge moved to the quarantine folder
 * restored to the Inbox through the R10.2 write sequence (release log `operator`, entry
 * `releasing` → `released`, `restore_inbox` with `trigger = release`, requested by the restoring
 * user), a tag reversed with `remove_tag`, a hard-blocked mailbox entry left for the quarantine
 * page (`approval_required`), a Graph hard delete `not_reversible`; restore reconcile and audit.
 * Synthetic `it-apiclaw-*` organizations only.
 */
const fx = new Fixtures('it-apiclaw');
const clock = new Clock();
const S = fx.suffix;
let sims: RunningSimulators;
let comps: MailboxComponents;
let hard: MailboxComponents;
let org: TestOrg;
let conn: TestConnection;
let sourceId: bigint;
let requester: { id: bigint; publicId: string };
let approver: { id: bigint; publicId: string };
let restorer: { id: bigint; publicId: string };
const USERS = ['alex', 'blake', 'casey', 'drew', 'erin'].map((u) => `${u}@${MS_DOMAIN}`);
const FOLDER = 'Email Gateway Quarantine';
let scan = 60_000n;

async function journal(recipients: string[], input: { urlSha256?: string } = {}) {
  const messageId = `${crypto.randomUUID()}@sender.example`;
  const eml = syntheticEml({ messageId, to: recipients });
  const delivered = new Map<string, string>();
  for (const to of recipients) delivered.set(to, (await sims.deliver({ user: to, eml })).messageId);
  const message = await fx.journalCopy(org, sourceId, {
    eml,
    recipients,
    messageId,
    from: 'sender@sender.example',
    receivedAt: clock.now(),
  });
  if (input.urlSha256) await messageUrl(fx, org.id, message, input.urlSha256);
  scan += 1n;
  await riskRow(fx, org.id, message, { scanId: scan, level: 'none', verdict: 'clean', score: 10 });
  await comps.copies.handle(
    fx.copyScanned(org.id, message, {
      completedAt: clock.now(),
      verdict: 'clean',
      riskScore: 10,
      scanId: scan.toString(),
    }),
  );
  const copies = await copiesOf(fx, message.id);
  return { message, delivered, copies, scanId: scan, hash: copies[0]!.messageIdHash! };
}

const reload = (id: bigint) => fx.prisma.apiClawback.findUniqueOrThrow({ where: { id } });
const targetsOf = (clawbackId: bigint) =>
  fx.prisma.apiClawbackTarget.findMany({ where: { clawbackId }, orderBy: { id: 'asc' } });

async function purge(
  c: MailboxComponents,
  hash: string,
  action: 'move_quarantine' | 'soft_delete' | 'hard_delete',
) {
  const created = await adminClawback(fx, org.id, {
    keys: { messageIdHashes: [hash] },
    now: clock.now(),
    requestedBy: requester.id,
  });
  clock.advance(c.config.API_MODE_CLAWBACK_TICK_MS + 1);
  await c.clawback.tick();
  const submitted = await submit(fx, created.id, {
    mode: 'explicit',
    action,
    submittedBy: requester.id,
    threshold: 50,
    now: clock.now(),
  });
  if (submitted.status === 'pending_approval') {
    expect(await approve(fx, created.id, { userId: approver.id }, clock.now())).toEqual({
      allowed: true,
    });
  }
  await settle(c, clock);
  return reload(created.id);
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
  hard = fx.components(clawbackConfig(fx, sims, { API_MODE_HARD_DELETE_ENABLED: 'true' }), {
    clock,
    tokens,
  });
  org = await fx.organization('restore');
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
  restorer = await user(fx, org.id, `it-rest-${S}@${MS_DOMAIN}`);
});

beforeEach(async () => {
  await cancelOpenActions(fx, fx.organizationIds);
});

afterAll(async () => {
  await sims?.stop();
  await fx.cleanup();
});

describe('bulk restore of a clawback (C7)', () => {
  it('a quarantine-folder purge is restored to the Inbox through the release sequence', async () => {
    const sent = await journal(USERS.slice(0, 2));
    const done = await purge(comps, sent.hash, 'move_quarantine');
    expect(done).toMatchObject({ status: 'completed', targetsSucceeded: 2 });
    for (const [to, id] of sent.delivered) {
      expect(messageLocation(sims.script, to, id)?.folder?.displayName).toBe(FOLDER);
    }
    await requestRestore(fx, done, restorer, clock.now());
    clock.advance(comps.config.API_MODE_CLAWBACK_TICK_MS + 1);
    await comps.clawback.tick();
    const queued = await targetsOf(done.id);
    expect(queued.map((t) => t.restoreStatus)).toEqual(['queued', 'queued']);
    for (const t of queued) {
      const restore = await fx.prisma.apiRemediationAction.findUniqueOrThrow({
        where: { id: t.restoreActionId! },
      });
      expect(restore).toMatchObject({
        action: 'restore_inbox',
        trigger: 'release',
        status: 'pending',
        reversesActionId: t.actionId,
        requestedByType: 'user',
        requestedByUserId: restorer.id,
        clawbackId: done.id,
      });
      const log = await fx.prisma.quarantineReleaseLog.findUniqueOrThrow({
        where: { id: restore.releaseLogId! },
      });
      expect(log).toMatchObject({
        mode: 'operator',
        status: 'pending',
        requestedByType: 'user',
        requestedById: restorer.publicId,
      });
      expect(
        await fx.prisma.quarantineMessage.findUniqueOrThrow({
          where: { id: restore.quarantineEntryId! },
        }),
      ).toMatchObject({ status: 'releasing' });
    }
    await settle(comps, clock);
    expect(await reload(done.id)).toMatchObject({
      restoreStatus: 'completed',
      restoresSucceeded: 2,
      restoresQueued: 0,
    });
    for (const t of await targetsOf(done.id)) {
      expect(t.restoreStatus).toBe('succeeded');
      const restore = await fx.prisma.apiRemediationAction.findUniqueOrThrow({
        where: { id: t.restoreActionId! },
      });
      expect(
        await fx.prisma.quarantineMessage.findUniqueOrThrow({
          where: { id: restore.quarantineEntryId! },
        }),
      ).toMatchObject({ status: 'released' });
    }
    for (const copy of await copiesOf(fx, sent.message.id)) {
      expect(copy).toMatchObject({ remediationState: 'restored', remediationGeneration: 1 });
    }
    for (const [to, id] of sent.delivered) {
      expect(messageLocation(sims.script, to, id)?.folder?.wellKnownName).toBe('inbox');
    }
    expect(
      await fx.prisma.auditLog.count({
        where: { organizationId: org.id, action: 'api_mode.clawback_restore_completed' },
      }),
    ).toBe(1);
  });

  it('a tag is reversed with remove_tag; a hard-blocked entry needs the quarantine approval', async () => {
    // URL dynamic `suspicious` → P1 tags the copy (C3.1).
    const urlHash = hex(`url-${S}`);
    const tagged = await journal([USERS[2]!], { urlSha256: urlHash });
    await comps.copies.handle(
      lateSignal(fx, org.id, {
        kind: 'url_dynamic',
        messageId: tagged.message.id.toString(),
        receivedAt: tagged.message.receivedAt.toISOString(),
        scanId: tagged.scanId.toString(),
        verdict: 'suspicious',
        level: 'high',
        hardBlocks: [],
        urlSha256: [urlHash],
        signalAt: clock.now(),
      }),
    );
    // Sandbox revision with a hard block → P1 moves; the entry carries the hard block.
    const blocked = await journal([USERS[3]!]);
    await riskRow(fx, org.id, blocked.message, {
      scanId: blocked.scanId,
      revision: 1,
      level: 'critical',
      verdict: 'malware',
      score: 990,
      hardBlocks: ['hb.malware_sandbox'],
    });
    await comps.copies.handle(
      lateSignal(fx, org.id, {
        messageId: blocked.message.id.toString(),
        receivedAt: blocked.message.receivedAt.toISOString(),
        scanId: blocked.scanId.toString(),
        signalAt: clock.now(),
      }),
    );
    await settle(comps, clock);
    const [tagClawback, blockClawback] = await fx.prisma.apiClawback.findMany({
      where: { organizationId: org.id, trigger: 'late_verdict' },
      orderBy: { id: 'asc' },
    });
    expect(tagClawback).toMatchObject({ status: 'completed', targetsSucceeded: 1 });
    expect((await targetsOf(tagClawback!.id))[0]).toMatchObject({ plannedAction: 'tag' });
    expect(blockClawback).toMatchObject({ status: 'completed', targetsSucceeded: 1 });
    const blockedEntry = await fx.prisma.quarantineMessage.findFirstOrThrow({
      where: { apiCopyId: blocked.copies[0]!.id },
    });
    expect(blockedEntry).toMatchObject({ hasHardBlock: true, status: 'held' });

    for (const c of [tagClawback!, blockClawback!])
      await requestRestore(fx, c, restorer, clock.now());
    await settle(comps, clock);
    const [tagTarget] = await targetsOf(tagClawback!.id);
    expect(tagTarget).toMatchObject({ restoreStatus: 'succeeded' });
    expect(
      await fx.prisma.apiRemediationAction.findUniqueOrThrow({
        where: { id: tagTarget!.restoreActionId! },
      }),
    ).toMatchObject({ action: 'remove_tag', trigger: 'admin', status: 'succeeded' });
    expect((await copiesOf(fx, tagged.message.id))[0]).toMatchObject({
      remediationState: 'restored',
    });
    const [blockTarget] = await targetsOf(blockClawback!.id);
    expect(blockTarget).toMatchObject({
      restoreStatus: 'skipped',
      restoreReasonCode: 'approval_required',
    });
    expect(
      await fx.prisma.quarantineMessage.findUniqueOrThrow({ where: { id: blockedEntry.id } }),
    ).toMatchObject({ status: 'held' });
    expect(await reload(tagClawback!.id)).toMatchObject({
      restoreStatus: 'completed',
      restoresSucceeded: 1,
    });
    expect(await reload(blockClawback!.id)).toMatchObject({
      restoreStatus: 'completed',
      restoresSkipped: 1,
    });
  });

  it('a restore requested again after completed_with_errors retries the failed targets', async () => {
    const urlHash = hex(`url-retry-${S}`);
    const tagged = await journal([USERS[1]!], { urlSha256: urlHash });
    await comps.copies.handle(
      lateSignal(fx, org.id, {
        kind: 'url_dynamic',
        messageId: tagged.message.id.toString(),
        receivedAt: tagged.message.receivedAt.toISOString(),
        scanId: tagged.scanId.toString(),
        verdict: 'suspicious',
        level: 'high',
        hardBlocks: [],
        urlSha256: [urlHash],
        signalAt: clock.now(),
      }),
    );
    await settle(comps, clock);
    const clawback = await fx.prisma.apiClawback.findFirstOrThrow({
      where: { organizationId: org.id, trigger: 'late_verdict' },
      orderBy: { id: 'desc' },
    });
    expect(clawback).toMatchObject({ status: 'completed', targetsSucceeded: 1 });
    const [to, id] = [...tagged.delivered][0]!;

    // First restore: the provider refuses the category removal → completed_with_errors.
    await requestRestore(fx, clawback, restorer, clock.now());
    sims.script.inject({
      simulator: 'graph',
      method: 'PATCH',
      path: /\/messages\/[^/]+$/,
      status: 403,
      times: 1,
    });
    try {
      await settle(comps, clock);
    } finally {
      sims.script.reset();
    }
    const [failed] = await targetsOf(clawback.id);
    expect(failed).toMatchObject({ restoreStatus: 'failed' });
    const firstAction = failed!.restoreActionId!;
    expect(
      await fx.prisma.apiRemediationAction.findUniqueOrThrow({ where: { id: firstAction } }),
    ).toMatchObject({ action: 'remove_tag', status: 'failed', reasonCode: 'provider_forbidden' });
    expect(await reload(clawback.id)).toMatchObject({
      restoreStatus: 'completed_with_errors',
      restoresFailed: 1,
      restoresSucceeded: 0,
    });
    expect(messageLocation(sims.script, to, id)!.categories?.length ?? 0).toBeGreaterThan(0);

    // Requested again (the api allows it from completed_with_errors): the failed target runs again.
    await requestRestore(fx, await reload(clawback.id), restorer, clock.now());
    await settle(comps, clock);
    const [retried] = await targetsOf(clawback.id);
    expect(retried).toMatchObject({ restoreStatus: 'succeeded', restoreReasonCode: null });
    // Same action key (copy, remove_tag, generation): the failed row was re-armed and succeeded.
    expect(retried!.restoreActionId).toBe(firstAction);
    expect(
      await fx.prisma.apiRemediationAction.findUniqueOrThrow({ where: { id: firstAction } }),
    ).toMatchObject({ action: 'remove_tag', status: 'succeeded' });
    expect(await reload(clawback.id)).toMatchObject({
      restoreStatus: 'completed',
      restoresFailed: 0,
      restoresSucceeded: 1,
    });
    expect(messageLocation(sims.script, to, id)!.categories ?? []).toEqual([]);
    expect(
      await fx.prisma.auditLog.count({
        where: {
          organizationId: org.id,
          action: 'api_mode.clawback_restore_completed',
          resourceId: clawback.publicId,
        },
      }),
    ).toBe(2);
  });

  it('a Graph hard delete is not reversible', async () => {
    const sent = await journal([USERS[4]!]);
    const done = await purge(hard, sent.hash, 'hard_delete');
    expect(done).toMatchObject({ status: 'completed', targetsSucceeded: 1 });
    expect(done.approvalReasons).toEqual(['hard_delete']);
    const [to, id] = [...sent.delivered][0]!;
    expect(messageLocation(sims.script, to, id)?.state).toBe('deleted');
    await requestRestore(fx, done, restorer, clock.now());
    await settle(hard, clock);
    expect((await targetsOf(done.id))[0]).toMatchObject({
      restoreStatus: 'skipped',
      restoreReasonCode: 'not_reversible',
    });
    expect(await reload(done.id)).toMatchObject({
      restoreStatus: 'completed',
      restoresSkipped: 1,
    });
  });
});
