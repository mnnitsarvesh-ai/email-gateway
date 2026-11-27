import { uuidv7, withTransactionDefaults } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { entryStateRestoreCode, remediationActionKey } from '@email-gateway/mailbox-api';
import { decideMailboxRestore, type QuarantinePlatformBounds } from '@email-gateway/quarantine';
import type { MailboxMetrics } from '../metrics/mailbox-metrics';
import {
  lockEntry,
  resolveOrganizationQuarantineSettings,
} from '../remediation/quarantine-entries';
import type { CounterStore } from '../runtime/redis-stores';
import { big, retryLockConflict, systemAudit, TX_MAX_WAIT_MS, TX_TIMEOUT_MS } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';
import type { ClaimedClawback } from './claims';
import type { ClawbackRow } from './clawback-runner';

/** Restore action statuses that end a target's restore (C7 reconcile). */
const TERMINAL = ['succeeded', 'failed', 'cancelled', 'skipped', 'simulated'];
/** Remediations whose success created a mailbox entry (R9.1). */
const ENTRY_ACTIONS = ['move_quarantine', 'move_junk', 'soft_delete'];

export interface RestoreDeps {
  prisma: PrismaClient;
  counters: CounterStore;
  metrics: MailboxMetrics | null;
  logger: Logger;
  now: () => Date;
  bounds: QuarantinePlatformBounds;
  /** Targets restored per tick (≤ 500, C7). */
  batch: number;
}

/** Who requested the restore (the api's audit row `api_mode.clawback_restore_requested`). */
export interface RestoreRequester {
  type: 'user' | 'api_key' | 'system';
  userId: bigint | null;
  /** The actor id as the api audits it (a user public id), null for the system. */
  actorId: string | null;
}

type Transition = (
  set: Prisma.Sql,
  extra?: (tx: Prisma.TransactionClient) => Promise<void>,
) => Promise<boolean>;

type TargetResult = 'queued' | 'skipped' | 'succeeded';

/**
 * Bulk restore of a clawback (step API-3, note 37 C7), run by the `clawback` role on
 * `restore_status = requested|running`: per `succeeded` target (≤ 500 per tick, one transaction
 * each) — `tag` → a `remove_tag` action; an entry-creating action (quarantine folder, Junk, soft
 * delete) → `decideMailboxRestore` in operator mode on its mailbox entry, then for `release` the
 * R10.2 write sequence of the api (`QuarantineEntryOps.queueRelease` + mailbox `queueRestore`:
 * `quarantine_actions` `release`, release log `pending` mode `operator`, entry `releasing`, a
 * `restore_inbox` action with `trigger = release`, `release_log_id` and `reverses_action_id`,
 * requested by the restoring user), keeping the lock order message → entry → copy → action;
 * `approval_required` / refused / an entry no longer `held` → `restore_skipped` with the code; a
 * Graph hard delete → `not_reversible`; a Google hard delete (Trash) → `restore_inbox` without an
 * entry. Then the restores are reconciled into `restores_*` and `restore_status`
 * `completed`/`completed_with_errors` with the audit `api_mode.clawback_restore_completed`. A
 * restore requested again after `completed_with_errors` first returns the `failed` targets to
 * `none` (retry). No provider call (the `remediate` role executes every row).
 */
export class ClawbackRestorer {
  private readonly txPrisma: PrismaClient;

  constructor(private readonly deps: RestoreDeps) {
    this.txPrisma = withTransactionDefaults(deps.prisma, {
      timeoutMs: TX_TIMEOUT_MS,
      maxWaitMs: TX_MAX_WAIT_MS,
    });
  }

  async run(claim: ClaimedClawback, row: ClawbackRow, transition: Transition): Promise<void> {
    if (row.restoreStatus === 'requested') {
      // A restore requested again after `completed_with_errors` retries what failed: the failed
      // targets return to `none` in the same transaction, so this run picks them up again. Their
      // reversal keeps its action key (copy, kind, generation) and `queueReversal` re-arms the
      // failed action row of that key.
      const now = this.deps.now();
      const moved = await transition(Prisma.sql`restore_status = 'running'`, async (tx) => {
        await tx.$executeRaw`
          UPDATE api_clawback_targets
          SET restore_status = 'none', restore_action_id = NULL, restore_reason_code = NULL,
              updated_at = ${now}
          WHERE clawback_id = ${row.id} AND organization_id = ${row.organizationId}
            AND restore_status = 'failed'`;
      });
      if (!moved) return;
      row.restoreStatus = 'running';
    }
    const requester = await this.requester(row);
    const prisma = this.deps.prisma;
    const targets = await prisma.apiClawbackTarget.findMany({
      where: { clawbackId: row.id, status: 'succeeded', restoreStatus: 'none' },
      select: {
        id: true,
        organizationId: true,
        apiConnectionId: true,
        mailboxId: true,
        copyId: true,
        copyReceivedAt: true,
        messageId: true,
        actionId: true,
      },
      orderBy: { id: 'asc' },
      take: this.deps.batch,
    });
    const tally = { queued: 0, skipped: 0, succeeded: 0 };
    for (const t of targets) {
      if (t.organizationId !== row.organizationId) {
        throw new InconsistentReadError('api_clawback_targets');
      }
      const result = await retryLockConflict(() =>
        this.txPrisma.$transaction((tx) => this.restoreTarget(tx, row, t, requester)),
      );
      tally[result] += 1;
    }
    this.deps.metrics?.clawbackTarget('restore_queued', tally.queued);
    this.deps.metrics?.clawbackTarget('restore_skipped', tally.skipped);
    await this.reconcile(claim, row, transition);
  }

  /** The restoring user: the latest `api_mode.clawback_restore_requested` audit row (api). */
  private async requester(row: ClawbackRow): Promise<RestoreRequester> {
    const audits = await this.deps.prisma.auditLog.findMany({
      where: {
        organizationId: row.organizationId,
        action: 'api_mode.clawback_restore_requested',
        resourceId: row.publicId,
      },
      select: { actorType: true, actorId: true, organizationId: true },
      orderBy: { createdAt: 'desc' },
      take: 1,
    });
    const audit = audits[0];
    if (audit && audit.organizationId === row.organizationId && audit.actorType === 'user') {
      const user =
        audit.actorId === null
          ? null
          : await this.deps.prisma.user.findFirst({
              where: { publicId: audit.actorId, organizationId: row.organizationId },
              select: { id: true, organizationId: true },
            });
      if (user && user.organizationId === row.organizationId) {
        return { type: 'user', userId: user.id, actorId: audit.actorId };
      }
    }
    if (audit && audit.actorType === 'api_key') {
      return { type: 'api_key', userId: null, actorId: audit.actorId };
    }
    const fallback = row.submittedByUserId ?? row.requestedByUserId;
    return fallback !== null
      ? { type: 'user', userId: fallback, actorId: null }
      : { type: 'system', userId: null, actorId: null };
  }

  private async restoreTarget(
    tx: Prisma.TransactionClient,
    row: ClawbackRow,
    target: {
      id: bigint;
      apiConnectionId: bigint;
      mailboxId: bigint;
      copyId: bigint;
      copyReceivedAt: Date;
      messageId: bigint;
      actionId: bigint | null;
    },
    requester: RestoreRequester,
  ): Promise<TargetResult> {
    const org = row.organizationId;
    const now = this.deps.now();
    const skip = async (code: string): Promise<'skipped'> => {
      await tx.$executeRaw`
        UPDATE api_clawback_targets
        SET restore_status = 'skipped', restore_reason_code = ${code.slice(0, 64)},
            updated_at = ${now}
        WHERE id = ${target.id} AND clawback_id = ${row.id} AND restore_status = 'none'`;
      return 'skipped';
    };
    if (target.actionId === null) return skip('not_reversible');
    const action = await tx.apiRemediationAction.findUnique({
      where: { id: target.actionId },
      select: {
        id: true,
        organizationId: true,
        action: true,
        status: true,
        generation: true,
        quarantineEntryId: true,
        copyId: true,
        apiConnectionId: true,
      },
    });
    if (!action) return skip('not_reversible');
    if (action.organizationId !== org || action.copyId !== target.copyId) {
      throw new InconsistentReadError('api_remediation_actions');
    }
    const requested = {
      type: requester.type,
      userId: requester.userId,
      reason: 'clawback restore',
    };
    if (action.action === 'tag') {
      const copy = await this.lockCopy(tx, org, target);
      if (!copy || copy.generation !== action.generation) return skip('refused');
      return this.queueReversal(tx, row, target, copy, {
        kind: 'remove_tag',
        trigger: 'admin',
        reverses: action.id,
        entryId: null,
        releaseLogId: null,
        requested,
        now,
      });
    }
    if (action.action === 'hard_delete') {
      const connection = await tx.apiModeConnection.findUnique({
        where: { id: action.apiConnectionId },
        select: { organizationId: true, provider: true },
      });
      if (!connection || connection.organizationId !== org) {
        throw new InconsistentReadError('api_mode_connections');
      }
      // Graph: permanently deleted. Google: the hard delete fell back to Trash (restorable).
      if (connection.provider !== 'google_workspace') return skip('not_reversible');
      const copy = await this.lockCopy(tx, org, target);
      if (!copy || copy.generation !== action.generation) return skip('refused');
      return this.queueReversal(tx, row, target, copy, {
        kind: 'restore_inbox',
        trigger: 'admin',
        reverses: action.id,
        entryId: null,
        releaseLogId: null,
        requested,
        now,
      });
    }
    if (!ENTRY_ACTIONS.includes(action.action) || action.quarantineEntryId === null) {
      return skip(action.quarantineEntryId === null ? 'entry_missing' : 'not_reversible');
    }
    // The policy-engine / api lock order: message → entry → copy → action.
    await tx.$queryRaw`
      SELECT id FROM email_messages
      WHERE id = ${target.messageId} AND received_at = ${target.copyReceivedAt}
        AND organization_id = ${org}
      FOR UPDATE`;
    const entry = await lockEntry(tx, action.quarantineEntryId, org);
    if (!entry) return skip(entryStateRestoreCode('missing'));
    if (entry.status !== 'held' || entry.location !== 'mailbox') {
      return skip(entryStateRestoreCode(entry.status));
    }
    const copy = await this.lockCopy(tx, org, target);
    if (!copy || copy.generation !== action.generation) return skip('refused');
    const settings = await resolveOrganizationQuarantineSettings(tx, org, this.deps.bounds);
    const decision = decideMailboxRestore({
      entry: {
        kind: entry.kind,
        reason: entry.reason as never,
        state: entry.status,
        riskLevel: (entry.riskLevel ?? null) as never,
        hasHardBlock: entry.hasHardBlock,
      },
      copyStatus: copy.status as never,
      mode: 'operator',
      settings,
    });
    if (decision.outcome === 'approval_required') return skip('approval_required');
    if (decision.outcome !== 'release') return skip('refused');
    const stored = await tx.quarantineMessage.findUnique({
      where: { id: entry.id },
      select: { organizationId: true, recipientAddress: true, apiRemediationActionId: true },
    });
    if (!stored || stored.organizationId !== org) {
      throw new InconsistentReadError('quarantine_messages');
    }
    const actorType = requester.type === 'system' ? 'system' : requester.type;
    const releaseAction = await tx.quarantineAction.create({
      data: {
        organizationId: org,
        quarantineMessageId: entry.id,
        action: 'release',
        actorType,
        actorUserId: requester.userId,
        actorId: requester.actorId,
        reason: 'clawback restore',
        result: 'queued',
        details: { mode: 'operator', clawbackId: row.publicId },
      },
      select: { id: true },
    });
    const log = await tx.quarantineReleaseLog.create({
      data: {
        organizationId: org,
        quarantineMessageId: entry.id,
        actionId: releaseAction.id,
        releasePublicId: uuidv7(now.getTime()),
        mode: 'operator',
        approvalRequestId: null,
        requestedByType: actorType,
        requestedById: requester.actorId,
        releasedTo: stored.recipientAddress,
        precheck: { outcome: 'release', clawbackId: row.publicId },
        status: 'pending',
      },
      select: { id: true },
    });
    const moved = await tx.$executeRaw`
      UPDATE quarantine_messages
      SET status = 'releasing', state_changed_at = ${now}, row_version = row_version + 1
      WHERE id = ${entry.id} AND organization_id = ${org} AND row_version = ${entry.rowVersion}
        AND status = 'held'`;
    if (moved !== 1) throw new InconsistentReadError('quarantine_messages CAS');
    return this.queueReversal(tx, row, target, copy, {
      kind: 'restore_inbox',
      trigger: 'release',
      reverses: stored.apiRemediationActionId ?? action.id,
      entryId: entry.id,
      releaseLogId: log.id,
      requested,
      now,
    });
  }

  private async lockCopy(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    target: { copyId: bigint; copyReceivedAt: Date },
  ): Promise<{ publicId: string; generation: number; status: string } | null> {
    const rows = await tx.$queryRaw<
      Array<{ public_id: string; remediation_generation: number; status: string }>
    >`
      SELECT public_id, remediation_generation, status FROM api_message_copies
      WHERE id = ${target.copyId} AND received_at = ${target.copyReceivedAt}
        AND organization_id = ${organizationId}
      FOR UPDATE`;
    const row = rows[0];
    return row
      ? {
          publicId: row.public_id,
          generation: Number(row.remediation_generation),
          status: row.status,
        }
      : null;
  }

  /**
   * The reversal action of one target (`INSERT`, or a re-arm of a terminal non-succeeded row of
   * the same key; a busy row is linked, a succeeded one ends the target's restore). A `remove_tag`
   * marks the copy `pending` on it as the api's `markCopyPending` (the remediation stays in
   * effect); a `restore_inbox` leaves the copy as the api's mailbox restore does.
   */
  private async queueReversal(
    tx: Prisma.TransactionClient,
    row: ClawbackRow,
    target: {
      id: bigint;
      apiConnectionId: bigint;
      mailboxId: bigint;
      copyId: bigint;
      copyReceivedAt: Date;
      messageId: bigint;
    },
    copy: { publicId: string; generation: number },
    r: {
      kind: 'remove_tag' | 'restore_inbox';
      trigger: 'admin' | 'release';
      reverses: bigint;
      entryId: bigint | null;
      releaseLogId: bigint | null;
      requested: { type: string; userId: bigint | null; reason: string };
      now: Date;
    },
  ): Promise<TargetResult> {
    const org = row.organizationId;
    const key = remediationActionKey(copy.publicId, r.kind, copy.generation);
    const decision = JSON.stringify({
      requestedAction: r.kind,
      reason: 'clawback_restore',
      clawbackId: row.publicId,
    });
    const existing = await tx.$queryRaw<
      Array<{ id: bigint | number; organization_id: bigint | number; status: string }>
    >`SELECT id, organization_id, status FROM api_remediation_actions WHERE action_key = ${key}
      FOR UPDATE`;
    let actionId: bigint;
    const prior = existing[0];
    if (prior) {
      if (big(prior.organization_id) !== org) {
        throw new InconsistentReadError('api_remediation_actions');
      }
      actionId = big(prior.id);
      if (prior.status === 'succeeded' && r.entryId === null) {
        await tx.$executeRaw`
          UPDATE api_clawback_targets
          SET restore_status = 'succeeded', restore_action_id = ${actionId}, updated_at = ${r.now}
          WHERE id = ${target.id} AND clawback_id = ${row.id} AND restore_status = 'none'`;
        return 'succeeded';
      }
      if (prior.status === 'pending' || prior.status === 'in_progress') {
        if (r.entryId !== null) throw new InconsistentReadError('restore already in flight');
      } else {
        await tx.$executeRaw`
          UPDATE api_remediation_actions
          SET status = 'pending', \`trigger\` = ${r.trigger}, clawback_id = ${row.id},
              decision = ${decision}, reason_code = NULL, attempts = 0, locate_attempts = 0,
              lease_until = NULL, last_error_code = NULL, last_http_status = NULL,
              provider_refs = NULL, started_at = NULL, completed_at = NULL,
              next_attempt_at = ${r.now}, reverses_action_id = ${r.reverses},
              quarantine_entry_id = ${r.entryId}, release_log_id = ${r.releaseLogId},
              requested_by_type = ${r.requested.type}, requested_by_user_id = ${r.requested.userId},
              request_reason = ${r.requested.reason}, row_version = row_version + 1,
              updated_at = ${r.now}
          WHERE id = ${actionId}`;
      }
    } else {
      await tx.$executeRaw`
        INSERT INTO api_remediation_actions
          (public_id, organization_id, api_connection_id, mailbox_id, copy_id, copy_received_at,
           message_id, action, generation, action_key, \`trigger\`, status, decision,
           reverses_action_id, quarantine_entry_id, release_log_id, requested_by_type,
           requested_by_user_id, request_reason, attempts, locate_attempts, next_attempt_at,
           clawback_id, row_version, created_at, updated_at)
        VALUES (${uuidv7(r.now.getTime())}, ${org}, ${target.apiConnectionId},
                ${target.mailboxId}, ${target.copyId}, ${target.copyReceivedAt},
                ${target.messageId}, ${r.kind}, ${copy.generation}, ${key}, ${r.trigger},
                'pending', ${decision}, ${r.reverses}, ${r.entryId}, ${r.releaseLogId},
                ${r.requested.type}, ${r.requested.userId}, ${r.requested.reason}, 0, 0, ${r.now},
                ${row.id}, 1, ${r.now}, ${r.now})`;
      const inserted = await tx.$queryRaw<
        Array<{ id: bigint | number; organization_id: bigint | number }>
      >`SELECT id, organization_id FROM api_remediation_actions WHERE action_key = ${key}`;
      if (!inserted[0] || big(inserted[0].organization_id) !== org) {
        throw new InconsistentReadError('api_remediation_actions');
      }
      actionId = big(inserted[0].id);
    }
    if (r.kind === 'remove_tag') {
      await tx.$executeRaw`
        UPDATE api_message_copies
        SET remediation_state = 'pending', last_action_id = ${actionId},
            remediation_updated_at = ${r.now}
        WHERE id = ${target.copyId} AND received_at = ${target.copyReceivedAt}
          AND organization_id = ${org}`;
    }
    await tx.$executeRaw`
      UPDATE api_clawback_targets
      SET restore_status = 'queued', restore_action_id = ${actionId}, restore_reason_code = NULL,
          updated_at = ${r.now}
      WHERE id = ${target.id} AND clawback_id = ${row.id} AND restore_status = 'none'`;
    return 'queued';
  }

  /** C7 reconcile: restore outcomes, `restores_*`, `restore_status` and the completion audit. */
  private async reconcile(
    claim: ClaimedClawback,
    row: ClawbackRow,
    transition: Transition,
  ): Promise<void> {
    const prisma = this.deps.prisma;
    const now = this.deps.now();
    const done = await prisma.$queryRaw<
      Array<{
        id: bigint | number;
        api_connection_id: bigint | number;
        a_status: string | null;
        a_reason: string | null;
      }>
    >`
      SELECT t.id, t.api_connection_id, a.status AS a_status, a.reason_code AS a_reason
      FROM api_clawback_targets t
      LEFT JOIN api_remediation_actions a
        ON a.id = t.restore_action_id AND a.organization_id = t.organization_id
      WHERE t.clawback_id = ${row.id} AND t.restore_status = 'queued'
        AND (a.id IS NULL OR a.status IN (${Prisma.join(TERMINAL)}))
      LIMIT 2000`;
    const tally = { succeeded: 0, failed: 0, skipped: 0 };
    for (const d of done) {
      const status =
        d.a_status === 'succeeded' ? 'succeeded' : d.a_status === 'failed' ? 'failed' : 'skipped';
      const reason = d.a_status === null ? 'not_reversible' : d.a_reason;
      await prisma.$executeRaw`
        UPDATE api_clawback_targets
        SET restore_status = ${status}, restore_reason_code = ${reason?.slice(0, 64) ?? null},
            updated_at = ${now}
        WHERE id = ${big(d.id)} AND restore_status = 'queued'`;
      tally[status] += 1;
    }
    this.deps.metrics?.clawbackTarget('restore_succeeded', tally.succeeded);
    this.deps.metrics?.clawbackTarget('restore_failed', tally.failed);
    this.deps.metrics?.clawbackTarget('restore_skipped', tally.skipped);
    const rows = await prisma.$queryRaw<Array<{ restore_status: string; n: bigint | number }>>`
      SELECT restore_status, COUNT(*) AS n FROM api_clawback_targets
      WHERE clawback_id = ${row.id} AND (status = 'succeeded' OR restore_status <> 'none')
      GROUP BY restore_status`;
    const by: Record<string, number> = {};
    for (const r of rows) by[r.restore_status] = Number(r.n);
    const counts = Prisma.sql`restores_queued = ${by.queued ?? 0},
      restores_succeeded = ${by.succeeded ?? 0}, restores_failed = ${by.failed ?? 0},
      restores_skipped = ${by.skipped ?? 0}`;
    if ((by.queued ?? 0) > 0 || (by.none ?? 0) > 0) {
      await prisma.$executeRaw`
        UPDATE api_clawbacks SET ${counts}, updated_at = ${now}
        WHERE id = ${row.id} AND row_version = ${claim.rowVersion}
          AND lease_until = ${claim.leaseUntil}`;
      return;
    }
    const status = (by.failed ?? 0) > 0 ? 'completed_with_errors' : 'completed';
    const finished = await transition(Prisma.sql`restore_status = ${status}, ${counts}`, (tx) =>
      systemAudit(tx, {
        organizationId: row.organizationId,
        action: 'api_mode.clawback_restore_completed',
        resourceType: 'api_clawback',
        resourceId: row.publicId,
        correlationId: `api-clawback:${row.publicId}`,
        metadata: {
          clawbackId: row.publicId,
          status,
          counts: {
            succeeded: by.succeeded ?? 0,
            failed: by.failed ?? 0,
            skipped: by.skipped ?? 0,
          },
        },
      }),
    );
    if (finished) {
      this.deps.metrics?.clawback(
        row.trigger,
        status === 'completed' ? 'restore_completed' : 'restore_completed_with_errors',
      );
      this.deps.logger.info({ clawbackId: row.publicId, status }, 'clawback restore completed');
    }
  }
}
