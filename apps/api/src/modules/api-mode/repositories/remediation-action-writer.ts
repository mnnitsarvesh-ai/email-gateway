import { Injectable } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { ActorType, Prisma } from '@email-gateway/database';
import { remediationActionKey, type RemediationActionKind } from '@email-gateway/mailbox-api';

type Tx = Prisma.TransactionClient;

/** The api's triggers (`policy` rows are written by the mailbox-worker only). */
export type ApiRemediationTrigger = 'admin' | 'release' | 'end_user';

/** One action row the api queues for the mailbox-worker's `remediate` role (R1, R5, R12). */
export interface QueueRemediationAction {
  organizationId: bigint;
  apiConnectionId: bigint;
  mailboxId: bigint;
  copyId: bigint;
  copyReceivedAt: Date;
  /** The copy's public id: the input of `action_key`. */
  copyPublicId: string;
  /** The copy's registry message. */
  messageId: bigint;
  action: RemediationActionKind;
  /** The copy's current `remediation_generation` (R5.5). */
  generation: number;
  trigger: ApiRemediationTrigger;
  /** `{ requestedAction, reason }` (R2.4 "otherwise"). */
  decision: Prisma.InputJsonValue;
  reversesActionId: bigint | null;
  quarantineEntryId: bigint | null;
  releaseLogId: bigint | null;
  requestedByType: ActorType;
  requestedByUserId: bigint | null;
  /** Operator-typed (untrusted) text, ≤ 512 characters. */
  requestReason: string | null;
  now: Date;
}

/**
 * - `inserted`: a new `pending` row;
 * - `rearmed`: the row of this key (same copy, action and generation) existed in a terminal
 *   non-success state (failed, cancelled, skipped, simulated) or still `pending`, and was set
 *   back to `pending` (due now) with this request's trigger, requester and links;
 * - `busy`: the row is `in_progress` (the worker holds its lease) — nothing changed;
 * - `succeeded`: the row already succeeded in this generation — nothing changed.
 */
export type QueueOutcome = 'inserted' | 'rearmed' | 'busy' | 'succeeded';

export interface QueuedAction {
  id: bigint;
  publicId: string;
  outcome: QueueOutcome;
}

/**
 * Writes the api's `api_remediation_actions` rows (step API-2 R1, R10.2, R10.4, R12, §3.1;
 * ADR-0101) in the caller's writer transaction, following the row contract the mailbox-worker's
 * `remediate` role executes: `action_key` = `remediationActionKey(copyPublicId, action,
 * generation)` (unique; `INSERT IGNORE`, R-I4), `status = pending`, `next_attempt_at = now`, no
 * lease, zero attempts. A key that already exists is re-armed instead (a failed restore whose
 * entry is released again, a manual remediation of an action the policy skipped), never
 * duplicated. Ids, enums, codes and the operator's reason only (R-I6).
 */
@Injectable()
export class RemediationActionWriter {
  async queue(tx: Tx, row: QueueRemediationAction): Promise<QueuedAction> {
    const key = remediationActionKey(row.copyPublicId, row.action, row.generation);
    const publicId = uuidv7(row.now.getTime());
    const decision = JSON.stringify(row.decision);
    const inserted = await tx.$executeRaw`
      INSERT IGNORE INTO api_remediation_actions
        (public_id, organization_id, api_connection_id, mailbox_id, copy_id, copy_received_at,
         message_id, action, generation, action_key, \`trigger\`, status, decision,
         reverses_action_id, quarantine_entry_id, release_log_id, requested_by_type,
         requested_by_user_id, request_reason, attempts, locate_attempts, next_attempt_at,
         row_version, created_at, updated_at)
      VALUES
        (${publicId}, ${row.organizationId}, ${row.apiConnectionId}, ${row.mailboxId},
         ${row.copyId}, ${row.copyReceivedAt}, ${row.messageId}, ${row.action},
         ${row.generation}, ${key}, ${row.trigger}, 'pending', CAST(${decision} AS JSON),
         ${row.reversesActionId}, ${row.quarantineEntryId}, ${row.releaseLogId},
         ${row.requestedByType}, ${row.requestedByUserId}, ${row.requestReason}, 0, 0,
         ${row.now}, 1, ${row.now}, ${row.now})`;
    const existing = await tx.$queryRaw<
      Array<{ id: bigint; publicId: string; status: string; organizationId: bigint }>
    >`
      SELECT id, public_id AS publicId, status, organization_id AS organizationId
      FROM api_remediation_actions WHERE action_key = ${key} FOR UPDATE`;
    const found = existing[0];
    if (found === undefined || BigInt(found.organizationId) !== row.organizationId) {
      // The key is derived from the copy's public id: another organization's row is impossible
      // unless the data is corrupt. Refuse rather than touch it.
      throw new Error('remediation action key integrity mismatch');
    }
    const id = BigInt(found.id);
    if (inserted === 1) return { id, publicId: found.publicId, outcome: 'inserted' };
    if (found.status === 'in_progress') return { id, publicId: found.publicId, outcome: 'busy' };
    if (found.status === 'succeeded') {
      return { id, publicId: found.publicId, outcome: 'succeeded' };
    }
    await tx.$executeRaw`
      UPDATE api_remediation_actions
      SET status = 'pending', \`trigger\` = ${row.trigger}, decision = CAST(${decision} AS JSON),
          reason_code = NULL, reverses_action_id = ${row.reversesActionId},
          quarantine_entry_id = ${row.quarantineEntryId}, release_log_id = ${row.releaseLogId},
          requested_by_type = ${row.requestedByType},
          requested_by_user_id = ${row.requestedByUserId}, request_reason = ${row.requestReason},
          attempts = 0, locate_attempts = 0, next_attempt_at = ${row.now}, lease_until = NULL,
          last_error_code = NULL, last_http_status = NULL, started_at = NULL,
          completed_at = NULL, row_version = row_version + 1, updated_at = ${row.now}
      WHERE id = ${id} AND organization_id = ${row.organizationId}`;
    return { id, publicId: found.publicId, outcome: 'rearmed' };
  }

  /**
   * The copy's remediation state while an api-queued action waits (R12): `pending`, the action
   * in effect (remediations only) and the last action id. Partitioned table: the key includes
   * `received_at`.
   */
  async markCopyPending(
    tx: Tx,
    copy: { organizationId: bigint; copyId: bigint; copyReceivedAt: Date },
    update: { remediationAction: string | null; lastActionId: bigint; now: Date },
  ): Promise<void> {
    if (update.remediationAction === null) {
      await tx.$executeRaw`
        UPDATE api_message_copies
        SET remediation_state = 'pending', last_action_id = ${update.lastActionId},
            remediation_updated_at = ${update.now}, updated_at = ${update.now}
        WHERE id = ${copy.copyId} AND received_at = ${copy.copyReceivedAt}
          AND organization_id = ${copy.organizationId}`;
      return;
    }
    await tx.$executeRaw`
      UPDATE api_message_copies
      SET remediation_state = 'pending', remediation_action = ${update.remediationAction},
          last_action_id = ${update.lastActionId}, remediation_updated_at = ${update.now},
          updated_at = ${update.now}
      WHERE id = ${copy.copyId} AND received_at = ${copy.copyReceivedAt}
        AND organization_id = ${copy.organizationId}`;
  }
}
