import { isUniqueViolation, uuidv7 } from '@email-gateway/common';
import { type DeliveryReinjection, Prisma, type PrismaClient } from '@email-gateway/database';
import { recipientSetSha256, reinjectionIdempotencyKey } from '@email-gateway/mail-routing';

/** A claimed `delivery_reinjections` row (status `in_progress`, attempts already incremented). */
export type ClaimedReinjection = Pick<
  DeliveryReinjection,
  | 'id'
  | 'receivedAt'
  | 'publicId'
  | 'messageId'
  | 'organizationId'
  | 'deliverySeq'
  | 'listener'
  | 'direction'
  | 'destinationKey'
  | 'emlObjectKey'
  | 'approvalEventId'
  | 'attempts'
  | 'startedAt'
  | 'createdAt'
  | 'lastErrorClass'
  | 'recipientSetSha256'
  | 'idempotencyKey'
  | 'leaseExpiresAt'
>;

const CLAIM_SELECT = {
  id: true,
  receivedAt: true,
  publicId: true,
  messageId: true,
  organizationId: true,
  deliverySeq: true,
  listener: true,
  direction: true,
  destinationKey: true,
  emlObjectKey: true,
  approvalEventId: true,
  attempts: true,
  startedAt: true,
  createdAt: true,
  lastErrorClass: true,
  recipientSetSha256: true,
  idempotencyKey: true,
  leaseExpiresAt: true,
} as const;

/**
 * Restricts claims to some organizations (integration tests and operator tooling on a shared
 * database). Production claims every due row.
 */
export interface ClaimScope {
  organizationIds: readonly bigint[];
}

/** One recipient of a reinjection that still needs the worker's hop. */
export interface ActiveDelivery {
  id: bigint;
  receivedAt: Date;
  recipientId: bigint;
  rcptSeq: number;
  /** As stored (case preserved; matching is case-insensitive). */
  address: string;
}

export interface ReinjectionContext {
  envelopeFrom: string;
  clientIp: string | null;
  clientHelo: string | null;
  deliveries: ActiveDelivery[];
}

/** Delivery statuses the worker's hop still applies to. */
const ACTIVE_STATUSES = ['pending', 'deferred', 'in_progress'] as const;
const MAX_ERROR = 512;

/** Default interactive-transaction budget of `claim` (the worker passes DELIVERY_DB_TX_TIMEOUT_MS). */
export const DEFAULT_STORE_TX_TIMEOUT_MS = 120_000;

/** The read whose echo check failed (bounded metric label of `delivery_inconsistent_reads_total`). */
export type InconsistentRead = 'message' | 'deliveries' | 'recipients' | 'approval';

/**
 * A writer read returned rows that do not belong to the request (step 4.2 §6.2 item 3): the
 * identifying columns of the result differ from what was asked for. Seen after a writer stall
 * with the Prisma 6.19 library engine (a pooled connection's unread reply is read by the next
 * request, §12 WP4). Transient: the reinjector reschedules the row with the attempt refunded.
 * The message names the check only, never row content.
 */
export class InconsistentReadError extends Error {
  override readonly name = 'InconsistentReadError';

  constructor(
    readonly read: InconsistentRead,
    readonly check: string,
  ) {
    super(`inconsistent ${read} read: ${check}`);
  }
}

const sameTime = (a: Date, b: Date): boolean => a.getTime() === b.getTime();

const where = (row: { id: bigint; receivedAt: Date }) => ({
  id_receivedAt: { id: row.id, receivedAt: row.receivedAt },
});

/**
 * Writer-side persistence of reinjection rows (R8). Every status change of a claimed row is
 * conditional on `status = in_progress` and its claimed `attempts`, so a row that the reconciler
 * already resolved (or another claim took over after a lease expiry) is never overwritten.
 */
export class ReinjectionStore {
  private readonly txTimeoutMs: number;

  /**
   * `txTimeoutMs`: budget (timeout and maxWait) of the claim transaction, longer than the
   * writer's own timeouts so the client never expires it while a statement is in flight (§6.2).
   */
  constructor(
    private readonly prisma: PrismaClient,
    options: { txTimeoutMs?: number } = {},
  ) {
    this.txTimeoutMs = options.txTimeoutMs ?? DEFAULT_STORE_TX_TIMEOUT_MS;
  }

  /**
   * Claims up to `limit` due rows: `SELECT … FOR UPDATE SKIP LOCKED` (replicas never claim the
   * same row), then `in_progress`, `lease_expires_at = now + lease`, `attempts + 1`, `started_at`.
   */
  async claim(
    limit: number,
    now: Date,
    leaseSeconds: number,
    scope?: ClaimScope,
  ): Promise<ClaimedReinjection[]> {
    if (limit <= 0) return [];
    const organizations = scope?.organizationIds ?? [];
    return this.prisma.$transaction(
      async (tx) => {
        const rows =
          organizations.length > 0
            ? await tx.$queryRaw<{ id: bigint; received_at: Date }[]>`
              SELECT id, received_at FROM delivery_reinjections
              WHERE status = 'pending' AND next_attempt_at <= ${now}
                AND organization_id IN (${Prisma.join(organizations)})
              ORDER BY next_attempt_at
              LIMIT ${limit}
              FOR UPDATE SKIP LOCKED`
            : await tx.$queryRaw<{ id: bigint; received_at: Date }[]>`
              SELECT id, received_at FROM delivery_reinjections
              WHERE status = 'pending' AND next_attempt_at <= ${now}
              ORDER BY next_attempt_at
              LIMIT ${limit}
              FOR UPDATE SKIP LOCKED`;
        if (rows.length === 0) return [];
        const leaseExpiresAt = new Date(now.getTime() + leaseSeconds * 1000);
        for (const row of rows) {
          await tx.deliveryReinjection.update({
            where: where({ id: BigInt(row.id), receivedAt: row.received_at }),
            data: {
              status: 'in_progress',
              leaseExpiresAt,
              attempts: { increment: 1 },
              startedAt: now,
            },
            select: { id: true },
          });
        }
        return tx.deliveryReinjection.findMany({
          where: { OR: rows.map((row) => ({ id: BigInt(row.id), receivedAt: row.received_at })) },
          select: CLAIM_SELECT,
          orderBy: { nextAttemptAt: 'asc' },
        });
      },
      { timeout: this.txTimeoutMs, maxWait: this.txTimeoutMs },
    );
  }

  /** Extends the lease of a row still held by this claim. False when the claim was lost. */
  async renewLease(row: ClaimedReinjection, until: Date): Promise<boolean> {
    const { count } = await this.prisma.deliveryReinjection.updateMany({
      where: {
        id: row.id,
        receivedAt: row.receivedAt,
        status: 'in_progress',
        attempts: row.attempts,
      },
      data: { leaseExpiresAt: until },
    });
    return count === 1;
  }

  /**
   * The message's envelope data and the deliveries that still need this hop; null when the
   * message row is not found. Every result is checked against the request (message id,
   * organization and `received_at` echo; each delivery's `reinjection_id`, message, organization
   * and status; each recipient requested, of the message, and every delivery's recipient
   * returned); a mismatch throws `InconsistentReadError` (§6.2 item 3).
   */
  async context(row: ClaimedReinjection): Promise<ReinjectionContext | null> {
    const message = await this.prisma.emailMessage.findFirst({
      where: { id: row.messageId, receivedAt: row.receivedAt, organizationId: row.organizationId },
      select: {
        id: true,
        receivedAt: true,
        organizationId: true,
        envelopeFrom: true,
        clientIp: true,
        clientHelo: true,
      },
    });
    if (!message) return null;
    if (
      message.id !== row.messageId ||
      message.organizationId !== row.organizationId ||
      !sameTime(message.receivedAt, row.receivedAt)
    ) {
      throw new InconsistentReadError('message', 'identity echo');
    }
    return {
      envelopeFrom: message.envelopeFrom,
      clientIp: message.clientIp,
      clientHelo: message.clientHelo,
      deliveries: await this.activeDeliveries(row),
    };
  }

  /**
   * The deliveries of the row that still need the hop, with their recipients (the same checks
   * as `context`). Also used without the message row (the final `context_missing` attempt).
   */
  async activeDeliveries(row: ClaimedReinjection): Promise<ActiveDelivery[]> {
    const deliveries = await this.prisma.emailDelivery.findMany({
      where: {
        reinjectionId: row.id,
        receivedAt: row.receivedAt,
        messageId: row.messageId,
        organizationId: row.organizationId,
        status: { in: [...ACTIVE_STATUSES] },
      },
      select: {
        id: true,
        receivedAt: true,
        recipientId: true,
        reinjectionId: true,
        messageId: true,
        organizationId: true,
        status: true,
      },
      orderBy: { recipientId: 'asc' },
    });
    for (const d of deliveries) {
      if (
        d.reinjectionId !== row.id ||
        d.messageId !== row.messageId ||
        d.organizationId !== row.organizationId ||
        !sameTime(d.receivedAt, row.receivedAt) ||
        !(ACTIVE_STATUSES as readonly string[]).includes(d.status)
      ) {
        throw new InconsistentReadError('deliveries', 'delivery echo');
      }
    }
    if (deliveries.length === 0) return [];
    const requested = new Set(deliveries.map((d) => d.recipientId));
    const recipients = await this.prisma.emailRecipient.findMany({
      where: { id: { in: [...requested] }, receivedAt: row.receivedAt, messageId: row.messageId },
      select: { id: true, rcptSeq: true, address: true, messageId: true, receivedAt: true },
    });
    for (const r of recipients) {
      if (
        !requested.has(r.id) ||
        r.messageId !== row.messageId ||
        !sameTime(r.receivedAt, row.receivedAt)
      ) {
        throw new InconsistentReadError('recipients', 'recipient echo');
      }
    }
    const byId = new Map(recipients.map((r) => [r.id, r]));
    return deliveries.map((d) => {
      const recipient = byId.get(d.recipientId);
      // A delivery always has its recipient row (same message, same partition).
      if (!recipient) throw new InconsistentReadError('recipients', 'recipient missing');
      return {
        id: d.id,
        receivedAt: d.receivedAt,
        recipientId: d.recipientId,
        rcptSeq: recipient.rcptSeq,
        address: recipient.address,
      };
    });
  }

  /**
   * When the approval that planned this row was accepted: the oldest row of the approval. The
   * claimed row itself matches the query, so a result is always expected; it must echo the
   * approval event and the message and be no newer than the row (§6.2 item 3).
   */
  async approvalTime(row: ClaimedReinjection): Promise<Date> {
    const oldest = await this.prisma.deliveryReinjection.findFirst({
      where: {
        messageId: row.messageId,
        receivedAt: row.receivedAt,
        approvalEventId: row.approvalEventId,
      },
      orderBy: { createdAt: 'asc' },
      select: { createdAt: true, approvalEventId: true, messageId: true, receivedAt: true },
    });
    if (
      !oldest ||
      oldest.approvalEventId !== row.approvalEventId ||
      oldest.messageId !== row.messageId ||
      !sameTime(oldest.receivedAt, row.receivedAt) ||
      oldest.createdAt.getTime() > row.createdAt.getTime()
    ) {
      throw new InconsistentReadError('approval', 'approval echo');
    }
    return oldest.createdAt;
  }

  /**
   * Final `context_missing` attempt, in the caller's transaction after the recorder: deliveries
   * of the row that are still active although the recorder could not resolve them (their
   * message row is gone, so the recorder reports them `unmatched`) are failed directly with
   * `failureReason`, so no delivery is left pending without a recovery path. Returns the count.
   */
  async failOrphanedDeliveries(
    tx: Prisma.TransactionClient,
    row: ClaimedReinjection,
    deliveryIds: readonly bigint[],
    failureReason: string,
    now: Date,
  ): Promise<number> {
    if (deliveryIds.length === 0) return 0;
    const { count } = await tx.emailDelivery.updateMany({
      where: {
        id: { in: [...deliveryIds] },
        receivedAt: row.receivedAt,
        reinjectionId: row.id,
        status: { in: [...ACTIVE_STATUSES] },
      },
      data: {
        status: 'failed',
        failureReason,
        lastErrorClass: 'other',
        statusChangedAt: now,
      },
    });
    return count;
  }

  /** Back to `pending` at `nextAttemptAt` (worker retry, hold, rate limit, shutdown release). */
  async reschedule(
    row: ClaimedReinjection,
    options: {
      nextAttemptAt: Date;
      errorClass: string | null;
      error: string | null;
      refundAttempt?: boolean;
    },
    tx: Prisma.TransactionClient | PrismaClient = this.prisma,
  ): Promise<boolean> {
    const { count } = await tx.deliveryReinjection.updateMany({
      where: {
        id: row.id,
        receivedAt: row.receivedAt,
        status: 'in_progress',
        attempts: row.attempts,
      },
      data: {
        status: 'pending',
        nextAttemptAt: options.nextAttemptAt,
        leaseExpiresAt: null,
        lastErrorClass: options.errorClass,
        lastError: options.error?.slice(0, MAX_ERROR) ?? null,
        ...(options.refundAttempt && row.attempts > 0 ? { attempts: { decrement: 1 } } : {}),
      },
    });
    return count === 1;
  }

  async markFailed(
    row: ClaimedReinjection,
    errorClass: string | null,
    error: string,
    tx: Prisma.TransactionClient | PrismaClient = this.prisma,
  ): Promise<boolean> {
    const { count } = await tx.deliveryReinjection.updateMany({
      where: {
        id: row.id,
        receivedAt: row.receivedAt,
        status: 'in_progress',
        attempts: row.attempts,
      },
      data: {
        status: 'failed',
        leaseExpiresAt: null,
        lastErrorClass: errorClass,
        lastError: error.slice(0, MAX_ERROR),
      },
    });
    return count === 1;
  }

  /** `queued` after the final 250 (queue id from the reply, or left to the log binding). */
  async markQueued(
    row: ClaimedReinjection,
    queuedAt: Date,
    tx: Prisma.TransactionClient,
  ): Promise<void> {
    await tx.deliveryReinjection.updateMany({
      where: { id: row.id, receivedAt: row.receivedAt, status: { in: ['in_progress', 'pending'] } },
      data: {
        status: 'queued',
        queuedAt,
        leaseExpiresAt: null,
        lastErrorClass: null,
        lastError: null,
      },
    });
  }

  /**
   * Locks the reinjection row, then the message row (`SELECT … FOR UPDATE`): the recorder's lock
   * order (reinjection → message → deliveries), so result commits never deadlock with the
   * status tailer or the bounce handler. Returns the current status, or null when gone.
   */
  async lockForResult(
    tx: Prisma.TransactionClient,
    row: ClaimedReinjection,
  ): Promise<{ status: string; attempts: number } | null> {
    const rows = await tx.$queryRaw<{ status: string; attempts: number }[]>`
      SELECT status, attempts FROM delivery_reinjections
      WHERE id = ${row.id} AND received_at = ${row.receivedAt} FOR UPDATE`;
    await tx.$queryRaw`
      SELECT id FROM email_messages
      WHERE id = ${row.messageId} AND received_at = ${row.receivedAt} FOR UPDATE`;
    const first = rows[0];
    return first ? { status: first.status, attempts: Number(first.attempts) } : null;
  }

  /**
   * Moves `moved` deliveries into new reinjection rows (R8 per-recipient 4xx, R11 chunking): a
   * new recipient set, its own idempotency key and token, `pending` at `nextAttemptAt`. The
   * moved deliveries lose any queue id bound from the current session. The current row's set is
   * recomputed over `kept`. Lineage guarantees new sets never repeat an earlier set of the
   * message (each new set is a strict subset of the row it leaves); a unique-key hit is
   * therefore unexpected and rethrown.
   */
  async split(
    tx: Prisma.TransactionClient,
    row: ClaimedReinjection,
    kept: readonly ActiveDelivery[],
    chunks: readonly (readonly ActiveDelivery[])[],
    options: { nextAttemptAt: Date; errorClass: string | null; error: string | null; now: Date },
  ): Promise<bigint[]> {
    const created: bigint[] = [];
    for (const chunk of chunks) {
      if (chunk.length === 0) continue;
      const setSha = recipientSetSha256(chunk.map((d) => d.address));
      const newRow = await tx.deliveryReinjection.create({
        data: {
          receivedAt: row.receivedAt,
          publicId: uuidv7(options.now.getTime()),
          messageId: row.messageId,
          organizationId: row.organizationId,
          deliverySeq: row.deliverySeq,
          listener: row.listener,
          direction: row.direction,
          destinationKey: row.destinationKey,
          emlObjectKey: row.emlObjectKey,
          recipientCount: chunk.length,
          recipientSetSha256: setSha,
          idempotencyKey: reinjectionIdempotencyKey({
            messageId: row.messageId,
            deliverySeq: row.deliverySeq,
            listener: row.listener,
            recipientSetSha256: setSha,
          }),
          approvalEventId: row.approvalEventId,
          status: 'pending',
          nextAttemptAt: options.nextAttemptAt,
          lastErrorClass: options.errorClass,
          lastError: options.error?.slice(0, MAX_ERROR) ?? null,
        },
        select: { id: true },
      });
      await tx.emailDelivery.updateMany({
        where: {
          OR: chunk.map((d) => ({ id: d.id, receivedAt: d.receivedAt })),
          reinjectionId: row.id,
        },
        data: { reinjectionId: newRow.id, outboundQueueId: null },
      });
      created.push(newRow.id);
    }
    if (kept.length > 0) {
      const setSha = recipientSetSha256(kept.map((d) => d.address));
      try {
        await tx.deliveryReinjection.update({
          where: where(row),
          data: {
            recipientCount: kept.length,
            recipientSetSha256: setSha,
            idempotencyKey: reinjectionIdempotencyKey({
              messageId: row.messageId,
              deliverySeq: row.deliverySeq,
              listener: row.listener,
              recipientSetSha256: setSha,
            }),
          },
          select: { id: true },
        });
      } catch (err) {
        // The set hash is informational for the current row; never fail a commit over it.
        if (!isUniqueViolation(err)) throw err;
      }
    }
    return created;
  }
}
