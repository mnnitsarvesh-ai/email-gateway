import type { Prisma } from '@email-gateway/database';
import {
  computeExpiry,
  type QuarantineEntryKind,
  type QuarantineOrigin,
  type QuarantineSettings,
} from '@email-gateway/quarantine';
import type { EntryFacts } from './entry-facts';
import { type QuarantineInconsistencySink, quarantineWrongRead } from './errors';
import { chunks, writeMessageEvent, writeQuarantineNotification } from './outbox';

/** States an entry can leave (Q3); everything else is terminal. */
export const NON_TERMINAL_STATES = ['held', 'pending_approval', 'releasing'] as const;

export interface MessageKey {
  messageId: bigint;
  receivedAt: Date;
  organizationId: bigint;
}

/** One recipient that gets an entry (a Q or H recipient of Q5, or an adopted recipient). */
export interface EntryCandidate {
  recipientId: bigint;
  rcptSeq: number;
  address: string;
  kind: QuarantineEntryKind;
  facts: EntryFacts;
}

export interface CreateEntriesInput {
  message: MessageKey & {
    round: number;
    scanId: bigint | null;
    direction: 'inbound' | 'outbound' | 'internal';
    envelopeFrom: string;
    headerFrom: string | null;
    sizeBytes: number;
    attachmentCount: number;
    /** The **original** EML (`email_messages.eml_object_key`). */
    emlObjectKey: string;
  };
  origin: Exclude<QuarantineOrigin, 'manual'>;
  candidates: EntryCandidate[];
  settings: QuarantineSettings;
  bounds: { maxHoldDays: number; maxReviewDays: number };
  /** `quarantined_at` (evaluation or adoption time). */
  now: Date;
  /** Adoption (Q8): `expires_at = max(now + 1 day, computeExpiry(received_at))`. */
  expiryFrom?: Date;
  /** `policy_version_id` of the decisive version by `<policyPublicId>#<versionNo>`. */
  policyVersionIds?: Readonly<Record<string, string>>;
  correlationId: string;
  /** Extra `quarantine_actions.details` (ids, counts). */
  actionDetails?: Record<string, string | number | boolean | null>;
}

export interface CreatedEntry {
  id: bigint;
  publicId: string;
  rcptSeq: number;
  kind: QuarantineEntryKind;
  reason: string;
  direction: string;
  hasHardBlock: boolean;
  approvalRequestPublicId: string | null;
}

export interface CreateEntriesResult {
  created: CreatedEntry[];
  /** `approval_requested` notification events written. */
  notifications: number;
}

const DAY_MS = 86_400_000;
const NOTIFICATION_IDS = 50;

/**
 * The quarantine store writer of the policy-engine (step 5.3 Q2, Q5, Q6, Q8): every write runs
 * in the caller's writer transaction after the message lifecycle lock (lock order message →
 * entries → approval requests). Entry state changes are compare-and-set on `row_version`;
 * reads are echo-checked (§6). Content-free: ids, enums, codes, addresses already stored by
 * earlier steps; `subject` is never written.
 */
export class QuarantineStoreWriter {
  constructor(private readonly sink: QuarantineInconsistencySink) {}

  /**
   * Q5 rescan interplay, before a round is decided: every non-terminal entry of an earlier round
   * → `superseded` (its pending approval requests → `cancelled`), then every `quarantined`
   * recipient → `pending` (re-decided by this round). Returns the number of superseded entries.
   */
  async supersedeEarlierRounds(
    tx: Prisma.TransactionClient,
    message: MessageKey,
    round: number,
    now: Date,
  ): Promise<number> {
    const locked = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM quarantine_messages
      WHERE message_id = ${message.messageId} AND message_received_at = ${message.receivedAt}
        AND lifecycle_round < ${round} AND status IN ('held', 'pending_approval', 'releasing')
      ORDER BY id
      FOR UPDATE`;
    let superseded = 0;
    if (locked.length > 0) {
      const ids = locked.map((r) => BigInt(r.id));
      const entries = await tx.quarantineMessage.findMany({
        where: { id: { in: ids } },
        select: {
          id: true,
          organizationId: true,
          messageId: true,
          lifecycleRound: true,
          status: true,
          rowVersion: true,
        },
      });
      if (entries.length !== ids.length) quarantineWrongRead(this.sink, 'entries', 'locked rows');
      for (const e of entries) {
        if (
          e.organizationId !== message.organizationId ||
          e.messageId !== message.messageId ||
          e.lifecycleRound >= round ||
          !(NON_TERMINAL_STATES as readonly string[]).includes(e.status)
        ) {
          quarantineWrongRead(this.sink, 'entries', 'supersede echo');
        }
      }
      await this.cancelPendingRequests(tx, message.organizationId, ids, 'cancelled', now);
      for (const e of entries) {
        await this.casEntry(tx, e, {
          status: 'superseded',
          stateChangedAt: now,
          terminalReason: 'superseded',
          decidedAt: now,
          decidedByType: 'system',
        });
      }
      await tx.quarantineAction.createMany({
        data: entries.map((e) => ({
          organizationId: message.organizationId,
          quarantineMessageId: e.id,
          action: 'supersede' as const,
          actorType: 'system' as const,
          result: 'superseded',
          details: { fromRound: e.lifecycleRound, byRound: round },
        })),
      });
      superseded = entries.length;
    }
    await tx.emailRecipient.updateMany({
      where: {
        messageId: message.messageId,
        receivedAt: message.receivedAt,
        organizationId: message.organizationId,
        status: 'quarantined',
      },
      data: { status: 'pending', finalAction: null },
    });
    return superseded;
  }

  /**
   * `pending` approval requests of the given entries → `status` (`cancelled` or `expired`), CAS
   * on `row_version`. Returns the public ids of the requests changed.
   */
  async cancelPendingRequests(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    entryIds: readonly bigint[],
    status: 'cancelled' | 'expired',
    now: Date,
  ): Promise<string[]> {
    if (entryIds.length === 0) return [];
    const requests = await tx.quarantineApprovalRequest.findMany({
      where: { quarantineMessageId: { in: [...entryIds] }, status: 'pending' },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        quarantineMessageId: true,
        status: true,
        rowVersion: true,
      },
    });
    for (const r of requests) {
      if (
        r.organizationId !== organizationId ||
        !entryIds.includes(r.quarantineMessageId) ||
        r.status !== 'pending'
      ) {
        quarantineWrongRead(this.sink, 'approval_requests', 'pending echo');
      }
      const updated = await tx.quarantineApprovalRequest.updateMany({
        where: { id: r.id, rowVersion: r.rowVersion, status: 'pending' },
        data: { status, decidedAt: now, rowVersion: { increment: 1 } },
      });
      if (updated.count !== 1) quarantineWrongRead(this.sink, 'approval_requests', 'request CAS');
    }
    return requests.map((r) => r.publicId);
  }

  /** One compare-and-set entry update (`row_version` + 1); exactly one row expected. */
  async casEntry(
    tx: Prisma.TransactionClient,
    entry: { id: bigint; rowVersion: number; status: string },
    data: Prisma.QuarantineMessageUncheckedUpdateManyInput,
  ): Promise<void> {
    const updated = await tx.quarantineMessage.updateMany({
      where: {
        id: entry.id,
        rowVersion: entry.rowVersion,
        status: entry.status as Prisma.EnumQuarantineStatusFilter['equals'],
      },
      data: { ...data, rowVersion: { increment: 1 } },
    });
    if (updated.count !== 1) quarantineWrongRead(this.sink, 'entry_update', 'entry CAS');
  }

  /**
   * Q5 recipient outcomes: `pending` recipients → `quarantined` / `discarded` with their
   * per-recipient `final_action`; allowed recipients keep `pending` and get theirs. Exactly the
   * named rows must change (CAS on the `pending` status).
   */
  async setRecipientOutcomes(
    tx: Prisma.TransactionClient,
    message: MessageKey,
    outcomes: ReadonlyArray<{
      id: bigint;
      status: 'pending' | 'quarantined' | 'discarded';
      finalAction: 'deliver' | 'tag' | 'quarantine' | 'require_approval' | 'discard' | 'reject';
    }>,
  ): Promise<void> {
    const groups = new Map<string, bigint[]>();
    for (const o of outcomes) {
      const key = `${o.status}|${o.finalAction}`;
      groups.set(key, [...(groups.get(key) ?? []), o.id]);
    }
    for (const [key, ids] of groups) {
      const [status, finalAction] = key.split('|') as [
        'pending' | 'quarantined' | 'discarded',
        'deliver' | 'tag' | 'quarantine' | 'require_approval' | 'discard' | 'reject',
      ];
      for (const part of chunks(ids, 1000)) {
        const updated = await tx.emailRecipient.updateMany({
          where: {
            id: { in: part },
            messageId: message.messageId,
            receivedAt: message.receivedAt,
            organizationId: message.organizationId,
            status: 'pending',
          },
          data: { status, finalAction },
        });
        if (updated.count !== part.length) {
          quarantineWrongRead(this.sink, 'recipient_update', 'pending recipients');
        }
      }
    }
  }

  /** The organization's active, non-deleted users by lower-cased e-mail (informational). */
  async usersByAddress(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    addresses: readonly string[],
  ): Promise<Map<string, bigint>> {
    const wanted = [...new Set(addresses.map((a) => a.toLowerCase()))];
    const map = new Map<string, bigint>();
    for (const part of chunks(wanted, 500)) {
      const users = await tx.user.findMany({
        where: { organizationId, email: { in: part }, status: 'active', deletedAt: null },
        select: { id: true, organizationId: true, email: true, status: true, deletedAt: true },
        orderBy: { id: 'asc' },
      });
      for (const u of users) {
        if (u.organizationId !== organizationId || u.status !== 'active' || u.deletedAt !== null) {
          quarantineWrongRead(this.sink, 'users', 'user echo');
        }
        const address = u.email.toLowerCase();
        if (part.includes(address) && !map.has(address)) map.set(address, u.id);
      }
    }
    return map;
  }

  /**
   * Q6 / Q8: one entry per candidate (`createMany skipDuplicates` on `(message_id,
   * lifecycle_round, rcpt_seq)`), a `policy_review` approval request per review entry, one
   * `quarantine_actions` row per entry (`quarantine`, or `adopt`), `email_events`
   * `quarantine.created` per kind and, when review entries were created and
   * `alerts.approvalRequests` is on, `approval_requested` notifications (≤ 50 request ids each).
   * Entries that already existed (the unique key is the backstop of a duplicate) are left alone.
   */
  async createEntries(
    tx: Prisma.TransactionClient,
    input: CreateEntriesInput,
  ): Promise<CreateEntriesResult> {
    const { message, now } = input;
    if (input.candidates.length === 0) return { created: [], notifications: 0 };
    const users = await this.usersByAddress(
      tx,
      message.organizationId,
      input.candidates.map((c) => c.address),
    );
    const expiry = (kind: QuarantineEntryKind): Date => {
      const computed = computeExpiry({
        kind,
        quarantinedAt: input.expiryFrom ?? now,
        holdDays: input.settings.hold.days,
        reviewDays: input.settings.review.days,
        maxHoldDays: input.bounds.maxHoldDays,
        maxReviewDays: input.bounds.maxReviewDays,
      });
      if (input.expiryFrom === undefined) return computed;
      return new Date(Math.max(now.getTime() + DAY_MS, computed.getTime()));
    };
    const versionId = (f: EntryFacts): bigint | null => {
      if (f.decisivePolicyPublicId === null || f.decisivePolicyVersionNo === null) return null;
      const id =
        input.policyVersionIds?.[`${f.decisivePolicyPublicId}#${f.decisivePolicyVersionNo}`];
      return id === undefined ? null : BigInt(id);
    };
    const rows = input.candidates.map((c) => {
      const address = c.address.toLowerCase();
      const f = c.facts;
      return {
        organizationId: message.organizationId,
        messageId: message.messageId,
        messageReceivedAt: message.receivedAt,
        lifecycleRound: message.round,
        scanId: message.scanId,
        evaluationSeq: input.origin === 'policy' ? message.round : null,
        recipientId: c.recipientId,
        rcptSeq: c.rcptSeq,
        recipientAddress: address,
        userId: users.get(address) ?? null,
        direction: message.direction,
        kind: c.kind,
        origin: input.origin,
        reason: f.reason,
        policyVersionId: versionId(f),
        status: c.kind === 'review' ? ('pending_approval' as const) : ('held' as const),
        envelopeFrom: message.envelopeFrom,
        headerFrom: message.headerFrom,
        hasAttachments: message.attachmentCount > 0,
        attachmentCount: Math.min(message.attachmentCount, 65_535),
        sizeBytes: Math.min(message.sizeBytes, 4_294_967_295),
        riskScore: f.riskScore,
        riskLevel: f.riskLevel,
        recommendedAction: f.recommendedAction,
        riskVerdict: f.riskVerdict,
        hasHardBlock: f.hardBlocks.length > 0,
        hardBlocks: f.hardBlocks,
        reasonCodes: f.reasonCodes,
        floorReasons: f.floorReasons,
        primaryEngine: f.primaryEngine,
        decisionSource: f.decisionSource,
        decisivePolicyPublicId: f.decisivePolicyPublicId,
        decisivePolicyVersionNo: f.decisivePolicyVersionNo,
        decisiveRuleId: f.decisiveRuleId,
        explanation: f.explanation,
        explanationText: f.explanationText,
        emlObjectKey: message.emlObjectKey,
        quarantinedAt: now,
        expiresAt: expiry(c.kind),
        stateChangedAt: now,
        rowVersion: 1,
      };
    });
    for (const part of chunks(rows, 500)) {
      await tx.quarantineMessage.createMany({ data: part, skipDuplicates: true });
    }
    const seqs = input.candidates.map((c) => c.rcptSeq);
    const stored = await tx.quarantineMessage.findMany({
      where: {
        messageId: message.messageId,
        lifecycleRound: message.round,
        rcptSeq: { in: seqs },
      },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        messageId: true,
        messageReceivedAt: true,
        lifecycleRound: true,
        rcptSeq: true,
        kind: true,
        reason: true,
        direction: true,
        status: true,
        hasHardBlock: true,
        expiresAt: true,
        rowVersion: true,
        _count: { select: { actions: true } },
      },
      orderBy: { rcptSeq: 'asc' },
    });
    for (const e of stored) {
      if (
        e.organizationId !== message.organizationId ||
        e.messageId !== message.messageId ||
        e.messageReceivedAt.getTime() !== message.receivedAt.getTime() ||
        e.lifecycleRound !== message.round ||
        !seqs.includes(e.rcptSeq)
      ) {
        quarantineWrongRead(this.sink, 'entries', 'created echo');
      }
    }
    if (stored.length !== seqs.length) quarantineWrongRead(this.sink, 'entries', 'created count');
    // Only entries without an action row are new (an existing one was created earlier).
    const fresh = stored.filter((e) => e._count.actions === 0);
    const byRcpt = new Map(input.candidates.map((c) => [c.rcptSeq, c]));
    const created: CreatedEntry[] = [];
    for (const e of fresh) {
      let approvalRequestPublicId: string | null = null;
      if (e.kind === 'review' && e.status === 'pending_approval') {
        const facts = byRcpt.get(e.rcptSeq)!.facts;
        const request = await tx.quarantineApprovalRequest.create({
          data: {
            organizationId: message.organizationId,
            quarantineMessageId: e.id,
            kind: 'policy_review',
            status: 'pending',
            approvalReasons: facts.approvalReasons,
            requestedByType: 'system',
            expiresAt: e.expiresAt,
          },
          select: { id: true, publicId: true },
        });
        const linked = await tx.quarantineMessage.updateMany({
          where: { id: e.id, rowVersion: e.rowVersion, approvalRequestId: null },
          data: { approvalRequestId: request.id },
        });
        if (linked.count !== 1) quarantineWrongRead(this.sink, 'entry_update', 'approval link');
        approvalRequestPublicId = request.publicId;
      }
      created.push({
        id: e.id,
        publicId: e.publicId,
        rcptSeq: e.rcptSeq,
        kind: e.kind,
        reason: e.reason,
        direction: e.direction,
        hasHardBlock: e.hasHardBlock,
        approvalRequestPublicId,
      });
    }
    if (created.length === 0) return { created, notifications: 0 };
    await tx.quarantineAction.createMany({
      data: created.map((e) => ({
        organizationId: message.organizationId,
        quarantineMessageId: e.id,
        action: input.origin === 'adopted' ? ('adopt' as const) : ('quarantine' as const),
        actorType: 'system' as const,
        result: e.kind === 'review' ? 'pending_approval' : 'held',
        details: {
          origin: input.origin,
          evaluationSeq: input.origin === 'policy' ? message.round : null,
          ...(input.actionDetails ?? {}),
        },
      })),
    });
    for (const kind of ['quarantine', 'review'] as const) {
      const n = created.filter((e) => e.kind === kind).length;
      if (n === 0) continue;
      await writeMessageEvent(tx, {
        messageId: message.messageId,
        receivedAt: message.receivedAt,
        organizationId: message.organizationId,
        eventType: 'quarantine.created',
        at: now,
        details: { entries: n, kind, origin: input.origin, round: message.round },
      });
    }
    let notifications = 0;
    const requestIds = created
      .map((e) => e.approvalRequestPublicId)
      .filter((id): id is string => id !== null);
    if (requestIds.length > 0 && input.settings.alerts.approvalRequests) {
      for (const part of chunks(requestIds, NOTIFICATION_IDS)) {
        await writeQuarantineNotification(tx, {
          organizationId: message.organizationId,
          correlationId: input.correlationId,
          at: now,
          payload: {
            kind: 'approval_requested',
            refs: {
              approvalRequestIds: part,
              messageId: message.messageId.toString(),
              receivedAt: message.receivedAt.toISOString(),
            },
            requestedAt: now.toISOString(),
          },
        });
        notifications += 1;
      }
    }
    return { created, notifications };
  }
}
