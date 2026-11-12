import { uuidv7 } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import {
  deliveryApprovedV1,
  type EventEnvelope,
  EventTypes,
  type QuarantineReleaseRequestedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  lockLifecycle,
  type LifecycleSnapshot,
  transitionMessage,
  type TransitionOutcome,
  type TransitionRequest,
} from '@email-gateway/message-lifecycle';
import {
  evaluatePolicyPerRecipient,
  normalizeAddress,
  POLICY_REWRITABLE_SKIP_REASONS,
  type PolicyEvaluationResult,
  type PolicyInput,
  releaseDeliveryEdits,
  restrictToRecipient,
} from '@email-gateway/policy-dsl';
import {
  type ApprovalReason,
  decideRelease,
  isAccountableRequester,
  type QuarantinePlatformBounds,
  type QuarantineReleaseMode,
  type QuarantineRiskLevel,
  type QuarantineSettings,
  releaseLifecycleFor,
  type ReleaseDecision,
  type StalenessBounds,
} from '@email-gateway/quarantine';
import { deliveryObject } from '../delivery/delivery-object';
import {
  type EditedCopyResult,
  type PolicyCopyResult,
  type PolicyCopyWriter,
  policyCopyKey,
  QUARANTINE_RELEASE_HEADER,
} from '../delivery/policy-copy';
import {
  type CopyFactsReader,
  planPolicyUrlRewrite,
  type PolicyUrlRewriteConfig,
} from '../delivery/policy-url-rewrite';
import type { InconsistencySink } from '../evaluation/errors';
import { nextDeliverySeq } from '../evaluation/evaluation.service';
import type { FactsRepository } from '../evaluation/facts.repository';
import { buildInputWithDirectory } from '../evaluation/input-builder';
import type { DirectoryRepository } from '../evaluation/directory.repository';
import type { SnapshotLookup, SnapshotRepository } from '../evaluation/snapshot.repository';
import type { LifecycleMetrics } from '@email-gateway/message-lifecycle';
import { type QuarantineInconsistencySink, quarantineWrongRead } from './errors';
import { chunks, writeMessageEvent, writeQuarantineNotification } from './outbox';
import type { LatestScanRound, ReleaseFactsReader } from './release-facts';
import type { QuarantineSettingsRepository } from './settings.repository';
import type { MessageKey, QuarantineStoreWriter } from './store-writer';

/** `message_idempotency.consumer` of the release executor (topology v10, Q27). */
export const QUARANTINE_RELEASE_CONSUMER = 'policy-engine.quarantine';
/** `mail.delivery.approved.v1` carries at most 1000 recipients (P15). */
const MAX_APPROVAL_RECIPIENTS = 1000;
const HOUR_MS = 3_600_000;

/** `quarantine_releases_total{result}` of one release event. */
export type ReleaseResult =
  | 'dispatched'
  | 'approval_required'
  | 'rescan_required'
  | 'refused'
  | 'message_busy'
  | 'message_archived'
  | 'stale';

export interface ReleaseOutcome {
  result: ReleaseResult;
  mode: QuarantineReleaseMode;
  durationSeconds: number;
  /** Entries released by this event. */
  released: number;
  copy: PolicyCopyResult['result'] | EditedCopyResult['result'] | null;
}

export interface ReleaseExecutorDeps {
  facts: Pick<FactsRepository, 'read'>;
  snapshots: Pick<SnapshotRepository, 'get'>;
  directory: Pick<DirectoryRepository, 'resolve'>;
  releaseFacts: Pick<ReleaseFactsReader, 'latestScanRound' | 'staleness'>;
  settings: Pick<QuarantineSettingsRepository, 'resolve'>;
  store: Pick<QuarantineStoreWriter, 'casEntry'>;
  copies: PolicyCopyWriter;
  copyFacts: Pick<CopyFactsReader, 'read'>;
  /** HEAD of an object of the mail bucket (Q13.6: the rewritten base must still exist). */
  objectExists: (key: string, signal: AbortSignal) => Promise<boolean>;
  urlRewrite: PolicyUrlRewriteConfig;
  bannerMaxPartBytes: number;
  bounds: QuarantinePlatformBounds;
  staleness: StalenessBounds;
  copyTimeoutMs: number;
  policySink: InconsistencySink;
  sink: QuarantineInconsistencySink;
  lifecycleMetrics: LifecycleMetrics;
  logger: Logger;
  now?: () => Date;
  hrtime?: () => bigint;
  transition?: typeof transitionMessage;
  lock?: typeof lockLifecycle;
}

interface EntryRow {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  messageId: bigint;
  messageReceivedAt: Date;
  lifecycleRound: number;
  recipientId: bigint;
  rcptSeq: number;
  recipientAddress: string;
  userId: bigint | null;
  kind: 'quarantine' | 'review';
  reason: string;
  status: string;
  riskLevel: QuarantineRiskLevel | null;
  rowVersion: number;
}

interface LogRow {
  id: bigint;
  quarantineMessageId: bigint;
  organizationId: bigint;
  releasePublicId: string;
  mode: QuarantineReleaseMode;
  status: string;
  approvalRequestId: bigint | null;
  requestedByType: 'system' | 'user' | 'api_key';
  requestedById: string | null;
}

interface Requester {
  type: 'system' | 'user' | 'api_key';
  publicId: string | null;
  userId: bigint | null;
  apiKeyId: bigint | null;
}

const EDGE_REASON = {
  E14: 'quarantine_release',
  E15: 'review_release',
  E28: 'quarantine_partial_release',
} as const;

/**
 * The release executor (step 5.3 Q13.2, Q13.3, Q13.5, Q13.6, ADR-0047): one writer transaction
 * per `mail.quarantine.release_requested.v1` (inside the consumer's `processOnce`):
 *
 * 1. lock the message (`lockLifecycle`), then the release's entries (`FOR UPDATE`); every entry
 *    must be `releasing` with a `pending` release log of this release id (else `stale`: the
 *    logs are marked `stale`, nothing else changes);
 * 2. `mode = approved`: the stored approval request must be `approved` with a decider who is not
 *    the requester nor the creator of a requesting API key (separation of duties re-checked on
 *    the stored decision);
 * 3. the message state (Q5): an edge (E14/E15/E28, new round), no transition (`approved`,
 *    `delivery_*`) or blocked (`message_busy`, `message_archived`);
 * 4. authoritative re-validation on writer facts per entry (`decideRelease`): the latest
 *    completed scan round with both risk revisions, the **current** snapshot, the entry's
 *    recipient, staleness from `email_scans.completed_at` and `scan_signature_versions`;
 * 5. released entries: the release copy (S3, before commit), the lifecycle edge, recipients
 *    `quarantined → pending`, `mail.delivery.approved.v1` (`quarantine_release`,
 *    `deliverySeq` = highest + 1, the round after the edge, ≤ 1000 recipients each), entries
 *    `released`, release logs `dispatched` with the re-validation summary, actions and events;
 * 6. other entries: `approval_required` (a new `release_approval` request whose requester is
 *    the release's requester, or in `approved` mode the approved request's requester; self mode
 *    never),
 *    `rescan_required`, `refused`, `message_busy` → entries back to `held` (or
 *    `pending_approval`), the release log records why, `release_blocked` notification.
 */
export class ReleaseExecutor {
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly hrtime: () => bigint;
  private readonly transition: typeof transitionMessage;
  private readonly lock: typeof lockLifecycle;

  constructor(private readonly deps: ReleaseExecutorDeps) {
    this.logger = deps.logger.child({ component: 'quarantine-release' });
    this.now = deps.now ?? (() => new Date());
    this.hrtime = deps.hrtime ?? (() => process.hrtime.bigint());
    this.transition = deps.transition ?? transitionMessage;
    this.lock = deps.lock ?? lockLifecycle;
  }

  async execute(
    event: EventEnvelope<QuarantineReleaseRequestedV1>,
    tx: Prisma.TransactionClient,
  ): Promise<ReleaseOutcome> {
    const started = this.hrtime();
    const p = event.payload;
    const organizationId = BigInt(event.organizationId);
    const message: MessageKey = {
      messageId: BigInt(p.messageId),
      receivedAt: new Date(p.receivedAt),
      organizationId,
    };
    const now = this.now();
    const ids = { eventId: event.eventId, releaseId: p.releaseId, messageId: p.messageId };
    const done = (result: ReleaseResult, released = 0, copy: ReleaseOutcome['copy'] = null) => ({
      result,
      mode: p.mode,
      durationSeconds: Number(this.hrtime() - started) / 1e9,
      released,
      copy,
    });

    // 1. Message lock, then entries (lock order message → entries → approval requests).
    const snapshot = await this.lock(tx, {
      id: message.messageId,
      receivedAt: message.receivedAt,
      organizationId,
    });
    if (snapshot === null) {
      this.logger.warn(ids, 'release of a message that does not exist for the organization');
      return done('stale');
    }
    const entries = await this.lockEntries(tx, message, p.entryIds);
    const logs = await this.releaseLogs(tx, organizationId, p.releaseId, entries);
    const stale =
      entries.length !== p.entryIds.length ||
      entries.some((e) => e.status !== 'releasing') ||
      logs.length !== entries.length ||
      logs.some((l) => l.status !== 'pending' || l.mode !== p.mode);
    if (stale) {
      await tx.quarantineReleaseLog.updateMany({
        where: {
          organizationId,
          releasePublicId: p.releaseId,
          status: 'pending',
          quarantineMessageId: { in: entries.map((e) => e.id) },
        },
        data: { status: 'stale', completedAt: now, blockedReason: 'stale' },
      });
      this.logger.info(ids, 'release is no longer pending for its entries; ledger only');
      return done('stale');
    }
    const requester = await this.requester(tx, organizationId, logs[0]!);
    const settings = await this.deps.settings.resolve(tx, organizationId);

    // 2. Approved releases: the stored decision must be `approved` and separation of duties hold.
    let approvedReasons: ApprovalReason[] = [];
    // The requester of a new `release_approval` request (6.): the release's requester, except in
    // `approved` mode, where the release log names the approver and the request that was
    // approved names who asked (Q14: the original requester never approves the new reasons).
    let approvalRequester = requester;
    if (p.mode === 'approved') {
      const approval = await this.approval(tx, organizationId, p.approvalRequestId, entries, logs);
      if (approval === null) {
        await this.block(tx, event, {
          entries,
          logs,
          message,
          requester,
          status: 'refused',
          blockedReason: 'approval_not_valid',
          revalidation: null,
          now,
          settings,
        });
        return done('refused');
      }
      approvedReasons = approval.reasons;
      approvalRequester = approval.requester;
    }

    // 3. The message state (Q5, Q13.5).
    const lifecycle = releaseLifecycleFor(snapshot.state);
    if (lifecycle.kind === 'blocked') {
      await this.block(tx, event, {
        entries,
        logs,
        message,
        requester,
        status: lifecycle.reason === 'message_busy' ? 'message_busy' : 'refused',
        blockedReason: lifecycle.reason,
        revalidation: null,
        now,
        settings,
      });
      return done(lifecycle.reason);
    }

    // 4. Authoritative re-validation per entry on writer facts.
    const scan = await this.deps.releaseFacts.latestScanRound(tx, message);
    const staleness = await this.deps.releaseFacts.staleness(tx, message, scan);
    const loaded = await this.deps.snapshots.get(tx, organizationId);
    const input = scan === null ? null : await this.input(tx, message, scan, loaded);
    const decisions = new Map<
      bigint,
      { decision: ReleaseDecision; result: PolicyEvaluationResult | null }
    >();
    for (const e of entries) {
      let result: PolicyEvaluationResult | null = null;
      let restricted: PolicyInput | null = null;
      if (input !== null) {
        restricted = restrictToRecipient(input, e.rcptSeq, recipientOf(e));
        result = evaluatePolicyPerRecipient(restricted, loaded.compiled).message;
      }
      const decision = decideRelease({
        entry: {
          kind: e.kind,
          reason: e.reason as Parameters<typeof decideRelease>[0]['entry']['reason'],
          state: 'releasing',
          riskLevel: e.riskLevel,
        },
        mode: p.mode,
        approvedReasons,
        messageState: snapshot.state,
        scan:
          scan === null ? null : { scanId: scan.scanId.toString(), completedAt: scan.completedAt },
        result,
        input: restricted,
        staleness,
        now,
        settings,
        bounds: this.deps.staleness,
      });
      decisions.set(e.id, { decision, result });
    }

    // 6. Entries that are not released.
    const releasable = entries.filter((e) => decisions.get(e.id)!.decision.outcome === 'release');
    const blocked = entries.filter((e) => !releasable.includes(e));
    for (const e of blocked) {
      const { decision } = decisions.get(e.id)!;
      const log = logs.find((l) => l.quarantineMessageId === e.id)!;
      const revalidation = revalidationJson(decision);
      if (decision.outcome === 'approval_required' && p.mode !== 'self') {
        await this.requireApproval(tx, event, {
          entry: e,
          log,
          requester,
          approvalRequester,
          decision,
          now,
          settings,
        });
      } else {
        await this.block(tx, event, {
          entries: [e],
          logs: [log],
          message,
          requester,
          status: decision.outcome === 'rescan_required' ? 'rescan_required' : 'refused',
          blockedReason:
            decision.outcome === 'rescan_required'
              ? 'rescan_required'
              : (decision.refusal?.cause ?? decision.outcome),
          revalidation,
          now,
          settings,
          notify: false,
        });
      }
    }
    if (blocked.length > 0) await this.notifyBlocked(tx, event, organizationId, now);

    if (releasable.length === 0) {
      const first = decisions.get(blocked[0]!.id)!.decision;
      const result: ReleaseResult =
        first.outcome === 'approval_required' && p.mode !== 'self'
          ? 'approval_required'
          : first.outcome === 'rescan_required'
            ? 'rescan_required'
            : 'refused';
      this.logger.info({ ...ids, result }, 'release not dispatched');
      return done(result);
    }

    // 5. Release: copy, lifecycle, recipients, approvals, entries, logs, actions, events.
    const dispatched = await this.dispatch(tx, event, {
      message,
      snapshot,
      lifecycle,
      entries: releasable,
      logs,
      decisions,
      requester,
      scan,
      input,
      loaded,
      settings,
      now,
    });
    this.logger.info(
      { ...ids, released: releasable.length, blocked: blocked.length, copy: dispatched.copy },
      'release dispatched',
    );
    return done('dispatched', releasable.length, dispatched.copy);
  }

  private async lockEntries(
    tx: Prisma.TransactionClient,
    message: MessageKey,
    publicIds: readonly string[],
  ): Promise<EntryRow[]> {
    const locked = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM quarantine_messages
      WHERE message_id = ${message.messageId} AND message_received_at = ${message.receivedAt}
        AND public_id IN (${Prisma.join([...publicIds])})
      ORDER BY id
      FOR UPDATE`;
    if (locked.length === 0) return [];
    const rows = await tx.quarantineMessage.findMany({
      where: { id: { in: locked.map((r) => BigInt(r.id)) } },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        messageId: true,
        messageReceivedAt: true,
        lifecycleRound: true,
        recipientId: true,
        rcptSeq: true,
        recipientAddress: true,
        userId: true,
        kind: true,
        reason: true,
        status: true,
        riskLevel: true,
        rowVersion: true,
      },
      orderBy: { id: 'asc' },
    });
    for (const r of rows) {
      if (
        r.organizationId !== message.organizationId ||
        r.messageId !== message.messageId ||
        r.messageReceivedAt.getTime() !== message.receivedAt.getTime() ||
        !publicIds.includes(r.publicId)
      ) {
        quarantineWrongRead(this.deps.sink, 'entries', 'release entry echo');
      }
    }
    if (rows.length !== locked.length)
      quarantineWrongRead(this.deps.sink, 'entries', 'locked rows');
    return rows;
  }

  private async releaseLogs(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    releaseId: string,
    entries: readonly EntryRow[],
  ): Promise<LogRow[]> {
    if (entries.length === 0) return [];
    const rows = await tx.quarantineReleaseLog.findMany({
      where: { releasePublicId: releaseId, quarantineMessageId: { in: entries.map((e) => e.id) } },
      select: {
        id: true,
        quarantineMessageId: true,
        organizationId: true,
        releasePublicId: true,
        mode: true,
        status: true,
        approvalRequestId: true,
        requestedByType: true,
        requestedById: true,
      },
    });
    for (const r of rows) {
      if (
        r.organizationId !== organizationId ||
        r.releasePublicId !== releaseId ||
        !entries.some((e) => e.id === r.quarantineMessageId)
      ) {
        quarantineWrongRead(this.deps.sink, 'release_logs', 'release log echo');
      }
    }
    return rows;
  }

  /** The requester of the release (internal ids for the new rows; public id for the trail). */
  private async requester(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    log: LogRow,
  ): Promise<Requester> {
    const base: Requester = {
      type: log.requestedByType,
      publicId: log.requestedById,
      userId: null,
      apiKeyId: null,
    };
    if (log.requestedById === null) return base;
    if (log.requestedByType === 'user') {
      const user = await tx.user.findFirst({
        where: { organizationId, publicId: log.requestedById },
        select: { id: true, organizationId: true, publicId: true },
      });
      if (
        user !== null &&
        (user.organizationId !== organizationId || user.publicId !== log.requestedById)
      ) {
        quarantineWrongRead(this.deps.sink, 'users', 'requester echo');
      }
      return { ...base, userId: user?.id ?? null };
    }
    if (log.requestedByType === 'api_key') {
      const key = await tx.apiKey.findFirst({
        where: { organizationId, publicId: log.requestedById },
        select: { id: true, organizationId: true, publicId: true },
      });
      if (
        key !== null &&
        (key.organizationId !== organizationId || key.publicId !== log.requestedById)
      ) {
        quarantineWrongRead(this.deps.sink, 'users', 'api key echo');
      }
      return { ...base, apiKeyId: key?.id ?? null };
    }
    return base;
  }

  /**
   * Q14: the approved request of an approved release, re-checked on the stored decision:
   * `approved`, of one of the release's entries, decided by a user who is neither the requester
   * (the requesting user, or the creator of the requesting API key: `isAccountableRequester`)
   * nor the entry's recipient. Returns the approved reasons and the request's requester (who
   * asked, carried to a follow-up request), or null when not valid.
   */
  private async approval(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    publicId: string | null,
    entries: readonly EntryRow[],
    logs: readonly LogRow[],
  ): Promise<{ reasons: ApprovalReason[]; requester: Requester } | null> {
    if (publicId === null) return null;
    const row = await tx.quarantineApprovalRequest.findFirst({
      where: { publicId, organizationId },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        quarantineMessageId: true,
        status: true,
        approvalReasons: true,
        approvedReasons: true,
        requestedByType: true,
        requestedByUserId: true,
        requestedByApiKeyId: true,
        decidedByUserId: true,
      },
    });
    if (row === null) return null;
    if (row.organizationId !== organizationId || row.publicId !== publicId) {
      quarantineWrongRead(this.deps.sink, 'approval_requests', 'approval echo');
    }
    const keyCreator =
      row.requestedByType === 'api_key' && row.requestedByApiKeyId !== null
        ? await this.apiKeyCreator(tx, organizationId, row.requestedByApiKeyId)
        : null;
    const entry = entries.find((e) => e.id === row.quarantineMessageId);
    if (
      entry === undefined ||
      row.status !== 'approved' ||
      row.decidedByUserId === null ||
      row.decidedByUserId === row.requestedByUserId ||
      isAccountableRequester(
        {
          requestedByType: row.requestedByType,
          requestedByUserId: row.requestedByUserId?.toString() ?? null,
          requestedByApiKeyCreatorUserId: keyCreator?.toString() ?? null,
        },
        row.decidedByUserId.toString(),
      ) ||
      (entry.userId !== null && row.decidedByUserId === entry.userId) ||
      logs.some((l) => l.approvalRequestId !== null && l.approvalRequestId !== row.id)
    ) {
      return null;
    }
    const list = (v: unknown): ApprovalReason[] =>
      Array.isArray(v) ? (v.filter((x) => typeof x === 'string') as ApprovalReason[]) : [];
    return {
      reasons: [...new Set([...list(row.approvalReasons), ...list(row.approvedReasons)])],
      requester: {
        type: row.requestedByType,
        publicId: null,
        userId: row.requestedByType === 'user' ? row.requestedByUserId : null,
        apiKeyId: row.requestedByType === 'api_key' ? row.requestedByApiKeyId : null,
      },
    };
  }

  /** `api_keys.created_by_user_id` of a requesting key (Q14), echo-checked; null when gone. */
  private async apiKeyCreator(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    apiKeyId: bigint,
  ): Promise<bigint | null> {
    const key = await tx.apiKey.findFirst({
      where: { id: apiKeyId, organizationId },
      select: { id: true, organizationId: true, createdByUserId: true },
    });
    if (key === null) return null;
    if (key.id !== apiKeyId || key.organizationId !== organizationId) {
      quarantineWrongRead(this.deps.sink, 'approval_requests', 'api key creator echo');
    }
    return key.createdByUserId;
  }

  /** P8 facts of the latest completed round (an older round is allowed) and the input. */
  private async input(
    tx: Prisma.TransactionClient,
    message: MessageKey,
    scan: LatestScanRound,
    loaded: SnapshotLookup,
  ): Promise<PolicyInput | null> {
    const facts = await this.deps.facts.read(tx, {
      ...message,
      round: scan.round,
      trigger: scan.status === 'completed' ? 'scanned' : 'scan_failed',
      scanId: scan.scanId,
      olderRoundAllowed: true,
    });
    try {
      return await buildInputWithDirectory(
        tx,
        this.deps.directory,
        message.organizationId,
        facts,
        loaded.compiled,
      );
    } catch (error) {
      this.logger.warn(
        { messageId: message.messageId.toString(), errName: (error as Error).name },
        'release re-validation cannot build the policy input; treated as a missing scan round',
      );
      return null;
    }
  }

  private async requireApproval(
    tx: Prisma.TransactionClient,
    event: EventEnvelope<QuarantineReleaseRequestedV1>,
    c: {
      entry: EntryRow;
      log: LogRow;
      /** The release's requester (actor of the `release_blocked` action). */
      requester: Requester;
      /** The new request's requester (the approved request's requester in `approved` mode). */
      approvalRequester: Requester;
      decision: ReleaseDecision;
      now: Date;
      settings: QuarantineSettings;
    },
  ): Promise<void> {
    const { entry, now } = c;
    const request = await tx.quarantineApprovalRequest.create({
      data: {
        organizationId: entry.organizationId,
        quarantineMessageId: entry.id,
        kind: 'release_approval',
        status: 'pending',
        approvalReasons: c.decision.approvalReasons,
        requestedByType: c.approvalRequester.type,
        requestedByUserId: c.approvalRequester.userId,
        requestedByApiKeyId: c.approvalRequester.apiKeyId,
        expiresAt: new Date(now.getTime() + c.settings.approvals.requestTtlHours * HOUR_MS),
      },
      select: { id: true, publicId: true },
    });
    await this.deps.store.casEntry(tx, entry, {
      status: 'pending_approval',
      stateChangedAt: now,
      approvalRequestId: request.id,
    });
    await this.completeLog(tx, c.log, now, {
      status: 'approval_required',
      blockedReason: 'approval_required',
      revalidation: revalidationJson(c.decision),
      approvalRequestId: request.id,
    });
    await this.action(
      tx,
      entry,
      c.requester,
      'release_blocked',
      'approval_required',
      c.log.id,
      {
        approvalReasons: c.decision.approvalReasons.join(','),
      },
      request.id,
    );
    if (c.settings.alerts.approvalRequests) {
      await writeQuarantineNotification(tx, {
        organizationId: entry.organizationId,
        correlationId: event.correlationId,
        at: now,
        payload: {
          kind: 'approval_requested',
          refs: {
            approvalRequestIds: [request.publicId],
            entryId: entry.publicId,
            releaseId: event.payload.releaseId,
          },
          requestedAt: now.toISOString(),
        },
      });
    }
  }

  /** Entries back to `held`, release logs completed with `status`, actions and (optionally) a notice. */
  private async block(
    tx: Prisma.TransactionClient,
    event: EventEnvelope<QuarantineReleaseRequestedV1>,
    c: {
      entries: readonly EntryRow[];
      logs: readonly LogRow[];
      message: MessageKey;
      requester: Requester;
      status: 'refused' | 'rescan_required' | 'message_busy';
      blockedReason: string;
      revalidation: Prisma.InputJsonValue | null;
      now: Date;
      settings: QuarantineSettings;
      notify?: boolean;
    },
  ): Promise<void> {
    for (const e of c.entries) {
      await this.deps.store.casEntry(tx, e, { status: 'held', stateChangedAt: c.now });
      const log = c.logs.find((l) => l.quarantineMessageId === e.id)!;
      await this.completeLog(tx, log, c.now, {
        status: c.status,
        blockedReason: c.blockedReason.slice(0, 64),
        revalidation: c.revalidation,
      });
      await this.action(tx, e, c.requester, 'release_blocked', c.status, log.id, {
        cause: c.blockedReason.slice(0, 64),
      });
    }
    if (c.notify !== false) await this.notifyBlocked(tx, event, c.message.organizationId, c.now);
  }

  private async notifyBlocked(
    tx: Prisma.TransactionClient,
    event: EventEnvelope<QuarantineReleaseRequestedV1>,
    organizationId: bigint,
    now: Date,
  ): Promise<void> {
    // The requesting user only (the notification-worker resolves it; API keys get none).
    if (event.payload.requestedBy.type !== 'user') return;
    await writeQuarantineNotification(tx, {
      organizationId,
      correlationId: event.correlationId,
      at: now,
      payload: {
        kind: 'release_blocked',
        refs: { releaseId: event.payload.releaseId, userId: event.payload.requestedBy.id! },
        requestedAt: now.toISOString(),
      },
    });
  }

  private async completeLog(
    tx: Prisma.TransactionClient,
    log: LogRow,
    now: Date,
    data: {
      status: 'dispatched' | 'approval_required' | 'rescan_required' | 'refused' | 'message_busy';
      blockedReason?: string | null;
      revalidation: Prisma.InputJsonValue | null;
      approvalRequestId?: bigint;
      extra?: Prisma.QuarantineReleaseLogUncheckedUpdateManyInput;
    },
  ): Promise<void> {
    const updated = await tx.quarantineReleaseLog.updateMany({
      where: { id: log.id, status: 'pending' },
      data: {
        status: data.status,
        completedAt: now,
        blockedReason: data.blockedReason ?? null,
        ...(data.revalidation === null ? {} : { revalidation: data.revalidation }),
        ...(data.extra ?? {}),
      },
    });
    if (updated.count !== 1) quarantineWrongRead(this.deps.sink, 'release_logs', 'log CAS');
  }

  private async action(
    tx: Prisma.TransactionClient,
    entry: EntryRow,
    requester: Requester,
    action: 'release' | 'release_blocked',
    result: string,
    releaseLogId: bigint,
    details: Record<string, string | number | boolean | null>,
    approvalRequestId?: bigint,
  ): Promise<void> {
    await tx.quarantineAction.create({
      data: {
        organizationId: entry.organizationId,
        quarantineMessageId: entry.id,
        action,
        actorType: 'system',
        actorId: requester.publicId,
        result,
        details: { ...details, requestedByType: requester.type },
        releaseLogId,
        approvalRequestId: approvalRequestId ?? null,
      },
      select: { id: true },
    });
  }

  private async dispatch(
    tx: Prisma.TransactionClient,
    event: EventEnvelope<QuarantineReleaseRequestedV1>,
    c: {
      message: MessageKey;
      snapshot: LifecycleSnapshot;
      lifecycle: ReturnType<typeof releaseLifecycleFor>;
      entries: readonly EntryRow[];
      logs: readonly LogRow[];
      decisions: Map<bigint, { decision: ReleaseDecision; result: PolicyEvaluationResult | null }>;
      requester: Requester;
      scan: LatestScanRound | null;
      input: PolicyInput | null;
      loaded: SnapshotLookup;
      settings: QuarantineSettings;
      now: Date;
    },
  ): Promise<{ copy: ReleaseOutcome['copy'] }> {
    const p = event.payload;
    const { message, now } = c;
    // The round after the edge (new round for E14/E15/E28; the current one otherwise).
    let roundAfter = c.snapshot.round;
    let transition: TransitionOutcome | null = null;
    if (c.lifecycle.kind === 'edge') {
      const request: TransitionRequest = {
        message: {
          id: message.messageId,
          receivedAt: message.receivedAt,
          organizationId: message.organizationId,
        },
        to: 'approved',
        reason: EDGE_REASON[c.lifecycle.edge],
        actor: {
          role: 'quarantine',
          service: 'policy-engine',
          type: p.requestedBy.type,
          id: p.requestedBy.id,
        },
        transitionKey: `release:${p.releaseId}:approved`,
        causationEventId: event.eventId,
        correlationId: event.correlationId,
        expectedFrom: [c.snapshot.state],
        expectedVersion: c.snapshot.version,
      };
      transition = await this.transition(tx, request, {
        metrics: this.deps.lifecycleMetrics,
        logger: this.logger,
      });
      if (transition.result !== 'applied') {
        // Impossible under the message lock taken above: retry from scratch.
        return quarantineWrongRead(this.deps.sink, 'message', `release edge ${transition.result}`);
      }
      roundAfter = transition.round;
    }

    // The delivered object (Q13.6): the latest round's rewritten copy if it still exists.
    const signal = AbortSignal.timeout(this.deps.copyTimeoutMs);
    let base = { key: c.snapshot.emlObjectKey, object: 'original' as 'original' | 'rewritten' };
    if (c.scan !== null) {
      const rewritten = await deliveryObject(
        tx,
        {
          messageId: message.messageId,
          receivedAt: message.receivedAt,
          organizationId: message.organizationId,
          round: c.scan.round,
          scanId: c.scan.scanId,
          original: c.snapshot.emlObjectKey,
        },
        this.deps.policySink,
      );
      if (
        rewritten.object === 'rewritten' &&
        (await this.deps.objectExists(rewritten.key, signal))
      ) {
        base = { key: rewritten.key, object: 'rewritten' };
      }
    }
    const results = c.entries
      .map((e) => c.decisions.get(e.id)!.result)
      .filter((r): r is PolicyEvaluationResult => r !== null);
    const edits =
      results.length === 0
        ? null
        : releaseDeliveryEdits(
            { actions: results.flatMap((r) => r.actions), round: results[0]!.round },
            c.loaded.compiled.settings,
          );
    const headers = [
      ...(edits?.headers ?? []),
      { name: QUARANTINE_RELEASE_HEADER, value: p.releaseId },
    ];
    const headerEdits = { headers, subjectPrefix: edits?.subjectPrefix ?? null };
    const banner = edits?.banner ?? null;
    let rewritePlan = null;
    let rewriteRecord: { status: 'rewritten' | 'skipped'; skipReason: string | null } | null = null;
    // Q23 on a release copy: only a round skipped because the tenant's 4.3 setting was off can
    // be rewritten by the policy-engine; any other skip is recorded (the operator released).
    const urls = c.input?.urls ?? null;
    const policyRewritable =
      urls !== null &&
      urls.rewriteStatus === 'skipped' &&
      urls.rewriteSkipReason !== null &&
      (POLICY_REWRITABLE_SKIP_REASONS as readonly string[]).includes(urls.rewriteSkipReason);
    let copyFacts = null;
    if (edits?.urlRewrite && base.object !== 'rewritten') {
      copyFacts = await this.deps.copyFacts.read(tx, message);
      if (policyRewritable) {
        const planned = planPolicyUrlRewrite(copyFacts, this.deps.urlRewrite, {
          direction: c.snapshot.direction,
          messageSizeBytes: c.input?.message.sizeBytes ?? 0,
          organizationId: message.organizationId,
          messageId: message.messageId,
          receivedAt: message.receivedAt,
          now,
        });
        if ('skip' in planned) rewriteRecord = { status: 'skipped', skipReason: planned.skip };
        else rewritePlan = planned.plan;
      } else {
        rewriteRecord = { status: 'skipped', skipReason: 'not_policy_rewritable' };
      }
    }
    if (banner !== null && copyFacts === null)
      copyFacts = await this.deps.copyFacts.read(tx, message);
    const key = policyCopyKey({
      organizationId: message.organizationId,
      messageId: message.messageId,
      receivedAt: message.receivedAt,
      round: roundAfter,
      baseKey: base.key,
      edits: headerEdits,
      body: { banner, urlRewrite: rewritePlan !== null },
      releaseId: p.releaseId,
    });
    let copy: ReleaseOutcome['copy'];
    let bannerStatus: string | null = null;
    let copyKey: string | null = null;
    if (banner === null && rewritePlan === null) {
      const written = await this.deps.copies.write({
        baseKey: base.key,
        key,
        edits: headerEdits,
        signal,
      });
      copy = written.result;
      if (written.result === 'written') copyKey = written.key;
    } else {
      const written = await this.deps.copies.writeEdited({
        baseKey: base.key,
        key,
        edits: headerEdits,
        plan: {
          urlRewrite: rewritePlan,
          banner:
            banner === null ? null : { ...banner, maxPartBytes: this.deps.bannerMaxPartBytes },
          structure: copyFacts?.structure ?? null,
        },
        signal,
      });
      copy = written.result;
      bannerStatus = written.banner;
      if (written.urlRewrite !== null) rewriteRecord = written.urlRewrite;
      if (written.result === 'written' && written.key !== undefined) copyKey = written.key;
    }
    const emlS3Key = copyKey ?? base.key;
    const deliveredObject = copyKey !== null ? 'policy_copy' : base.object;
    const copyRefused = copy === 'too_large' || copy === 'header_too_large';

    // Recipients quarantined → pending (before any approval: L10.3 ordering).
    const recipientIds = c.entries.map((e) => e.recipientId);
    const reset = await tx.emailRecipient.updateMany({
      where: {
        id: { in: recipientIds },
        messageId: message.messageId,
        receivedAt: message.receivedAt,
        organizationId: message.organizationId,
        status: 'quarantined',
      },
      data: { status: 'pending', finalAction: 'deliver' },
    });
    if (reset.count !== recipientIds.length) {
      quarantineWrongRead(this.deps.sink, 'recipient_update', 'released recipients');
    }

    // Approvals (`quarantine_release`, the round after the edge, ≤ 1000 recipients each).
    const deliverySeq = await nextDeliverySeq(tx, message);
    const approvalEventIds: string[] = [];
    const ordered = [...c.entries].sort((a, b) => a.rcptSeq - b.rcptSeq);
    for (const part of chunks(ordered, MAX_APPROVAL_RECIPIENTS)) {
      const approvalId = uuidv7(now.getTime());
      await tx.messageOutbox.create({
        data: {
          eventId: approvalId,
          organizationId: message.organizationId,
          eventType: EventTypes.DeliveryApproved,
          aggregateType: 'message',
          aggregateId: message.messageId.toString(),
          correlationId: event.correlationId,
          payload: deliveryApprovedV1.parse({
            messageId: message.messageId.toString(),
            receivedAt: message.receivedAt.toISOString(),
            deliverySeq,
            lifecycleRound: roundAfter,
            source: 'quarantine_release',
            emlS3Key,
            recipients: part.map((e) => ({
              recipientId: e.recipientId.toString(),
              rcptSeq: e.rcptSeq,
            })),
            approvedAt: now.toISOString(),
          }),
        },
        select: { id: true },
      });
      await writeMessageEvent(tx, {
        ...message,
        eventType: 'delivery.approved',
        at: now,
        eventId: approvalId,
        details: {
          source: 'quarantine_release',
          approvalEventId: approvalId,
          deliverySeq,
          lifecycleRound: roundAfter,
          recipientCount: part.length,
        },
      });
      approvalEventIds.push(approvalId);
    }

    // Entries released, logs dispatched, actions, events.
    const decidedByUserId = c.requester.type === 'user' ? c.requester.userId : null;
    for (const e of c.entries) {
      const { decision } = c.decisions.get(e.id)!;
      await this.deps.store.casEntry(tx, e, {
        status: 'released',
        stateChangedAt: now,
        releasedAt: now,
        decidedAt: now,
        decidedByType: c.requester.type,
        decidedByUserId,
        terminalReason: 'released',
      });
      const log = c.logs.find((l) => l.quarantineMessageId === e.id)!;
      await this.completeLog(tx, log, now, {
        status: 'dispatched',
        revalidation: {
          ...(revalidationJson(decision) as Record<string, unknown>),
          copy: {
            result: copy,
            banner: bannerStatus,
            urlRewrite: rewriteRecord,
            tagWarn: copyRefused ? 'recorded' : copyKey !== null ? 'enforced' : 'not_applicable',
          },
        },
        extra: {
          deliveredObject,
          objectKey: copyKey,
          deliverySeq,
          approvalEventIds,
          lifecycleRoundAfter: roundAfter,
          revalidationScanId: c.scan?.scanId ?? null,
          revalidationVerdict: c.decisions.get(e.id)!.result?.finalVerdict ?? null,
        },
      });
      await this.action(tx, e, c.requester, 'release', 'dispatched', log.id, {
        deliverySeq,
        roundAfter,
        object: deliveredObject,
      });
    }
    await writeMessageEvent(tx, {
      ...message,
      eventType: 'quarantine.released',
      at: now,
      details: {
        entries: c.entries.length,
        mode: p.mode,
        deliverySeq,
        roundAfter,
        edge: c.lifecycle.kind === 'edge' ? c.lifecycle.edge : null,
        object: deliveredObject,
      },
    });
    return { copy };
  }
}

/** The recipient of an entry for `restrictToRecipient` (beyond the input's 1 000 window). */
function recipientOf(e: EntryRow): PolicyInput['recipients'][number] {
  const n = normalizeAddress(e.recipientAddress);
  return {
    rcptSeq: e.rcptSeq,
    address: n.address,
    domain: n.domain,
    localPart: n.localPart,
    departments: [],
    users: [],
  };
}

/** The content-free re-validation record of a release log (Q13.3 summary, reasons, staleness). */
function revalidationJson(decision: ReleaseDecision): Prisma.InputJsonValue {
  return {
    outcome: decision.outcome,
    approvalReasons: decision.approvalReasons,
    refusal: decision.refusal ?? null,
    staleness: decision.staleness,
    summary: decision.summary,
  } as unknown as Prisma.InputJsonValue;
}
