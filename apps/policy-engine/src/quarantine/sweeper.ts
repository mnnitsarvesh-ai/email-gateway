import {
  backoffDelay,
  sleep as defaultSleep,
  withTransactionDefaults,
} from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  type LifecycleMetrics,
  lockLifecycle,
  transitionMessage,
} from '@email-gateway/message-lifecycle';
import { rowToEvaluationView } from '@email-gateway/policy-dsl';
import {
  decideObjectDisposal,
  type ObjectDisposal,
  type QuarantinePlatformBounds,
} from '@email-gateway/quarantine';
import type { QuarantineMetrics } from '../metrics/quarantine-metrics';
import type { DigestScheduler } from './digest-scheduler';
import {
  type DisposalFactsReader,
  isOrganizationKey,
  messageObjectPrefixes,
  type QuarantineObjects,
} from './disposal';
import { entryFactsFromView } from './entry-facts';
import { type QuarantineInconsistencySink, quarantineWrongRead } from './errors';
import { chunks, writeMessageEvent, writeQuarantineNotification } from './outbox';
import type { QuarantineSettingsRepository } from './settings.repository';
import {
  type EntryCandidate,
  type MessageKey,
  NON_TERMINAL_STATES,
  type QuarantineStoreWriter,
} from './store-writer';

/** One cluster-wide leader (Q19). */
export const QUARANTINE_SWEEPER_LOCK = 'eg:quarantine-sweeper';
/** Batches per step and pass (bounded work per tick; the next pass continues). */
const MAX_BATCHES = 10;
const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
/** Download grants are kept one day after expiry (§3 retention), digest runs 90 days. */
const GRANT_RETENTION_MS = DAY_MS;
const DIGEST_RETENTION_MS = 90 * DAY_MS;
const TERMINAL_STATES = ['released', 'rejected', 'deleted', 'expired', 'superseded'] as const;
const EXPIRABLE = ['held', 'pending_approval'] as const;
const LIVE_RECIPIENT = ['pending', 'deferred', 'delivered'];

/** The subset of `AdvisoryLocks` the sweeper needs (GET_LOCK on a dedicated connection). */
export interface LeaderLock {
  ensure(name: string): Promise<boolean>;
  release(name: string): Promise<void>;
}

export interface QuarantineSweeperOptions {
  prisma: PrismaClient;
  locks: LeaderLock;
  objects: QuarantineObjects;
  store: Pick<QuarantineStoreWriter, 'casEntry' | 'cancelPendingRequests' | 'createEntries'>;
  settings: Pick<QuarantineSettingsRepository, 'resolve'>;
  disposal: Pick<DisposalFactsReader, 'read'>;
  digests: Pick<DigestScheduler, 'run'>;
  metrics: QuarantineMetrics;
  lifecycleMetrics: LifecycleMetrics;
  sink: QuarantineInconsistencySink;
  logger: Logger;
  /** QUARANTINE_SWEEP_INTERVAL_MS. */
  intervalMs: number;
  /** QUARANTINE_DB_TX_TIMEOUT_MS. */
  txTimeoutMs: number;
  /** QUARANTINE_SWEEP_BATCH_SIZE. */
  batchSize: number;
  /** QUARANTINE_ENTRY_RETENTION_DAYS. */
  retentionDays: number;
  bounds: QuarantinePlatformBounds;
  /** Lock name (default `eg:quarantine-sweeper`; integration tests use a per-run name). */
  lockName?: string;
  /** Restricts the sweep to these organizations (integration tests on the shared writer). */
  organizationIds?: readonly bigint[];
  now?: () => Date;
  sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
}

export type SweepStep =
  'expiry' | 'approvals' | 'purge' | 'adoption' | 'digests' | 'retention' | 'gauges';

export interface QuarantineSweepReport {
  outcome: 'not_leader' | 'database_error' | 'swept' | 'partial';
  expired: number;
  messagesExpired: number;
  approvalsExpired: number;
  purged: number;
  retained: number;
  purgeFailures: number;
  adopted: number;
  digests: number;
  alerts: number;
  entriesDeleted: number;
  failedSteps: SweepStep[];
}

interface LockedEntry {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  messageId: bigint;
  messageReceivedAt: Date;
  recipientId: bigint;
  kind: 'quarantine' | 'review';
  status: string;
  expiresAt: Date;
  approvalRequestId: bigint | null;
  rowVersion: number;
}

/**
 * The quarantine sweeper (step 5.3 Q19, Q8, Q17, Q20): while this process holds
 * `GET_LOCK('eg:quarantine-sweeper')` (a dedicated connection, like the 4.5 DLP evidence
 * sweeper), every QUARANTINE_SWEEP_INTERVAL_MS it runs, in bounded batches and one writer
 * transaction per message under the message lock:
 *
 * 1. **entry expiry** (`held`/`pending_approval`, `expires_at <= now`) → `expired` (pending
 *    requests `expired`), recipient `discarded`, E26 `quarantine_expired` when nothing remains
 *    held and no recipient is pending/deferred/delivered; the object is scheduled for purge or
 *    retained (Q17). **Never releases.**
 * 2. **approval-request expiry** (Q14): `release_*` → entry back to `held`; `policy_review` →
 *    entry expiry as step 1; the requesting user is notified (`approval_decided`, `expired`);
 * 3. **object purge** (Q17) of due `pending`/`retained`/`failed` rows, re-checked at purge time;
 * 4. **adoption** (Q8) of held messages without entries for their current round; a held message
 *    with no `pending`/`quarantined` recipient, no open entry and nothing live (a rescanned
 *    quarantine-expired message) ends `expired` again (E26) instead of being selected forever;
 * 5. **digests and admin alerts** (Q20);
 * 6. **entry row retention**: terminal entries older than QUARANTINE_ENTRY_RETENTION_DAYS with
 *    their actions, release logs, approval requests and grants, then the registry row of a
 *    message below `MIN(email_messages.id)` (D3.4); expired grants and old digest runs;
 *
 * and refreshes the `quarantine_entries{state}` and `quarantine_pending_approvals` gauges.
 * A failing step is logged and retried next pass; the other steps still run.
 */
export class QuarantineSweeper {
  readonly lockName: string;
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private readonly tx: PrismaClient;
  private abort = new AbortController();
  private loop: Promise<void> | undefined;
  private failures = 0;
  private leader = false;

  constructor(private readonly options: QuarantineSweeperOptions) {
    this.lockName = options.lockName ?? QUARANTINE_SWEEPER_LOCK;
    this.logger = options.logger.child({ component: 'quarantine-sweeper' });
    this.now = options.now ?? (() => new Date());
    this.sleepFn = options.sleep ?? defaultSleep;
    this.tx = withTransactionDefaults(options.prisma, { timeoutMs: options.txTimeoutMs });
  }

  get running(): boolean {
    return this.loop !== undefined;
  }

  /** Whether the last pass held the sweeper lock (readiness detail, not a readiness gate). */
  get isLeader(): boolean {
    return this.leader;
  }

  start(): void {
    if (this.loop) return;
    this.abort = new AbortController();
    this.loop = this.run(this.abort.signal);
    this.logger.info(
      { intervalMs: this.options.intervalMs, lock: this.lockName },
      'quarantine sweeper started',
    );
  }

  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop;
    this.loop = undefined;
    await this.options.locks.release(this.lockName).catch(() => undefined);
    this.options.metrics.sweeperLeader.set(0);
  }

  private get orgFilter() {
    const ids = this.options.organizationIds;
    return ids ? { organizationId: { in: [...ids] } } : {};
  }

  async sweepOnce(): Promise<QuarantineSweepReport> {
    const report: QuarantineSweepReport = {
      outcome: 'swept',
      expired: 0,
      messagesExpired: 0,
      approvalsExpired: 0,
      purged: 0,
      retained: 0,
      purgeFailures: 0,
      adopted: 0,
      digests: 0,
      alerts: 0,
      entriesDeleted: 0,
      failedSteps: [],
    };
    try {
      this.leader = await this.options.locks.ensure(this.lockName);
    } catch (err) {
      this.leader = false;
      this.options.metrics.sweeperLeader.set(0);
      this.logger.warn(
        { errName: (err as Error).name },
        'quarantine sweeper could not check its lock',
      );
      return { ...report, outcome: 'database_error' };
    }
    this.options.metrics.sweeperLeader.set(this.leader ? 1 : 0);
    if (!this.leader) return { ...report, outcome: 'not_leader' };
    const stop = this.options.metrics.sweepDuration.startTimer();
    const now = this.now();
    const steps: Array<[SweepStep, () => Promise<void>]> = [
      ['expiry', () => this.expiryStep(now, report)],
      ['approvals', () => this.approvalStep(now, report)],
      ['purge', () => this.purgeStep(now, report)],
      ['adoption', () => this.adoptionStep(now, report)],
      [
        'digests',
        async () => {
          const r = await this.options.digests.run(now);
          report.digests += r.digests;
          report.alerts += r.alerts;
          if (r.digests > 0)
            this.options.metrics.notifications.inc({ kind: 'user_digest' }, r.digests);
          if (r.alerts > 0)
            this.options.metrics.notifications.inc({ kind: 'admin_alert' }, r.alerts);
        },
      ],
      ['retention', () => this.retentionStep(now, report)],
      ['gauges', () => this.gauges()],
    ];
    for (const [name, step] of steps) {
      try {
        await step();
      } catch (err) {
        report.failedSteps.push(name);
        this.logger.warn(
          { step: name, errName: (err as Error).name, errCode: (err as { code?: string }).code },
          'quarantine sweeper step failed; retried next pass',
        );
      }
    }
    stop();
    if (report.failedSteps.length === 0) {
      this.options.metrics.sweepLastSuccess.set(Math.floor(this.now().getTime() / 1000));
    } else {
      report.outcome = 'partial';
    }
    if (
      report.expired + report.approvalsExpired + report.purged + report.adopted + report.digests >
      0
    ) {
      this.logger.info(
        {
          expired: report.expired,
          approvalsExpired: report.approvalsExpired,
          purged: report.purged,
          retained: report.retained,
          adopted: report.adopted,
          digests: report.digests,
          entriesDeleted: report.entriesDeleted,
        },
        'quarantine sweep',
      );
    }
    return report;
  }

  // ---------------------------------------------------------------------------------------------
  // Locks and shared writes
  // ---------------------------------------------------------------------------------------------

  /** Message lock, then every entry of the message (`FOR UPDATE`, echo-checked). */
  private async lockMessage(
    tx: Prisma.TransactionClient,
    key: MessageKey,
  ): Promise<{ snapshot: Awaited<ReturnType<typeof lockLifecycle>>; entries: LockedEntry[] }> {
    const snapshot = await lockLifecycle(tx, {
      id: key.messageId,
      receivedAt: key.receivedAt,
      organizationId: key.organizationId,
    });
    const locked = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM quarantine_messages
      WHERE message_id = ${key.messageId} AND message_received_at = ${key.receivedAt}
      ORDER BY id
      FOR UPDATE`;
    const entries =
      locked.length === 0
        ? []
        : await tx.quarantineMessage.findMany({
            where: { id: { in: locked.map((r) => BigInt(r.id)) } },
            select: {
              id: true,
              publicId: true,
              organizationId: true,
              messageId: true,
              messageReceivedAt: true,
              recipientId: true,
              kind: true,
              status: true,
              expiresAt: true,
              approvalRequestId: true,
              rowVersion: true,
            },
            orderBy: { id: 'asc' },
          });
    for (const e of entries) {
      if (
        e.organizationId !== key.organizationId ||
        e.messageId !== key.messageId ||
        e.messageReceivedAt.getTime() !== key.receivedAt.getTime()
      ) {
        quarantineWrongRead(this.options.sink, 'entries', 'sweeper entry echo');
      }
    }
    if (entries.length !== locked.length) {
      quarantineWrongRead(this.options.sink, 'entries', 'locked rows');
    }
    return { snapshot, entries };
  }

  /**
   * Expires `targets` (held / pending_approval): requests `expired`, entries `expired`,
   * recipients `discarded`, actions and events, E26 when nothing remains, the purge decision.
   */
  private async expireEntries(
    tx: Prisma.TransactionClient,
    key: MessageKey,
    locked: { snapshot: Awaited<ReturnType<typeof lockLifecycle>>; entries: LockedEntry[] },
    targets: LockedEntry[],
    now: Date,
  ): Promise<{ expired: number; messageExpired: boolean; requests: number }> {
    if (targets.length === 0) return { expired: 0, messageExpired: false, requests: 0 };
    const requests = await this.options.store.cancelPendingRequests(
      tx,
      key.organizationId,
      targets.map((e) => e.id),
      'expired',
      now,
    );
    for (const e of targets) {
      await this.options.store.casEntry(tx, e, {
        status: 'expired',
        stateChangedAt: now,
        terminalReason: 'expired',
        decidedAt: now,
        decidedByType: 'system',
      });
      e.status = 'expired';
    }
    await tx.emailRecipient.updateMany({
      where: {
        id: { in: targets.map((e) => e.recipientId) },
        messageId: key.messageId,
        receivedAt: key.receivedAt,
        organizationId: key.organizationId,
        status: 'quarantined',
      },
      data: { status: 'discarded' },
    });
    await tx.quarantineAction.createMany({
      data: targets.map((e) => ({
        organizationId: key.organizationId,
        quarantineMessageId: e.id,
        action: 'expire' as const,
        actorType: 'system' as const,
        result: 'expired',
        details: { kind: e.kind },
      })),
    });
    for (const kind of ['quarantine', 'review'] as const) {
      const n = targets.filter((e) => e.kind === kind).length;
      if (n === 0) continue;
      await writeMessageEvent(tx, {
        ...key,
        eventType: 'quarantine.expired',
        at: now,
        details: { entries: n, kind },
      });
      this.options.metrics.expired.inc({ kind }, n);
    }
    // E26 (`quarantine_expired`) when nothing is held any more and no recipient is live.
    let messageExpired = false;
    const snapshot = locked.snapshot;
    if (
      snapshot !== null &&
      (snapshot.state === 'quarantined' || snapshot.state === 'held_for_review') &&
      !locked.entries.some((e) => (NON_TERMINAL_STATES as readonly string[]).includes(e.status))
    ) {
      const live = await tx.emailRecipient.count({
        where: {
          messageId: key.messageId,
          receivedAt: key.receivedAt,
          organizationId: key.organizationId,
          status: { in: LIVE_RECIPIENT as Array<'pending' | 'deferred' | 'delivered'> },
        },
      });
      if (live === 0) {
        const outcome = await transitionMessage(
          tx,
          {
            message: {
              id: key.messageId,
              receivedAt: key.receivedAt,
              organizationId: key.organizationId,
            },
            to: 'expired',
            reason: 'quarantine_expired',
            actor: { role: 'quarantine', service: 'policy-engine', type: 'system' },
            transitionKey: `quarantine-expired:${key.messageId.toString()}:${String(snapshot.version)}`,
            expectedFrom: [snapshot.state],
            expectedRound: snapshot.round,
          },
          { metrics: this.options.lifecycleMetrics, logger: this.logger },
        );
        messageExpired = outcome.result === 'applied';
      }
    }
    await this.schedulePurge(tx, key, now);
    return { expired: targets.length, messageExpired, requests: requests.length };
  }

  /**
   * Q17 at expiry / re-evaluation: the message's `quarantine_object_purges` row — `pending`
   * (`purge_after = now`) when rules 1–4 allow the purge, else `retained` with the reason and
   * `purge_after` = the retention end (or one day later when unknown, re-evaluated then).
   */
  private async schedulePurge(
    tx: Prisma.TransactionClient,
    key: MessageKey,
    now: Date,
  ): Promise<ObjectDisposal> {
    const facts = await this.options.disposal.read(tx, key);
    const decision = decideObjectDisposal({
      ...facts,
      now,
      entries: facts.entries.map((e) => ({ state: e.state })),
    });
    const existing = await tx.quarantineObjectPurge.findFirst({
      where: { messageId: key.messageId, messageReceivedAt: key.receivedAt },
      select: { id: true, organizationId: true, status: true },
    });
    if (existing !== null && existing.organizationId !== key.organizationId) {
      quarantineWrongRead(this.options.sink, 'purges', 'purge echo');
    }
    if (existing?.status === 'purged') return decision;
    const data =
      decision.purge === 'now'
        ? { status: 'pending' as const, reason: null, purgeAfter: now }
        : {
            status: 'retained' as const,
            reason: decision.retainedReason,
            purgeAfter: decision.purgeAfter ?? new Date(now.getTime() + DAY_MS),
          };
    if (existing === null) {
      await tx.quarantineObjectPurge.create({
        data: {
          organizationId: key.organizationId,
          messageId: key.messageId,
          messageReceivedAt: key.receivedAt,
          ...data,
        },
        select: { id: true },
      });
    } else {
      await tx.quarantineObjectPurge.updateMany({
        where: { id: existing.id, status: { not: 'purged' } },
        data,
      });
    }
    if (decision.purge === 'retained' && existing?.status !== 'retained') {
      this.options.metrics.purges.inc({ result: 'retained' });
    }
    return decision;
  }

  // ---------------------------------------------------------------------------------------------
  // Step 1: entry expiry
  // ---------------------------------------------------------------------------------------------

  private async expiryStep(now: Date, report: QuarantineSweepReport): Promise<void> {
    for (let batch = 0; batch < MAX_BATCHES; batch += 1) {
      const due = await this.options.prisma.quarantineMessage.findMany({
        where: { ...this.orgFilter, status: { in: [...EXPIRABLE] }, expiresAt: { lte: now } },
        orderBy: { expiresAt: 'asc' },
        take: this.options.batchSize,
        select: {
          messageId: true,
          messageReceivedAt: true,
          organizationId: true,
          status: true,
          expiresAt: true,
        },
      });
      if (
        due.some(
          (e) =>
            !(EXPIRABLE as readonly string[]).includes(e.status) ||
            e.expiresAt.getTime() > now.getTime(),
        )
      ) {
        quarantineWrongRead(this.options.sink, 'entries', 'expiry candidates');
      }
      const messages = uniqueMessages(due);
      for (const key of messages) {
        const r = await this.tx.$transaction(async (tx) => {
          const locked = await this.lockMessage(tx, key);
          const targets = locked.entries.filter(
            (e) =>
              (EXPIRABLE as readonly string[]).includes(e.status) &&
              e.expiresAt.getTime() <= now.getTime(),
          );
          return this.expireEntries(tx, key, locked, targets, now);
        });
        report.expired += r.expired;
        if (r.messageExpired) report.messagesExpired += 1;
      }
      if (due.length < this.options.batchSize) break;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Step 2: approval-request expiry (Q14)
  // ---------------------------------------------------------------------------------------------

  private async approvalStep(now: Date, report: QuarantineSweepReport): Promise<void> {
    for (let batch = 0; batch < MAX_BATCHES; batch += 1) {
      const due = await this.options.prisma.quarantineApprovalRequest.findMany({
        where: { ...this.orgFilter, status: 'pending', expiresAt: { lte: now } },
        orderBy: { expiresAt: 'asc' },
        take: this.options.batchSize,
        select: { quarantineMessageId: true, status: true, expiresAt: true },
      });
      if (due.some((r) => r.status !== 'pending' || r.expiresAt.getTime() > now.getTime())) {
        quarantineWrongRead(this.options.sink, 'approval_requests', 'expiry candidates');
      }
      const entries = await this.options.prisma.quarantineMessage.findMany({
        where: { id: { in: [...new Set(due.map((r) => r.quarantineMessageId))] } },
        select: { messageId: true, messageReceivedAt: true, organizationId: true },
      });
      for (const key of uniqueMessages(entries)) {
        report.approvalsExpired += await this.tx.$transaction((tx) =>
          this.expireRequests(tx, key, now, report),
        );
      }
      if (due.length < this.options.batchSize) break;
    }
  }

  private async expireRequests(
    tx: Prisma.TransactionClient,
    key: MessageKey,
    now: Date,
    report: QuarantineSweepReport,
  ): Promise<number> {
    const locked = await this.lockMessage(tx, key);
    const ids = locked.entries.map((e) => e.id);
    if (ids.length === 0) return 0;
    const requests = await tx.quarantineApprovalRequest.findMany({
      where: { quarantineMessageId: { in: ids }, status: 'pending', expiresAt: { lte: now } },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        quarantineMessageId: true,
        kind: true,
        status: true,
        requestedByType: true,
        requestedByUserId: true,
        rowVersion: true,
      },
    });
    let expired = 0;
    const reviewEntries: LockedEntry[] = [];
    for (const r of requests) {
      if (r.organizationId !== key.organizationId || r.status !== 'pending') {
        quarantineWrongRead(this.options.sink, 'approval_requests', 'request echo');
      }
      const entry = locked.entries.find((e) => e.id === r.quarantineMessageId)!;
      if (r.kind === 'policy_review') {
        if (EXPIRABLE.includes(entry.status as (typeof EXPIRABLE)[number]))
          reviewEntries.push(entry);
        continue;
      }
      const updated = await tx.quarantineApprovalRequest.updateMany({
        where: { id: r.id, rowVersion: r.rowVersion, status: 'pending' },
        data: { status: 'expired', decidedAt: now, rowVersion: { increment: 1 } },
      });
      if (updated.count !== 1) {
        quarantineWrongRead(this.options.sink, 'approval_requests', 'request CAS');
      }
      expired += 1;
      if (entry.status === 'pending_approval' && entry.approvalRequestId === r.id) {
        await this.options.store.casEntry(tx, entry, { status: 'held', stateChangedAt: now });
        entry.status = 'held';
      }
      await tx.quarantineAction.create({
        data: {
          organizationId: key.organizationId,
          quarantineMessageId: entry.id,
          action: 'approval_expired',
          actorType: 'system',
          result: 'expired',
          approvalRequestId: r.id,
          details: { kind: r.kind },
        },
        select: { id: true },
      });
      if (r.requestedByType === 'user' && r.requestedByUserId !== null) {
        await writeQuarantineNotification(tx, {
          organizationId: key.organizationId,
          correlationId: `quarantine-approval:${r.publicId}`,
          at: now,
          payload: {
            kind: 'approval_decided',
            refs: { approvalRequestIds: [r.publicId], entryId: entry.publicId },
            decision: 'expired',
            requestedAt: now.toISOString(),
          },
        });
        this.options.metrics.notifications.inc({ kind: 'approval_decided' });
      }
    }
    if (reviewEntries.length > 0) {
      const r = await this.expireEntries(tx, key, locked, reviewEntries, now);
      expired += r.requests;
      report.expired += r.expired;
      if (r.messageExpired) report.messagesExpired += 1;
    }
    if (expired > 0) this.options.metrics.approvalsExpired.inc(expired);
    return expired;
  }

  // ---------------------------------------------------------------------------------------------
  // Step 3: object purge (Q17)
  // ---------------------------------------------------------------------------------------------

  private async purgeStep(now: Date, report: QuarantineSweepReport): Promise<void> {
    const rows = await this.options.prisma.quarantineObjectPurge.findMany({
      where: {
        ...this.orgFilter,
        status: { in: ['pending', 'retained', 'failed'] },
        purgeAfter: { lte: now },
      },
      orderBy: { purgeAfter: 'asc' },
      take: this.options.batchSize,
      select: {
        id: true,
        organizationId: true,
        messageId: true,
        messageReceivedAt: true,
        status: true,
        attempts: true,
        purgeAfter: true,
      },
    });
    for (const row of rows) {
      if (row.status === 'purged' || row.purgeAfter.getTime() > now.getTime()) {
        quarantineWrongRead(this.options.sink, 'purges', 'purge candidates');
      }
      const key: MessageKey = {
        messageId: row.messageId,
        receivedAt: row.messageReceivedAt,
        organizationId: row.organizationId,
      };
      try {
        const result = await this.tx.$transaction((tx) => this.purgeOne(tx, key, row.id, now));
        if (result === 'purged') report.purged += 1;
        else report.retained += 1;
      } catch (err) {
        const code =
          err instanceof PurgeKeyError ? err.code : ((err as { name?: string }).name ?? 'error');
        report.purgeFailures += 1;
        this.options.metrics.purges.inc({ result: 'failed' });
        this.logger.warn(
          { messageId: row.messageId.toString(), errCode: code },
          'quarantine object purge failed; retried later',
        );
        const attempts = Math.min(row.attempts + 1, 65_535);
        await this.options.prisma.quarantineObjectPurge.updateMany({
          where: { id: row.id, status: { not: 'purged' } },
          data: {
            status: 'failed',
            attempts,
            lastErrorCode: code.slice(0, 64),
            purgeAfter: new Date(
              now.getTime() + backoffDelay(attempts, { baseMs: 60_000, maxMs: 6 * HOUR_MS }),
            ),
          },
        });
      }
    }
  }

  private async purgeOne(
    tx: Prisma.TransactionClient,
    key: MessageKey,
    purgeId: bigint,
    now: Date,
  ): Promise<'purged' | 'retained'> {
    // The message lock serializes the purge with releases, rescans and manual quarantine.
    await this.lockMessage(tx, key);
    const decision = await this.schedulePurge(tx, key, now);
    if (decision.purge !== 'now') return 'retained';
    const message = await tx.emailMessage.findFirst({
      where: { id: key.messageId, receivedAt: key.receivedAt, organizationId: key.organizationId },
      select: { id: true, organizationId: true, emlObjectKey: true },
    });
    if (message !== null && message.organizationId !== key.organizationId) {
      quarantineWrongRead(this.options.sink, 'message', 'purge message echo');
    }
    const entries = await tx.quarantineMessage.findMany({
      where: { messageId: key.messageId, messageReceivedAt: key.receivedAt },
      select: { id: true, organizationId: true, emlObjectKey: true },
    });
    if (entries.some((e) => e.organizationId !== key.organizationId)) {
      quarantineWrongRead(this.options.sink, 'entries', 'purge entry echo');
    }
    const emlKeys = [
      ...new Set([
        ...entries.map((e) => e.emlObjectKey),
        ...(message === null ? [] : [message.emlObjectKey]),
      ]),
    ];
    for (const k of emlKeys) {
      if (!isOrganizationKey(k, key.organizationId)) throw new PurgeKeyError('key_prefix');
    }
    let versions = 0;
    for (const k of emlKeys) versions += await this.options.objects.purgeKey(k);
    for (const prefix of messageObjectPrefixes(key)) {
      versions += await this.options.objects.purgePrefix(prefix);
    }
    const updated = await tx.quarantineObjectPurge.updateMany({
      where: { id: purgeId, organizationId: key.organizationId, status: { not: 'purged' } },
      data: { status: 'purged', purgedAt: now, reason: null, lastErrorCode: null },
    });
    if (updated.count !== 1) quarantineWrongRead(this.options.sink, 'purges', 'purge CAS');
    await tx.quarantineMessage.updateMany({
      where: { messageId: key.messageId, messageReceivedAt: key.receivedAt, objectPurgedAt: null },
      data: { objectPurgedAt: now },
    });
    if (entries.length > 0) {
      await tx.quarantineAction.createMany({
        data: entries.map((e) => ({
          organizationId: key.organizationId,
          quarantineMessageId: e.id,
          action: 'object_purged' as const,
          actorType: 'system' as const,
          result: 'purged',
          details: { versions },
        })),
      });
    }
    await writeMessageEvent(tx, {
      ...key,
      eventType: 'quarantine.object_purged',
      at: now,
      details: { versions, entries: entries.length },
    });
    this.options.metrics.purges.inc({ result: 'purged' });
    return 'purged';
  }

  // ---------------------------------------------------------------------------------------------
  // Step 4: adoption (Q8)
  // ---------------------------------------------------------------------------------------------

  private async adoptionStep(now: Date, report: QuarantineSweepReport): Promise<void> {
    const ids = this.options.organizationIds;
    const orgClause =
      ids === undefined || ids.length === 0
        ? Prisma.empty
        : Prisma.sql`AND m.organization_id IN (${Prisma.join([...ids])})`;
    const candidates = await this.options.prisma.$queryRaw<
      Array<{ id: bigint; received_at: Date; organization_id: bigint }>
    >`
      SELECT m.id, m.received_at, m.organization_id FROM email_messages m
      WHERE m.status IN ('quarantined', 'held_for_review') ${orgClause}
        AND NOT EXISTS (
          SELECT 1 FROM quarantine_messages q
          WHERE q.message_id = m.id AND q.message_received_at = m.received_at
            AND q.lifecycle_round = m.lifecycle_round)
        AND (
          EXISTS (
            SELECT 1 FROM email_recipients r
            WHERE r.message_id = m.id AND r.received_at = m.received_at
              AND r.organization_id = m.organization_id
              AND r.status IN ('pending', 'quarantined'))
          OR (
            NOT EXISTS (
              SELECT 1 FROM email_recipients r
              WHERE r.message_id = m.id AND r.received_at = m.received_at
                AND r.organization_id = m.organization_id
                AND r.status IN ('pending', 'deferred', 'delivered'))
            AND NOT EXISTS (
              SELECT 1 FROM quarantine_messages q
              WHERE q.message_id = m.id AND q.message_received_at = m.received_at
                AND q.status IN (${Prisma.join([...NON_TERMINAL_STATES])}))))
      ORDER BY m.status_changed_at
      LIMIT ${this.options.batchSize}`;
    for (const c of candidates) {
      const key: MessageKey = {
        messageId: BigInt(c.id),
        receivedAt: new Date(c.received_at),
        organizationId: BigInt(c.organization_id),
      };
      if (ids !== undefined && !ids.includes(key.organizationId)) {
        quarantineWrongRead(this.options.sink, 'message', 'adoption organization');
      }
      const adopted = await this.tx.$transaction((tx) => this.adopt(tx, key, now));
      if (adopted === 'closed') {
        report.messagesExpired += 1;
      } else if (adopted > 0) {
        report.adopted += 1;
        this.options.metrics.adopted.inc();
      }
    }
  }

  /**
   * Q8 adoption of one held message: entries for its `pending`/`quarantined` recipients. A held
   * message with no such recipient and nothing live (for example a quarantine-expired message
   * rescanned by an operator: E19 from `expired` re-decides only `pending` recipients, and every
   * recipient is `discarded`) has nothing an operator can act on: it ends `expired` again (E26
   * `quarantine_expired`), so it never blocks the adoption batch. Returns the entries created,
   * or `closed`.
   */
  private async adopt(
    tx: Prisma.TransactionClient,
    key: MessageKey,
    now: Date,
  ): Promise<number | 'closed'> {
    const { snapshot, entries } = await this.lockMessage(tx, key);
    if (snapshot === null) return 0;
    if (snapshot.state !== 'quarantined' && snapshot.state !== 'held_for_review') return 0;
    const existing = await tx.quarantineMessage.count({
      where: {
        messageId: key.messageId,
        messageReceivedAt: key.receivedAt,
        lifecycleRound: snapshot.round,
      },
    });
    if (existing > 0) return 0;
    const message = await tx.emailMessage.findFirst({
      where: { id: key.messageId, receivedAt: key.receivedAt, organizationId: key.organizationId },
      select: {
        id: true,
        organizationId: true,
        receivedAt: true,
        direction: true,
        envelopeFrom: true,
        headerFrom: true,
        sizeBytes: true,
        attachmentCount: true,
        emlObjectKey: true,
      },
    });
    if (message === null || message.organizationId !== key.organizationId) {
      return quarantineWrongRead(this.options.sink, 'message', 'adoption message echo');
    }
    const recipients = await tx.emailRecipient.findMany({
      where: {
        messageId: key.messageId,
        receivedAt: key.receivedAt,
        organizationId: key.organizationId,
        status: { in: ['pending', 'quarantined'] },
      },
      select: { id: true, rcptSeq: true, address: true, organizationId: true, messageId: true },
      orderBy: { rcptSeq: 'asc' },
    });
    if (
      recipients.some(
        (r) => r.organizationId !== key.organizationId || r.messageId !== key.messageId,
      )
    ) {
      quarantineWrongRead(this.options.sink, 'recipients', 'adoption recipient echo');
    }
    if (recipients.length === 0) return this.closeEmpty(tx, key, snapshot, entries, now);
    const row = await tx.policyExecutionLog.findFirst({
      where: {
        messageId: key.messageId,
        receivedAt: key.receivedAt,
        organizationId: key.organizationId,
        evaluationSeq: snapshot.round,
      },
    });
    let view = null;
    if (row !== null) {
      if (row.organizationId !== key.organizationId || row.messageId !== key.messageId) {
        quarantineWrongRead(this.options.sink, 'evaluation', 'adoption evaluation echo');
      }
      try {
        view = rowToEvaluationView(row);
      } catch {
        view = null;
      }
    }
    const scan = await tx.emailScan.findFirst({
      where: {
        messageId: key.messageId,
        receivedAt: key.receivedAt,
        organizationId: key.organizationId,
        lifecycleRound: snapshot.round,
      },
      select: { id: true, organizationId: true },
    });
    const kind =
      snapshot.state === 'held_for_review' ? ('review' as const) : ('quarantine' as const);
    const facts = entryFactsFromView(view, kind);
    const settings = await this.options.settings.resolve(tx, key.organizationId);
    const candidates: EntryCandidate[] = recipients.map((r) => ({
      recipientId: r.id,
      rcptSeq: r.rcptSeq,
      address: r.address,
      kind,
      facts,
    }));
    for (const part of chunks(recipients, 1000)) {
      await tx.emailRecipient.updateMany({
        where: {
          id: { in: part.map((r) => r.id) },
          messageId: key.messageId,
          receivedAt: key.receivedAt,
          organizationId: key.organizationId,
          status: { in: ['pending', 'quarantined'] },
        },
        data: {
          status: 'quarantined',
          finalAction: kind === 'review' ? 'require_approval' : 'quarantine',
        },
      });
    }
    const created = await this.options.store.createEntries(tx, {
      message: {
        ...key,
        round: snapshot.round,
        scanId: scan?.organizationId === key.organizationId ? scan.id : null,
        direction: message.direction,
        envelopeFrom: message.envelopeFrom,
        headerFrom: message.headerFrom,
        sizeBytes: message.sizeBytes,
        attachmentCount: message.attachmentCount,
        emlObjectKey: message.emlObjectKey,
      },
      origin: 'adopted',
      candidates,
      settings,
      bounds: this.options.bounds,
      now,
      expiryFrom: message.receivedAt,
      correlationId: `quarantine-adopt:${key.messageId.toString()}`,
      actionDetails: { state: snapshot.state, evaluation: row !== null },
    });
    for (const e of created.created) {
      this.options.metrics.entriesCreated.inc({
        origin: 'adopted',
        kind: e.kind,
        reason: e.reason,
        direction: e.direction,
      });
    }
    if (created.notifications > 0) {
      this.options.metrics.notifications.inc({ kind: 'approval_requested' }, created.notifications);
    }
    return created.created.length;
  }

  /**
   * A held message without an adoptable recipient: E26 `quarantine_expired` when no entry of the
   * message is open and no recipient is pending/deferred/delivered (as entry expiry, step 1);
   * the object disposal is decided again. Otherwise nothing (0).
   */
  private async closeEmpty(
    tx: Prisma.TransactionClient,
    key: MessageKey,
    snapshot: NonNullable<Awaited<ReturnType<typeof lockLifecycle>>>,
    entries: readonly LockedEntry[],
    now: Date,
  ): Promise<number | 'closed'> {
    if (entries.some((e) => (NON_TERMINAL_STATES as readonly string[]).includes(e.status))) {
      return 0;
    }
    const live = await tx.emailRecipient.count({
      where: {
        messageId: key.messageId,
        receivedAt: key.receivedAt,
        organizationId: key.organizationId,
        status: { in: LIVE_RECIPIENT as Array<'pending' | 'deferred' | 'delivered'> },
      },
    });
    if (live > 0) return 0;
    const outcome = await transitionMessage(
      tx,
      {
        message: {
          id: key.messageId,
          receivedAt: key.receivedAt,
          organizationId: key.organizationId,
        },
        to: 'expired',
        reason: 'quarantine_expired',
        actor: { role: 'quarantine', service: 'policy-engine', type: 'system' },
        transitionKey: `quarantine-expired:${key.messageId.toString()}:${String(snapshot.version)}`,
        expectedFrom: [snapshot.state],
        expectedRound: snapshot.round,
      },
      { metrics: this.options.lifecycleMetrics, logger: this.logger },
    );
    if (outcome.result !== 'applied') return 0;
    await writeMessageEvent(tx, {
      ...key,
      eventType: 'quarantine.expired',
      at: now,
      details: { entries: 0, kind: snapshot.state === 'held_for_review' ? 'review' : 'quarantine' },
    });
    await this.schedulePurge(tx, key, now);
    this.logger.info(
      { messageId: key.messageId.toString(), round: snapshot.round },
      'held message without an adoptable recipient ended expired',
    );
    return 'closed';
  }

  // ---------------------------------------------------------------------------------------------
  // Step 6: retention
  // ---------------------------------------------------------------------------------------------

  private async retentionStep(now: Date, report: QuarantineSweepReport): Promise<void> {
    const cut = new Date(now.getTime() - this.options.retentionDays * DAY_MS);
    for (let batch = 0; batch < MAX_BATCHES; batch += 1) {
      const rows = await this.options.prisma.quarantineMessage.findMany({
        where: {
          ...this.orgFilter,
          status: { in: [...TERMINAL_STATES] },
          stateChangedAt: { lt: cut },
        },
        orderBy: { stateChangedAt: 'asc' },
        take: this.options.batchSize,
        select: { messageId: true, messageReceivedAt: true, organizationId: true, status: true },
      });
      if (rows.some((r) => !(TERMINAL_STATES as readonly string[]).includes(r.status))) {
        quarantineWrongRead(this.options.sink, 'entries', 'retention candidates');
      }
      for (const key of uniqueMessages(rows)) {
        const deleted = await this.tx.$transaction((tx) => this.deleteOldEntries(tx, key, cut));
        report.entriesDeleted += deleted;
        if (deleted > 0) this.options.metrics.entriesDeleted.inc(deleted);
      }
      if (rows.length < this.options.batchSize) break;
    }
    await this.options.prisma.quarantineDownloadGrant.deleteMany({
      where: { ...this.orgFilter, expiresAt: { lt: new Date(now.getTime() - GRANT_RETENTION_MS) } },
    });
    await this.options.prisma.quarantineDigestRun.deleteMany({
      where: {
        ...this.orgFilter,
        createdAt: { lt: new Date(now.getTime() - DIGEST_RETENTION_MS) },
      },
    });
  }

  private async deleteOldEntries(
    tx: Prisma.TransactionClient,
    key: MessageKey,
    cut: Date,
  ): Promise<number> {
    const { entries } = await this.lockMessage(tx, key);
    const old = await tx.quarantineMessage.findMany({
      where: {
        id: { in: entries.map((e) => e.id) },
        status: { in: [...TERMINAL_STATES] },
        stateChangedAt: { lt: cut },
      },
      select: { id: true },
    });
    const ids = old.map((e) => e.id);
    if (ids.length === 0) return 0;
    await tx.quarantineReleaseLog.deleteMany({ where: { quarantineMessageId: { in: ids } } });
    await tx.quarantineAction.deleteMany({ where: { quarantineMessageId: { in: ids } } });
    await tx.quarantineApprovalRequest.deleteMany({ where: { quarantineMessageId: { in: ids } } });
    await tx.quarantineDownloadGrant.deleteMany({ where: { quarantineMessageId: { in: ids } } });
    const deleted = await tx.quarantineMessage.deleteMany({
      where: { id: { in: ids }, status: { in: [...TERMINAL_STATES] }, stateChangedAt: { lt: cut } },
    });
    if (deleted.count !== ids.length) {
      quarantineWrongRead(this.options.sink, 'entry_update', 'retention delete');
    }
    if (entries.length === ids.length) {
      // The message's last quarantine reference is gone (D3.4 registry contract).
      await tx.quarantineObjectPurge.deleteMany({
        where: { messageId: key.messageId, messageReceivedAt: key.receivedAt, status: 'purged' },
      });
      const [min] = await tx.$queryRaw<Array<{ min: bigint | null }>>`
        SELECT MIN(id) AS min FROM email_messages`;
      const below = min?.min !== null && min?.min !== undefined && key.messageId < BigInt(min.min);
      if (below) {
        const archives = await tx.emailArchive.count({
          where: { messageId: key.messageId, deletedAt: null },
        });
        if (archives === 0) {
          await tx.messageIdentity.deleteMany({
            where: { id: key.messageId, organizationId: key.organizationId },
          });
        }
      }
    }
    return deleted.count;
  }

  // ---------------------------------------------------------------------------------------------
  // Gauges
  // ---------------------------------------------------------------------------------------------

  private async gauges(): Promise<void> {
    const groups = await this.options.prisma.quarantineMessage.groupBy({
      by: ['status'],
      where: { ...this.orgFilter, status: { in: [...NON_TERMINAL_STATES] } },
      _count: { _all: true },
    });
    for (const state of NON_TERMINAL_STATES) {
      const found = groups.find((g) => g.status === state);
      this.options.metrics.entries.set({ state }, found?._count._all ?? 0);
    }
    const pending = await this.options.prisma.quarantineApprovalRequest.count({
      where: { ...this.orgFilter, status: 'pending' },
    });
    this.options.metrics.pendingApprovals.set(pending);
  }

  private async run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      const report = await this.sweepOnce();
      let delay = this.options.intervalMs;
      if (report.outcome === 'database_error' || report.outcome === 'partial') {
        this.failures += 1;
        delay = Math.max(delay, backoffDelay(this.failures, { baseMs: 1_000, maxMs: 60_000 }));
      } else {
        this.failures = 0;
      }
      if (!(await this.sleepFn(delay, signal))) break;
    }
  }
}

/** A purge refused before any deletion (an object key outside the organization prefix). */
export class PurgeKeyError extends Error {
  override readonly name = 'PurgeKeyError';
  constructor(readonly code: string) {
    super(`quarantine purge refused: ${code}`);
  }
}

function uniqueMessages(
  rows: ReadonlyArray<{ messageId: bigint; messageReceivedAt: Date; organizationId: bigint }>,
): MessageKey[] {
  const seen = new Map<string, MessageKey>();
  for (const r of rows) {
    const k = `${r.messageId.toString()}|${r.messageReceivedAt.getTime()}`;
    if (!seen.has(k)) {
      seen.set(k, {
        messageId: r.messageId,
        receivedAt: r.messageReceivedAt,
        organizationId: r.organizationId,
      });
    }
  }
  return [...seen.values()];
}
