import {
  archivePartiesSchema,
  type ArchiveRecordObjects,
  archiveRecordObjectsSchema,
  type ArchiveScanRounds,
  archiveScanRoundsSchema,
  CAPTURE_WAIT_STEPS_MINUTES,
  categoryOf,
  decideCapture,
  isFinalMessageStatus,
  nextOutcomeCheckAt,
  QUARANTINE_WAIT_MAX_DAYS,
  unwrapRecordKey,
} from '@email-gateway/archive';
import { backoffDelay, uuidv7 } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { TenantKeyService } from '../keys/tenant-keys';
import type { ArchiveMetrics } from '../metrics/archive-metrics';
import { big, orgFilter } from '../shared/db';
import {
  DeterministicCaptureError,
  errorCode,
  errorFields,
  LeaseLostError,
  OriginalMissingError,
} from '../shared/errors';
import { mapLimit } from '../shared/loops';
import {
  type ArchiveStorage,
  LOCK_FLOOR_MS,
  type ObjectLockSpec,
} from '../storage/archive-storage';
import { refreshMergedParties } from './dedupe';
import { type CaptureExecutor, type ClaimedIntent, writeScanSnapshot } from './executor';
import { FactsReader, isMalicious, type MessageFacts, partiesOf, sameParties } from './facts';
import type { OrgContextCache } from './org-context';

const MINUTE_MS = 60_000;
const DAY_MS = 86_400_000;
const PENDING_CAP = 1_000_000;
/** Linked rounds/revisions per record (A7). */
export const MAX_SCAN_LINKS = 16;

/** How late a due intent may be before it counts as a capture backlog (scheduler lag). */
export const BACKLOG_GRACE_MS = 10 * MINUTE_MS;

/** How many waits an intent of this age has had (the 1, 2, 5, 15, 30 min, hourly schedule). */
export function waitsFromElapsed(elapsedMs: number): number {
  let cumulative = 0;
  let waits = 0;
  for (const minutes of CAPTURE_WAIT_STEPS_MINUTES) {
    cumulative += minutes * MINUTE_MS;
    if (elapsedMs < cumulative) return waits;
    waits += 1;
  }
  return waits + Math.floor((elapsedMs - cumulative) / (60 * MINUTE_MS));
}

interface IntentRow extends ClaimedIntent {
  status: 'pending' | 'captured_open';
  /** A pending intent waiting in quarantine carries `quarantined` (the wait marker), else null. */
  category: string | null;
  attempts: number;
  createdAt: Date;
  capturedAt: Date | null;
  archiveId: bigint | null;
  /** Step 8.6: the record's `received_at` of a merged intent (NULL = the intent's own). */
  archiveReceivedAt: Date | null;
  /** Step 8.6: the intent's message was merged into another message's record. */
  merged: boolean;
}

export type IntentOutcome =
  | 'captured'
  | 'waiting'
  | 'skipped'
  | 'lost'
  | 'failed'
  | 'retry'
  | 'lost_race'
  | 'lease_lost'
  | 'refreshed'
  | 'closed';

const sourceLabel = (s: { journal: boolean; policy: boolean }): string =>
  s.journal && s.policy ? 'both' : s.journal ? 'journal' : s.policy ? 'policy' : 'none';

/**
 * The capture scheduler (A2, A3, A6, A7): claims due intents (`status IN ('pending',
 * 'captured_open') AND next_check_at <= now`, `FOR UPDATE SKIP LOCKED`, lease
 * `ARCHIVE_CAPTURE_LEASE_SECONDS` written into `lease_until` and `next_check_at`, so a crashed
 * replica's claim becomes due again when the lease ends), decides on fresh writer facts and
 * executes with `ARCHIVE_CAPTURE_CONCURRENCY` in parallel. Every write after the claim is a CAS on
 * the claimed lease. `captured_open` intents get the outcome refresh (A7) and close after the
 * final +24 h check or the outcome window.
 */
export class CaptureScheduler {
  private readonly reader = new FactsReader();
  private readonly now: () => Date;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      orgs: OrgContextCache;
      executor: CaptureExecutor;
      storage: ArchiveStorage;
      keys: TenantKeyService;
      metrics: ArchiveMetrics;
      logger: Logger;
      concurrency: number;
      leaseSeconds: number;
      retryBaseMs: number;
      retryMaxMs: number;
      maxAgeDays: number;
      outcomeWindowDays: number;
      chunkBytes: number;
      organizationIds?: readonly bigint[];
      random?: () => number;
      now?: () => Date;
    },
  ) {
    this.now = options.now ?? (() => new Date());
  }

  /** One pass: claim, process. True when the claim was full (run again at once). */
  async runOnce(): Promise<boolean> {
    const limit = this.options.concurrency * 2;
    const claimed = await this.claim(limit);
    if (claimed.length === 0) return false;
    await mapLimit(claimed, this.options.concurrency, (intent) => this.process(intent));
    return claimed.length === limit;
  }

  async claim(limit: number): Promise<IntentRow[]> {
    const now = this.now();
    const lease = new Date(now.getTime() + this.options.leaseSeconds * 1000);
    return this.prisma.$transaction(async (tx) => {
      const due = await tx.$queryRaw<Array<{ id: bigint | number; received_at: Date }>>`
        SELECT id, received_at FROM archive_capture_intents
        WHERE status IN ('pending', 'captured_open') AND next_check_at <= ${now}
          ${orgFilter('organization_id', this.options.organizationIds)}
        ORDER BY next_check_at LIMIT ${limit}
        FOR UPDATE SKIP LOCKED`;
      if (due.length === 0) return [];
      // AUTO_INCREMENT ids are unique across partitions; the received_at range prunes them.
      // (Row-value IN lists with DATETIME parameters are mis-bound by the Prisma driver.)
      const times = due.map((d) => d.received_at.getTime());
      const keys = Prisma.sql`id IN (${Prisma.join(due.map((d) => big(d.id)))})
        AND received_at BETWEEN ${new Date(Math.min(...times))} AND ${new Date(Math.max(...times))}`;
      await tx.$executeRaw`
        UPDATE archive_capture_intents SET lease_until = ${lease}, next_check_at = ${lease},
          updated_at = NOW(3)
        WHERE ${keys}`;
      const rows = await tx.$queryRaw<
        Array<{
          id: bigint | number;
          received_at: Date;
          organization_id: bigint | number;
          message_id: bigint | number;
          status: 'pending' | 'captured_open';
          source_journal: number | boolean;
          source_policy: number | boolean;
          policy_rule_ref: string | null;
          category: string | null;
          attempts: number | bigint;
          created_at: Date;
          captured_at: Date | null;
          archive_id: bigint | number | null;
          archive_received_at: Date | null;
          merged: number | boolean;
        }>
      >`
        SELECT id, received_at, organization_id, message_id, status, source_journal,
          source_policy, policy_rule_ref, category, attempts, created_at, captured_at, archive_id,
          archive_received_at, merged
        FROM archive_capture_intents WHERE ${keys}`;
      return rows.map((r) => ({
        id: big(r.id),
        receivedAt: r.received_at,
        organizationId: big(r.organization_id),
        messageId: big(r.message_id),
        leaseUntil: lease,
        status: r.status,
        sourceJournal: Boolean(Number(r.source_journal)),
        sourcePolicy: Boolean(Number(r.source_policy)),
        policyRuleRef: r.policy_rule_ref,
        category: r.category,
        attempts: Number(r.attempts),
        createdAt: r.created_at,
        capturedAt: r.captured_at,
        archiveId: r.archive_id === null ? null : big(r.archive_id),
        archiveReceivedAt: r.archive_received_at,
        merged: Boolean(Number(r.merged)),
      }));
    });
  }

  async process(intent: IntentRow): Promise<IntentOutcome> {
    try {
      return intent.status === 'captured_open'
        ? await this.refresh(intent)
        : await this.decide(intent);
    } catch (error) {
      if (error instanceof LeaseLostError) return 'lease_lost';
      this.options.logger.warn(
        { intentId: intent.id.toString(), ...errorFields(error) },
        'capture intent not processed; retried',
      );
      return this.retry(intent, errorCode(error, 'capture_error'));
    }
  }

  private async decide(intent: IntentRow): Promise<IntentOutcome> {
    const now = this.now();
    const started = process.hrtime.bigint();
    const sources = { journal: intent.sourceJournal, policy: intent.sourcePolicy };
    const facts = await this.reader.message(this.prisma, intent);
    const ctx = await this.options.orgs.get(intent.organizationId);
    const decision = decideCapture({
      now,
      entitled: ctx.entitled,
      enabled: ctx.enabled,
      settings: ctx.settings,
      sources,
      message:
        facts === null
          ? null
          : {
              status: facts.message.status,
              statusReason: facts.message.statusReason,
              statusChangedAt: facts.message.statusChangedAt,
              direction: facts.message.direction,
              recipients: facts.recipients,
              ingestSource: facts.message.ingestSource,
            },
      intentCreatedAt: intent.createdAt,
      waitsSoFar: waitsFromElapsed(now.getTime() - intent.createdAt.getTime()),
      maxAgeDays: this.options.maxAgeDays,
      outcomeWindowDays: this.options.outcomeWindowDays,
    });
    const label = sourceLabel(sources);
    switch (decision.action) {
      case 'wait':
        // A wait in quarantine is marked (`category = 'quarantined'`): it is bounded by
        // QUARANTINE_WAIT_MAX_DAYS, not the intent max age, and is neither a capture backlog nor
        // a capture issue. A wait is no error: the last error code is cleared.
        await this.update(
          intent,
          Prisma.sql`next_check_at = ${decision.recheckAt},
            category = ${decision.reason === 'quarantine_excluded' ? 'quarantined' : null},
            last_error_code = NULL`,
        );
        return 'waiting';
      case 'skip':
        await this.update(
          intent,
          Prisma.sql`status = 'skipped', skip_reason = ${decision.reason}, closed_at = ${now},
            next_check_at = ${now}`,
        );
        this.options.metrics.captures.inc({ result: 'skipped', source: label, category: 'none' });
        this.options.metrics.captureSkips.inc({ reason: decision.reason });
        if (decision.reason === 'max_age') {
          this.options.logger.warn(
            { intentId: intent.id.toString(), organizationId: intent.organizationId.toString() },
            'capture intent aged out: the message was never archived',
          );
        }
        return 'skipped';
      case 'lost':
        await this.markLost(intent, decision.reason);
        this.options.metrics.captures.inc({ result: 'lost', source: label, category: 'none' });
        return 'lost';
      case 'capture':
        break;
    }
    try {
      const result = await this.options.executor.capture({
        intent,
        facts: facts!,
        ctx,
        category: decision.category,
        sources: decision.sources,
        recheckAt: decision.recheckAt,
      });
      const seconds = Number(process.hrtime.bigint() - started) / 1e9;
      if (result.status === 'lost_race') {
        // A record of this message already exists (another claim after a lease expiry, or an
        // intent re-created after its partition was dropped), or the message was already merged
        // into another record (step 8.6): link it and refresh from there.
        const existing = await this.prisma.emailArchive.findUnique({
          where: {
            messageId_receivedAt: { messageId: intent.messageId, receivedAt: intent.receivedAt },
          },
          select: { id: true, organizationId: true, archivedAt: true },
        });
        const mergedInto =
          existing === null
            ? await this.prisma.archiveRecordSource.findFirst({
                where: {
                  messageId: intent.messageId,
                  messageReceivedAt: intent.receivedAt,
                  organizationId: intent.organizationId,
                },
                select: {
                  organizationId: true,
                  archiveId: true,
                  archiveReceivedAt: true,
                  mergedAt: true,
                },
              })
            : null;
        if (existing !== null && existing.organizationId === intent.organizationId) {
          await this.update(
            intent,
            Prisma.sql`status = 'captured_open', archive_id = ${existing.id},
              captured_at = ${existing.archivedAt}, category = ${decision.category},
              next_check_at = ${now}`,
          );
        } else if (mergedInto !== null && mergedInto.organizationId === intent.organizationId) {
          await this.update(
            intent,
            Prisma.sql`status = 'captured_open', archive_id = ${mergedInto.archiveId},
              archive_received_at = ${mergedInto.archiveReceivedAt}, merged = 1,
              captured_at = ${mergedInto.mergedAt}, category = ${decision.category},
              next_check_at = ${now}`,
          );
        } else {
          await this.update(intent, Prisma.sql`next_check_at = ${now}`);
        }
        return 'lost_race';
      }
      this.options.metrics.captureDuration.observe({ result: 'captured' }, seconds);
      this.options.metrics.captures.inc({
        result: 'captured',
        source: sourceLabel(decision.sources),
        category: decision.category,
      });
      return 'captured';
    } catch (error) {
      const seconds = Number(process.hrtime.bigint() - started) / 1e9;
      if (error instanceof OriginalMissingError) {
        await this.markLost(intent, 'original_missing');
        this.options.metrics.captures.inc({
          result: 'lost',
          source: label,
          category: decision.category,
        });
        return 'lost';
      }
      if (error instanceof DeterministicCaptureError) {
        await this.update(
          intent,
          Prisma.sql`status = 'failed', last_error_code = ${error.code}, attempts = attempts + 1,
            closed_at = ${now}, next_check_at = ${now}`,
        );
        this.options.metrics.captureDuration.observe({ result: 'failed' }, seconds);
        this.options.metrics.captures.inc({
          result: error.code === 'integrity_mismatch' ? 'integrity_failed' : 'failed',
          source: label,
          category: decision.category,
        });
        this.options.logger.error(
          { intentId: intent.id.toString(), errCode: error.code },
          'capture failed deterministically',
        );
        return 'failed';
      }
      this.options.metrics.captureDuration.observe({ result: 'retry' }, seconds);
      throw error;
    }
  }

  /** Backoff after a failure; past the intent's max age the intent fails (A5.7). */
  private async retry(intent: IntentRow, code: string): Promise<IntentOutcome> {
    const now = this.now();
    const attempts = intent.attempts + 1;
    const maxAgeDays =
      intent.category === 'quarantined'
        ? Math.max(this.options.maxAgeDays, QUARANTINE_WAIT_MAX_DAYS)
        : this.options.maxAgeDays;
    const aged = now.getTime() - intent.createdAt.getTime() > maxAgeDays * DAY_MS;
    try {
      if (aged && intent.status === 'pending') {
        await this.update(
          intent,
          Prisma.sql`status = 'failed', last_error_code = ${code.slice(0, 64)},
            attempts = ${Math.min(attempts, 65_535)}, closed_at = ${now}, next_check_at = ${now}`,
        );
        this.options.metrics.captures.inc({
          result: 'failed',
          source: sourceLabel({ journal: intent.sourceJournal, policy: intent.sourcePolicy }),
          category: 'none',
        });
        return 'failed';
      }
      const delay = backoffDelay(
        attempts,
        { baseMs: this.options.retryBaseMs, maxMs: this.options.retryMaxMs },
        this.options.random,
      );
      await this.update(
        intent,
        Prisma.sql`attempts = ${Math.min(attempts, 65_535)}, last_error_code = ${code.slice(0, 64)},
          next_check_at = ${new Date(now.getTime() + delay)}`,
      );
    } catch (error) {
      if (!(error instanceof LeaseLostError)) {
        this.options.logger.warn({ ...errorFields(error) }, 'intent retry not recorded');
      }
    }
    return 'retry';
  }

  private async markLost(intent: IntentRow, reason: string): Promise<void> {
    const now = this.now();
    await this.update(
      intent,
      Prisma.sql`status = 'lost', skip_reason = ${reason}, last_error_code = ${reason},
        closed_at = ${now}, next_check_at = ${now}`,
    );
    this.options.logger.warn(
      { intentId: intent.id.toString(), reason },
      'capture intent lost (message or original gone)',
    );
  }

  /** CAS update on the claimed lease; the lease is released. */
  private async update(intent: IntentRow, set: Prisma.Sql): Promise<void> {
    const changed = await this.prisma.$executeRaw`
      UPDATE archive_capture_intents SET ${set}, lease_until = NULL, updated_at = NOW(3)
      WHERE id = ${intent.id} AND received_at = ${intent.receivedAt}
        AND lease_until = ${intent.leaseUntil}`;
    if (changed !== 1) throw new LeaseLostError();
  }

  /**
   * Outcome refresh (A7) of a `captured_open` intent: message state and reason, the parties'
   * statuses, verdict / action / risk / malicious, a later source (policy or journal), and new terminal
   * rounds or risk revisions frozen as new snapshot objects (≤ 16 links; never the EML or the
   * journal object). Changes enqueue an index upsert in the same transaction. The intent closes
   * after the final +24 h check or the outcome window.
   *
   * Step 8.6 (D7, ADR-0088): a merged intent reads its record by `(archive_id,
   * archive_received_at)` and its facts by its own message. A gateway copy is authoritative for the
   * record's security outcome (state, verdict, action, risk, malicious, category, scan links; a
   * merged gateway copy's snapshots are encrypted under the record's subject); an intake copy never
   * overwrites a record that has a gateway copy, and only its parties are refreshed. The parties of
   * a record with merged copies are refreshed by address into the merged parties.
   */
  private async refresh(intent: IntentRow): Promise<IntentOutcome> {
    const now = this.now();
    const record =
      intent.merged && intent.archiveId !== null
        ? await this.prisma.emailArchive.findUnique({
            where: {
              id_receivedAt: {
                id: intent.archiveId,
                receivedAt: intent.archiveReceivedAt ?? intent.receivedAt,
              },
            },
          })
        : await this.prisma.emailArchive.findUnique({
            where: {
              messageId_receivedAt: { messageId: intent.messageId, receivedAt: intent.receivedAt },
            },
          });
    if (
      record === null ||
      record.organizationId !== intent.organizationId ||
      record.status === 'disposing'
    ) {
      await this.update(
        intent,
        Prisma.sql`status = 'closed', closed_at = ${now}, next_check_at = ${now}`,
      );
      return 'closed';
    }
    const facts = await this.reader.message(this.prisma, intent);
    if (facts === null) {
      await this.update(
        intent,
        Prisma.sql`status = 'closed', closed_at = ${now}, next_check_at = ${now}`,
      );
      return 'closed';
    }
    const m = facts.message;
    const copySource = m.ingestSource;
    if (copySource === 'mailbox_api') {
      // Step API-1 D7.6: no record is ever built from a mailbox API copy; nothing to refresh.
      await this.update(
        intent,
        Prisma.sql`status = 'closed', closed_at = ${now}, next_check_at = ${now}`,
      );
      return 'closed';
    }
    // Step 8.6 D7: who may change the record's security outcome.
    const authoritative = copySource === 'gateway' || (!intent.merged && !record.sourceGateway);
    const objects = archiveRecordObjectsSchema.parse(record.objects);
    const links = archiveScanRoundsSchema.parse(record.scanRounds);
    const linked = new Set(links.map((l) => `${l.round}:${l.revision}`));
    const rounds = authoritative ? await this.reader.terminalRounds(this.prisma, m) : [];
    const newest = rounds[0];
    const added: { refs: ArchiveRecordObjects['scans']; links: ArchiveScanRounds } = {
      refs: [],
      links: [],
    };
    let rows: Awaited<ReturnType<FactsReader['roundRows']>> | null = null;
    if (
      newest !== undefined &&
      !linked.has(`${newest.round}:${newest.revision}`) &&
      links.length < MAX_SCAN_LINKS &&
      !links.some(
        (l) => l.round > newest.round || (l.round === newest.round && l.revision > newest.revision),
      ) &&
      record.wrappedDek !== null
    ) {
      const tenantKey = await this.options.keys.version(record.organizationId, record.keyVersion);
      const dek = unwrapRecordKey(tenantKey.key, record.wrappedDek, {
        organizationId: record.organizationId,
        messagePublicId: record.messagePublicId,
        captureId: objects.captureId,
        keyVersion: record.keyVersion,
      });
      try {
        const lock: ObjectLockSpec | null =
          record.lockMode === 'none' || record.lockUntil === null
            ? null
            : {
                mode: record.lockMode,
                until: new Date(
                  Math.max(record.lockUntil.getTime(), now.getTime() + LOCK_FLOOR_MS),
                ),
              };
        const snap = await writeScanSnapshot({
          storage: this.options.storage,
          reader: this.reader,
          db: this.prisma,
          facts,
          round: newest,
          dek,
          // A merged copy's snapshots lie under its own message prefix, under the record subject.
          captureId: intent.merged ? uuidv7(now.getTime()) : objects.captureId,
          frozenAt: now,
          lock,
          chunkBytes: this.options.chunkBytes,
          ...(intent.merged ? { subjectId: record.messagePublicId } : {}),
        });
        added.refs.push(snap.ref);
        added.links.push(snap.link);
        rows = snap.rows;
      } finally {
        dek.fill(0);
      }
    }
    const intake = await this.reader.intake(this.prisma, m);
    const fresh = partiesOf(facts, intake);
    const storedParties = archivePartiesSchema.safeParse(record.parties);
    const parties =
      (record.mergedCount > 0 || intent.merged) && storedParties.success
        ? refreshMergedParties(storedParties.data, fresh, copySource)
        : fresh;
    const malicious = authoritative ? record.malicious || isMalicious(m, rows) : record.malicious;
    const category =
      authoritative && record.category === 'quarantined'
        ? (categoryOf({ ...m, recipients: facts.recipients, ingestSource: m.ingestSource }) ??
          record.category)
        : record.category;
    const outcomeChanged =
      authoritative &&
      (record.messageState !== m.status ||
        (record.messageStateReason ?? null) !== (m.statusReason ?? null) ||
        (record.finalVerdict ?? null) !== (m.finalVerdict ?? null) ||
        (record.finalAction ?? null) !== (m.finalAction ?? null) ||
        (record.riskScore ?? null) !== (m.riskScore ?? null));
    const changed =
      added.refs.length > 0 ||
      outcomeChanged ||
      !sameParties(record.parties, parties) ||
      record.malicious !== malicious ||
      (intent.sourcePolicy && !record.capturedByPolicy) ||
      (intent.sourceJournal && !record.capturedByJournal) ||
      category !== record.category;
    const final = isFinalMessageStatus(m.status);
    const next = nextOutcomeCheckAt({
      now,
      capturedAt: intent.capturedAt ?? record.archivedAt,
      final,
      finalSince: m.statusChangedAt,
      outcomeWindowDays: this.options.outcomeWindowDays,
    });
    const nextObjects: ArchiveRecordObjects = {
      ...objects,
      scans: [...objects.scans, ...added.refs],
    };
    const storedBytes = added.refs.reduce((s, r) => s + r.bytes, 0);
    await this.prisma.$transaction(async (tx) => {
      if (changed) {
        const updated = await tx.emailArchive.updateMany({
          where: {
            id: record.id,
            receivedAt: record.receivedAt,
            organizationId: record.organizationId,
            status: { not: 'disposing' },
            updatedAt: record.updatedAt,
          },
          data: {
            ...(authoritative
              ? {
                  messageState: m.status,
                  messageStateReason: m.statusReason?.slice(0, 64) ?? null,
                  finalVerdict: m.finalVerdict,
                  finalAction: m.finalAction,
                  riskScore: m.riskScore,
                }
              : {}),
            parties,
            ...(record.mergedCount > 0 || intent.merged
              ? { recipientCount: Math.min(parties.recipients.length, 65_535) }
              : {}),
            category,
            malicious,
            capturedByJournal: record.capturedByJournal || intent.sourceJournal,
            capturedByPolicy: record.capturedByPolicy || intent.sourcePolicy,
            policyRuleRef: record.policyRuleRef ?? intent.policyRuleRef?.slice(0, 128) ?? null,
            ...(added.refs.length > 0
              ? {
                  objects: nextObjects,
                  scanRounds: [...links, ...added.links],
                  storedBytes: record.storedBytes + BigInt(storedBytes),
                }
              : {}),
            outcomeRefreshedAt: now,
          },
        });
        if (updated.count !== 1) throw new LeaseLostError();
        await tx.archiveIndexQueue.create({
          data: {
            organizationId: record.organizationId,
            messageId: record.messageId,
            receivedAt: record.receivedAt,
            messagePublicId: record.messagePublicId,
            op: 'upsert',
          },
          select: { id: true },
        });
      }
      const set =
        next === null
          ? Prisma.sql`status = 'closed', closed_at = ${now}, next_check_at = ${now}`
          : Prisma.sql`next_check_at = ${next}`;
      const done = await tx.$executeRaw`
        UPDATE archive_capture_intents SET ${set}, lease_until = NULL, updated_at = NOW(3)
        WHERE id = ${intent.id} AND received_at = ${intent.receivedAt}
          AND lease_until = ${intent.leaseUntil}`;
      if (done !== 1) throw new LeaseLostError();
    });
    if (storedBytes > 0) this.options.metrics.captureBytes.inc(storedBytes);
    return next === null ? 'closed' : 'refreshed';
  }

  /**
   * Intent gauges and stuck-intent detection (A15, capture role): pending intents past their
   * max age (a wait in quarantine: past QUARANTINE_WAIT_MAX_DAYS) whose next check lies in the
   * future are made due now, so the scheduler decides them (`skipped (max_age)`, `failed` or
   * `lost`) instead of letting them sit.
   *
   * `archive_intent_oldest_pending_seconds` is the age of the oldest pending intent that is NOT
   * waiting as designed: overdue (its check is more than BACKLOG_GRACE_MS late: the scheduler is
   * not keeping up) or erroring (`last_error_code` set by a retry). Intents waiting for a
   * non-final message or in quarantine are expected to wait and do not count (review finding
   * of 8.1: the alert must keep its meaning for real stalls).
   */
  async maintain(): Promise<{ pending: number; oldestSeconds: number; stuck: number }> {
    const now = this.now();
    const aged = new Date(now.getTime() - this.options.maxAgeDays * DAY_MS);
    const quarantineAged = new Date(
      now.getTime() - Math.max(this.options.maxAgeDays, QUARANTINE_WAIT_MAX_DAYS) * DAY_MS,
    );
    const stuck = await this.prisma.$executeRaw`
      UPDATE archive_capture_intents SET next_check_at = ${now}, updated_at = NOW(3)
      WHERE status = 'pending' AND next_check_at > ${now}
        AND (((category IS NULL OR category <> 'quarantined') AND created_at < ${aged})
          OR (category = 'quarantined' AND created_at < ${quarantineAged}))
        AND (lease_until IS NULL OR lease_until < ${now})
        ${orgFilter('organization_id', this.options.organizationIds)}`;
    const [count] = await this.prisma.$queryRaw<Array<{ n: bigint | number }>>`
      SELECT COUNT(*) AS n FROM (
        SELECT 1 FROM archive_capture_intents WHERE status = 'pending'
          ${orgFilter('organization_id', this.options.organizationIds)}
        LIMIT ${PENDING_CAP}) AS bounded`;
    const [oldest] = await this.prisma.$queryRaw<Array<{ at: Date | null }>>`
      SELECT MIN(created_at) AS at FROM archive_capture_intents
      WHERE status = 'pending'
        AND (next_check_at < ${new Date(now.getTime() - BACKLOG_GRACE_MS)}
          OR last_error_code IS NOT NULL)
        ${orgFilter('organization_id', this.options.organizationIds)}`;
    const pending = Number(count?.n ?? 0);
    const oldestSeconds =
      oldest?.at instanceof Date ? Math.max(0, (now.getTime() - oldest.at.getTime()) / 1000) : 0;
    this.options.metrics.intentsPending.set(pending);
    this.options.metrics.intentOldestPending.set(oldestSeconds);
    return { pending, oldestSeconds, stuck };
  }
}

export type { MessageFacts };
