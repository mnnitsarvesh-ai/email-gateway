import {
  type HandleOutcome,
  isUniqueViolation,
  NonRetryableError,
  uuidv7,
  withTransactionDefaults,
} from '@email-gateway/common';
import { type Prisma, processOnce, type PrismaClient } from '@email-gateway/database';
import { EventTypes, messageScannedV1 } from '@email-gateway/event-contracts';
import {
  type LifecycleMetrics,
  type LifecycleSnapshot,
  lockLifecycle,
  type TransitionActor,
  transitionMessage,
} from '@email-gateway/message-lifecycle';
import { aggregateRound, type FinalEngineResult } from './aggregate';
import type { EngineSettingsRow } from './registry';
import {
  type AttemptInput,
  type CompletionContext,
  type CompletionResult,
  decideOpen,
  type FinalizeInput,
  type FinalizeResult,
  type FinalRowInput,
  type OpenRoundInput,
  type OpenRoundResult,
  type ScanKindValue,
  type ScanMessageRecord,
  type ScanRound,
  type ScanStore,
  type SweepCandidate,
  type SweepResult,
} from './scan-store';

/** `email_events.source_service` and the actor service of the scan transitions. */
export const SCAN_SERVICE = 'email-worker';

/** The scanner actor of E3, E6 and E7 (step 3.3 L3). */
export const SCANNER_ACTOR: TransitionActor = {
  role: 'scanner',
  service: SCAN_SERVICE,
  type: 'system',
};

/** Most recipients loaded for the envelope (the Rspamd client sends at most 100). */
const MAX_ENVELOPE_RECIPIENTS = 1_000;

const json = (value: unknown): Prisma.InputJsonValue => value as Prisma.InputJsonValue;

interface ScanRow {
  id: bigint;
  received_at: Date;
  message_id: bigint;
  organization_id: bigint;
  status: string;
  lifecycle_round: number | bigint;
  scan_kind: string;
  required_engines: unknown;
  started_at: Date | null;
  deadline_at: Date | null;
}

function stringArray(value: unknown): string[] {
  const parsed: unknown = typeof value === 'string' ? JSON.parse(value) : value;
  return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : [];
}

function toRound(row: ScanRow): ScanRound {
  const startedAt = row.started_at ?? row.received_at;
  return {
    scanId: BigInt(row.id),
    receivedAt: row.received_at,
    messageId: BigInt(row.message_id),
    organizationId: BigInt(row.organization_id),
    round: Number(row.lifecycle_round),
    scanKind: row.scan_kind === 'rescan' ? 'rescan' : 'initial',
    requiredEngines: stringArray(row.required_engines),
    startedAt,
    deadlineAt: row.deadline_at ?? startedAt,
  };
}

const decimal = (value: number | null): Prisma.Decimal | number | null =>
  value === null ? null : Math.round(value * 1000) / 1000;

/**
 * MySQL side of the scan stage (step 4.1 S5, S6, S10), on the **writer** only (§2.0 invariant
 * 6). Every statement is scoped by the writer row's `(message_id, received_at)` and its
 * organization. Lock order in every transaction: message row (`lockLifecycle`) → scan row
 * (`SELECT … FOR UPDATE`) → result rows. The lifecycle is changed only through
 * `@email-gateway/message-lifecycle` (one-door rule).
 */
export class ScanRepository implements ScanStore {
  private readonly txPrisma: PrismaClient;

  constructor(
    private readonly prisma: PrismaClient,
    /** SCAN_DB_TIMEOUT_MS: timeout and maxWait of every writer transaction. */
    txTimeoutMs: number,
    private readonly lifecycleMetrics?: LifecycleMetrics,
  ) {
    this.txPrisma = withTransactionDefaults(prisma, { timeoutMs: txTimeoutMs });
  }

  async isProcessed(consumer: string, eventId: string): Promise<boolean> {
    const row = await this.prisma.messageIdempotency.findUnique({
      where: { consumer_eventId: { consumer, eventId } },
      select: { eventId: true },
    });
    return row !== null;
  }

  async recordNoop(consumer: string, eventId: string): Promise<HandleOutcome> {
    const result = await processOnce(this.txPrisma, consumer, eventId, () => Promise.resolve());
    return result.status === 'duplicate' ? 'duplicate' : 'handled';
  }

  async loadMessage(
    messageId: bigint,
    receivedAt: Date,
    organizationId: bigint,
  ): Promise<ScanMessageRecord | null> {
    const row = await this.prisma.emailMessage.findFirst({
      where: { id: messageId, receivedAt, organizationId },
      select: {
        id: true,
        receivedAt: true,
        organizationId: true,
        direction: true,
        emlObjectKey: true,
        sizeBytes: true,
        clientIp: true,
        clientHelo: true,
        clientName: true,
        envelopeFrom: true,
        mtaQueueId: true,
      },
    });
    if (!row) return null;
    const recipients = await this.prisma.emailRecipient.findMany({
      where: { messageId, receivedAt, organizationId },
      orderBy: { rcptSeq: 'asc' },
      select: { address: true },
      take: MAX_ENVELOPE_RECIPIENTS,
    });
    return { ...row, recipients: recipients.map((r) => r.address) };
  }

  async loadEngineSettings(
    organizationId: bigint,
    engine: string,
  ): Promise<EngineSettingsRow | null> {
    const row = await this.prisma.scanEngineSetting.findUnique({
      where: { organizationId_engine: { organizationId, engine } },
      select: { settings: true, version: true },
    });
    return row ? { settings: row.settings, version: row.version } : null;
  }

  openRound(input: OpenRoundInput): Promise<OpenRoundResult> {
    const { message } = input;
    const ref = {
      id: message.id,
      receivedAt: message.receivedAt,
      organizationId: message.organizationId,
    };
    return this.txPrisma.$transaction(async (tx): Promise<OpenRoundResult> => {
      const snapshot = await lockLifecycle(tx, ref);
      if (!snapshot) return { kind: 'skip', reason: 'message_not_found' };
      const decision = decideOpen(snapshot, input.round, input.trigger);
      if (decision.action === 'skip') return { kind: 'skip', reason: decision.reason };

      if (decision.action === 'check_final') {
        // A completed round of this engine: a duplicate (its final row exists); otherwise the
        // round ended without this engine, which completion never allows (defence in depth).
        const scan = await this.findScan(tx, message, input.round);
        if (scan && (await this.engineRows(tx, scan, input.engine)).finalExists) {
          return { kind: 'skip', reason: 'already_final' };
        }
        return { kind: 'skip', reason: `lifecycle_${snapshot.state}` };
      }

      let opened = false;
      if (decision.action === 'open_e3') {
        const outcome = await transitionMessage(
          tx,
          {
            message: ref,
            to: 'scanning',
            reason: 'scan_started',
            actor: SCANNER_ACTOR,
            // Shared by every engine: the first opener applies E3, the others get `duplicate`.
            transitionKey: `scan-open:${message.id.toString()}:0`,
            causationEventId: input.eventId,
            correlationId: input.correlationId,
            expectedRound: 0,
            expectedFrom: ['persisted'],
          },
          this.lifecycleMetrics ? { metrics: this.lifecycleMetrics } : {},
        );
        if (outcome.result === 'applied') opened = true;
        else if (outcome.result !== 'duplicate') {
          return { kind: 'skip', reason: `lifecycle_${snapshot.state}` };
        }
      }

      const deadlineAt = new Date(input.now.getTime() + input.deadlineSeconds * 1000);
      await tx.emailScan.createMany({
        data: [
          {
            receivedAt: message.receivedAt,
            messageId: message.id,
            organizationId: message.organizationId,
            scanKind: input.scanKind,
            lifecycleRound: input.round,
            status: 'running',
            startedAt: input.now,
            deadlineAt,
            requiredEngines: json(input.requiredEngines),
            triggerEventId: input.eventId,
          },
        ],
        // INSERT IGNORE: the round's row exists when another engine (or a redelivery) opened it.
        skipDuplicates: true,
      });
      const scan = await this.findScan(tx, message, input.round);
      if (!scan) throw new Error('email_scans row of the round not found after insert');
      const rows = await this.engineRows(tx, scan, input.engine);
      return {
        kind: 'open',
        round: scan,
        finalExists: rows.finalExists,
        attempts: rows.attempts,
        opened,
      };
    });
  }

  async recordAttempt(input: AttemptInput): Promise<void> {
    const { round } = input;
    try {
      await this.prisma.scanEngineResult.create({
        data: {
          receivedAt: round.receivedAt,
          scanId: round.scanId,
          messageId: round.messageId,
          organizationId: round.organizationId,
          engine: input.engine,
          engineVersion: input.engineVersion,
          outcome: input.outcome,
          durationMs: Math.max(0, Math.round(input.durationMs)),
          completedAt: input.completedAt,
          attempt: input.attempt,
          isFinal: false,
          reasonCodes: json([input.reasonCode]),
          errorCode: input.errorCode,
          settingsVersion: input.settingsVersion,
        },
        select: { id: true },
      });
    } catch (err) {
      // A concurrent delivery (another event id) recorded the same attempt number first.
      if (!isUniqueViolation(err)) throw err;
    }
  }

  async finalize(input: FinalizeInput): Promise<FinalizeResult> {
    const result = await processOnce(this.txPrisma, input.consumer, input.eventId, async (tx) => {
      const snapshot = await this.lockMessage(tx, input.round);
      const scan = await this.lockScan(tx, input.round);
      let inserted = false;
      if (input.final && scan) {
        const existing = await this.engineRows(tx, scan, input.final.engine);
        if (!existing.finalExists) {
          await this.insertFinal(tx, scan, input.final);
          inserted = true;
        }
      }
      const completion = scan
        ? await this.complete(tx, scan, snapshot, input.completion)
        : ({ kind: 'already_completed' } as const);
      return { inserted, completion };
    });
    return result.status === 'duplicate'
      ? { kind: 'duplicate' }
      : { kind: 'handled', ...result.result };
  }

  async sweepCandidates(
    now: Date,
    lookbackHours: number,
    limit: number,
    organizationIds?: readonly bigint[],
  ): Promise<SweepCandidate[]> {
    const rows = await this.prisma.emailScan.findMany({
      where: {
        status: 'running',
        // Bounded by the round's own deadline, never by the message's received_at: a rescan
        // round (E19) of a message received weeks earlier is swept like a fresh one (S10).
        deadlineAt: { lt: now, gte: new Date(now.getTime() - lookbackHours * 3_600_000) },
        ...(organizationIds ? { organizationId: { in: [...organizationIds] } } : {}),
      },
      orderBy: { deadlineAt: 'asc' },
      take: limit,
      select: { id: true, receivedAt: true, messageId: true, organizationId: true },
    });
    return rows.map((r) => ({
      scanId: r.id,
      receivedAt: r.receivedAt,
      messageId: r.messageId,
      organizationId: r.organizationId,
    }));
  }

  sweepRound(candidate: SweepCandidate, now: Date): Promise<SweepResult> {
    return this.txPrisma.$transaction(async (tx): Promise<SweepResult> => {
      const ref = { ...candidate, scanId: candidate.scanId };
      const snapshot = await lockLifecycle(tx, {
        id: ref.messageId,
        receivedAt: ref.receivedAt,
        organizationId: ref.organizationId,
      });
      const scan = await this.lockScanRow(tx, ref.scanId, ref.receivedAt);
      if (!scan || scan.status !== 'running') {
        return { finalized: [], completion: { kind: 'already_completed' } };
      }
      const round = toRound(scan);
      const rows = await tx.scanEngineResult.findMany({
        where: { scanId: round.scanId, receivedAt: round.receivedAt },
        select: { engine: true, isFinal: true },
      });
      const finalized: string[] = [];
      for (const engine of round.requiredEngines) {
        const own = rows.filter((r) => r.engine === engine);
        if (own.some((r) => r.isFinal)) continue;
        await this.insertFinal(tx, round, {
          engine,
          attempt: own.length + 1,
          outcome: 'timeout',
          errorCode: 'deadline_exceeded',
          engineVersion: null,
          score: null,
          requiredScore: null,
          action: null,
          reasonCodes: ['engine.deadline_exceeded'],
          evidence: null,
          durationMs: 0,
          settingsVersion: null,
          auth: null,
        });
        finalized.push(engine);
      }
      const completion = await this.complete(tx, round, snapshot, {
        causationEventId: null,
        correlationId: `message:${round.messageId.toString()}`,
        now,
      });
      return { finalized, completion };
    });
  }

  // -------------------------------------------------------------------------------------------

  private lockMessage(
    tx: Prisma.TransactionClient,
    round: ScanRound,
  ): Promise<LifecycleSnapshot | null> {
    return lockLifecycle(tx, {
      id: round.messageId,
      receivedAt: round.receivedAt,
      organizationId: round.organizationId,
    });
  }

  private async lockScanRow(
    tx: Prisma.TransactionClient,
    scanId: bigint,
    receivedAt: Date,
  ): Promise<ScanRow | null> {
    const rows = await tx.$queryRaw<ScanRow[]>`
      SELECT id, received_at, message_id, organization_id, status, lifecycle_round, scan_kind,
             required_engines, started_at, deadline_at
      FROM email_scans
      WHERE id = ${scanId} AND received_at = ${receivedAt}
      FOR UPDATE`;
    return rows[0] ?? null;
  }

  private async lockScan(
    tx: Prisma.TransactionClient,
    round: ScanRound,
  ): Promise<ScanRound | null> {
    const row = await this.lockScanRow(tx, round.scanId, round.receivedAt);
    if (!row || BigInt(row.organization_id) !== round.organizationId) return null;
    return toRound(row);
  }

  private async findScan(
    tx: Prisma.TransactionClient,
    message: Pick<ScanMessageRecord, 'id' | 'receivedAt' | 'organizationId'>,
    round: number,
  ): Promise<ScanRound | null> {
    const row = await tx.emailScan.findFirst({
      where: {
        messageId: message.id,
        receivedAt: message.receivedAt,
        organizationId: message.organizationId,
        lifecycleRound: round,
      },
      select: {
        id: true,
        receivedAt: true,
        messageId: true,
        organizationId: true,
        status: true,
        lifecycleRound: true,
        scanKind: true,
        requiredEngines: true,
        startedAt: true,
        deadlineAt: true,
      },
    });
    if (!row) return null;
    return toRound({
      id: row.id,
      received_at: row.receivedAt,
      message_id: row.messageId,
      organization_id: row.organizationId,
      status: row.status,
      lifecycle_round: row.lifecycleRound,
      scan_kind: row.scanKind,
      required_engines: row.requiredEngines,
      started_at: row.startedAt,
      deadline_at: row.deadlineAt,
    });
  }

  private async engineRows(
    tx: Prisma.TransactionClient,
    scan: ScanRound,
    engine: string,
  ): Promise<{ finalExists: boolean; attempts: number }> {
    const rows = await tx.scanEngineResult.findMany({
      where: { scanId: scan.scanId, receivedAt: scan.receivedAt, engine },
      select: { isFinal: true },
    });
    return {
      finalExists: rows.some((r) => r.isFinal),
      attempts: rows.filter((r) => !r.isFinal).length,
    };
  }

  private async insertFinal(
    tx: Prisma.TransactionClient,
    scan: ScanRound,
    final: FinalRowInput,
  ): Promise<void> {
    const completedAt = new Date();
    await tx.scanEngineResult.create({
      data: {
        receivedAt: scan.receivedAt,
        scanId: scan.scanId,
        messageId: scan.messageId,
        organizationId: scan.organizationId,
        engine: final.engine,
        engineVersion: final.engineVersion,
        outcome: final.outcome,
        score: decimal(final.score),
        requiredScore: decimal(final.requiredScore),
        action: final.action,
        durationMs: Math.max(0, Math.round(final.durationMs)),
        ...(final.evidence ? { evidence: json(final.evidence) } : {}),
        completedAt,
        attempt: final.attempt,
        isFinal: true,
        reasonCodes: json(final.reasonCodes),
        errorCode: final.errorCode,
        settingsVersion: final.settingsVersion,
      },
      select: { id: true },
    });
    if (final.auth) {
      const auth = final.auth;
      await tx.emailAuthResult.createMany({
        data: [
          {
            receivedAt: scan.receivedAt,
            messageId: scan.messageId,
            organizationId: scan.organizationId,
            scanId: scan.scanId,
            engine: final.engine,
            spf: auth.spf.result,
            spfDomain: auth.spf.domain,
            dkim: auth.dkim.result,
            dkimSignatures: json(auth.dkim.signatures),
            dmarc: auth.dmarc.result,
            dmarcPolicy: auth.dmarc.policy,
            dmarcDomain: auth.dmarc.domain,
            arc: auth.arc.result,
          },
        ],
        // Unique per (scan, engine): an earlier final of this engine wrote it already.
        skipDuplicates: true,
      });
    }
  }

  /**
   * S5 step 6 / S6 in the caller's transaction (message and scan rows locked): when every
   * required engine has its final row, aggregate, complete the `email_scans` row, apply E6/E7
   * and write `mail.message.scanned.v1` (only when the transition applied).
   */
  private async complete(
    tx: Prisma.TransactionClient,
    scan: ScanRound,
    snapshot: LifecycleSnapshot | null,
    ctx: CompletionContext,
  ): Promise<CompletionResult> {
    const row = await this.lockScanRow(tx, scan.scanId, scan.receivedAt);
    if (!row || row.status !== 'running') return { kind: 'already_completed' };
    const round = toRound(row);
    const finals = await tx.scanEngineResult.findMany({
      where: { scanId: round.scanId, receivedAt: round.receivedAt, isFinal: true },
      select: { engine: true, outcome: true, errorCode: true, reasonCodes: true, attempt: true },
    });
    const required = round.requiredEngines;
    if (!required.every((engine) => finals.some((f) => f.engine === engine))) {
      return { kind: 'not_complete' };
    }
    const results: FinalEngineResult[] = finals.map((f) => ({
      engine: f.engine,
      outcome: f.outcome,
      errorCode: f.errorCode,
      reasonCodes: stringArray(f.reasonCodes),
      attempts: f.attempt,
    }));
    const aggregate = aggregateRound(required, results);
    await tx.emailScan.updateMany({
      where: { id: round.scanId, receivedAt: round.receivedAt, status: 'running' },
      data: {
        status: aggregate.scanStatus,
        scanVerdict: aggregate.verdict,
        reasonCodes: json(aggregate.reasonCodes),
        completedAt: ctx.now,
      },
    });

    const outcome = await transitionMessage(
      tx,
      {
        message: {
          id: round.messageId,
          receivedAt: round.receivedAt,
          organizationId: round.organizationId,
        },
        to: aggregate.outcome,
        reason: aggregate.lifecycleReason,
        actor: SCANNER_ACTOR,
        transitionKey: `scan-complete:${round.messageId.toString()}:${String(round.round)}`,
        causationEventId: ctx.causationEventId,
        correlationId: ctx.correlationId,
        expectedRound: round.round,
        expectedFrom: ['scanning'],
      },
      this.lifecycleMetrics ? { metrics: this.lifecycleMetrics } : {},
    );
    if (outcome.result !== 'applied') {
      return {
        kind: 'completed',
        aggregate,
        round,
        transition: outcome.result,
        scannedEventId: null,
      };
    }

    const direction = outcome.snapshot.direction ?? snapshot?.direction;
    const parsed = messageScannedV1.safeParse({
      messageId: round.messageId.toString(),
      receivedAt: round.receivedAt.toISOString(),
      direction,
      emlS3Key: outcome.snapshot.emlObjectKey,
      lifecycleRound: round.round,
      scanId: round.scanId.toString(),
      scanKind: round.scanKind satisfies ScanKindValue,
      outcome: aggregate.outcome,
      verdict: aggregate.verdict,
      engines: results.map((r) => ({
        engine: r.engine,
        required: required.includes(r.engine),
        outcome: r.outcome,
        attempts: Math.max(1, r.attempts),
      })),
      reasonCodes: aggregate.reasonCodes,
      completedAt: ctx.now.toISOString(),
    });
    if (!parsed.success) {
      // A contract violation never commits half a completion; the delivery is dead-lettered.
      throw new NonRetryableError('scanned_payload_invalid');
    }
    const scannedEventId = uuidv7(ctx.now.getTime());
    await tx.messageOutbox.create({
      data: {
        eventId: scannedEventId,
        organizationId: round.organizationId,
        eventType: EventTypes.MessageScanned,
        aggregateType: 'message',
        aggregateId: round.messageId.toString(),
        correlationId: ctx.correlationId,
        payload: parsed.data,
      },
      select: { id: true },
    });
    return { kind: 'completed', aggregate, round, transition: 'applied', scannedEventId };
  }
}
