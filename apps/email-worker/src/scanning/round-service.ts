import { performance } from 'node:perf_hooks';
import type { Readable } from 'node:stream';
import type { HandleOutcome } from '@email-gateway/common';
import {
  type EventEnvelope,
  EventTypes,
  type MessageParsedV1,
  type MessageRescanRequestedV1,
  type MessageScanStageReadyV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import { errorFields } from '../mime-ingestion/error-fields';
import { isOrganizationKey } from '../mime-ingestion/part-keys';
import type { CircuitBreaker } from './circuit-breaker';
import {
  EngineAttemptFailedError,
  type EngineFailure,
  type EngineScanContext,
  type EngineScanOutcome,
  failureMetricReason,
  failureReasonCode,
  type ScanEngineAdapter,
} from './engine';
import type { EngineBudget, EngineSettingsResolution, ScanEngineRegistration } from './registry';
import type { ScanMetrics } from './scan-metrics';
import type {
  CompletionResult,
  FinalRowInput,
  ScanMessageRecord,
  ScanRound,
  ScanStore,
  ScanTrigger,
} from './scan-store';

/**
 * The events an engine queue consumes (S2): parse results and rescans for stage-1 engines, the
 * stage trigger for stage-2 engines (step 4.4 B2).
 */
export type ScanTriggerPayload =
  MessageParsedV1 | MessageRescanRequestedV1 | MessageScanStageReadyV1;
export type ScanTriggerEvent = EventEnvelope<ScanTriggerPayload>;

export interface SettingsLookup {
  resolve(
    registration: ScanEngineRegistration,
    organizationId: bigint,
  ): Promise<EngineSettingsResolution>;
}

/** Opens a streaming read of a stored EML; rejects with EmlUnavailableError when missing. */
export type EmlOpener = (key: string, signal: AbortSignal) => Promise<Readable>;

export interface RoundServiceOptions {
  registration: ScanEngineRegistration;
  adapter: ScanEngineAdapter;
  store: ScanStore;
  settings: SettingsLookup;
  openEml: EmlOpener;
  breaker: CircuitBreaker;
  metrics: ScanMetrics;
  logger: Logger;
  budget: EngineBudget;
  /** Required engines of a new round (S4 snapshot from SCAN_ENGINES). */
  requiredEngines: readonly string[];
  /** SCAN_ROUND_DEADLINE_SECONDS. */
  deadlineSeconds: number;
  /** Default the registration's consumer name; integration tests use a per-run name. */
  consumer?: string;
  now?: () => Date;
}

/** Logs and metrics after a round completed (shared with the deadline sweeper). */
export function reportCompletion(
  completion: CompletionResult,
  metrics: ScanMetrics,
  logger: Logger,
  engines: readonly string[],
  ids: Record<string, string | number>,
  now: Date,
): void {
  if (completion.kind !== 'completed') return;
  const { aggregate, round } = completion;
  metrics.round(
    aggregate.outcome,
    aggregate.verdict,
    round.scanKind,
    (now.getTime() - round.startedAt.getTime()) / 1000,
  );
  const log = {
    ...ids,
    scanId: round.scanId.toString(),
    round: round.round,
    outcome: aggregate.outcome,
    verdict: aggregate.verdict,
    reasonCodes: aggregate.reasonCodes,
    transition: completion.transition,
  };
  if (completion.transition === 'applied') {
    if (aggregate.outcome === 'scanned') logger.info(log, 'scan round completed');
    else logger.warn(log, 'scan round failed');
    return;
  }
  for (const engine of engines) metrics.superseded.inc({ engine });
  logger.info(log, 'scan round completed after it was superseded; no scanned event written');
}

/**
 * One engine's delivery of a scan trigger (step 4.1 S5, docs/plan/steps/09-rspamd.md), generic
 * over the registry: it never names an engine.
 *
 * 1. ledger check (`duplicate`); 2. the writer row of the envelope's organization (absent →
 * ledger row only, `message_not_found`), the EML key checked against `org/<id>/` and the row;
 * 3. open (or join) the round in a short transaction (E3 `scan-open:<id>:0`, the `email_scans`
 * row, this engine's rows); 4. scan outside any transaction through the engine's circuit
 * breaker with a per-call timeout; 5. a retryable failure within the attempt budget and the
 * deadline is a non-final row and `EngineAttemptFailedError` (retried with backoff); anything
 * else is finalized through `processOnce` with the completion check (6) in the same
 * transaction. A transient failure (MySQL, S3, network) is thrown unchanged: no row, the
 * consumer retries it without consuming an attempt.
 *
 * Step 4.4 B2 (stage-2 engines): a `scan_stage_ready.v1` delivery runs in the round its payload
 * names (`lifecycleRound`); a trigger for another engine is a ledger no-op
 * (`other_stage_engine`); the round is never opened by it — it must exist with the payload's
 * `scanId` (else a ledger no-op `stage_round_missing`, warned). Everything after the open is the
 * same for both stages. The completion check of the transaction that inserts the last dependency
 * final writes the stage triggers (`ScanStore.finalize` → `stageTriggers`).
 *
 * Logs carry ids, codes, counts and durations only (never symbols, options or addresses).
 */
export class ScanRoundService {
  readonly consumer: string;
  readonly engine: string;
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(private readonly options: RoundServiceOptions) {
    this.consumer = options.consumer ?? options.registration.consumerName;
    this.engine = options.registration.catalog.name;
    this.logger = options.logger.child({ component: 'scan-round', engine: this.engine });
    this.now = options.now ?? (() => new Date());
  }

  async handle(event: ScanTriggerEvent): Promise<HandleOutcome> {
    const { store, metrics } = this.options;
    const engine = this.engine;
    const startedAt = this.now();
    const occurred = Date.parse(event.occurredAt);
    if (Number.isFinite(occurred)) {
      metrics.eventLag.observe({ engine }, Math.max(0, (startedAt.getTime() - occurred) / 1000));
    }
    const trigger: ScanTrigger =
      event.eventType === EventTypes.MessageRescanRequested
        ? 'rescan'
        : event.eventType === EventTypes.MessageScanStageReady
          ? 'stage'
          : 'parsed';
    const payload = event.payload;
    const stage = trigger === 'stage' ? (payload as MessageScanStageReadyV1) : null;
    const round =
      trigger === 'parsed'
        ? 0
        : (payload as MessageRescanRequestedV1 | MessageScanStageReadyV1).lifecycleRound;
    const ids = {
      eventId: event.eventId,
      messageId: payload.messageId,
      organizationId: event.organizationId,
      round,
    };

    // 1. Ledger pre-check.
    if (await store.isProcessed(this.consumer, event.eventId)) {
      metrics.skip(engine, 'duplicate');
      return 'duplicate';
    }

    // A stage trigger names the engine it is for (B2); another engine's trigger is a no-op.
    if (stage && stage.engine !== engine) {
      const outcome = await store.recordNoop(this.consumer, event.eventId);
      metrics.skip(engine, 'other_stage_engine');
      this.logger.warn(
        { ...ids, stageEngine: stage.engine },
        'stage trigger for another engine; skipped',
      );
      return outcome;
    }

    // 2. The writer row of the envelope's organization (tenant from trusted context only).
    const organizationId = BigInt(event.organizationId);
    const message = await store.loadMessage(
      BigInt(payload.messageId),
      new Date(payload.receivedAt),
      organizationId,
    );
    if (!message) {
      const outcome = await store.recordNoop(this.consumer, event.eventId);
      metrics.skip(engine, 'message_not_found');
      this.logger.warn(ids, 'scan trigger for a message not found in the organization; skipped');
      return outcome;
    }
    const keyOk =
      isOrganizationKey(payload.emlS3Key, organizationId) &&
      payload.emlS3Key === message.emlObjectKey;

    // 3. Open (or join) the round.
    const opened = await store.openRound({
      message,
      round,
      scanKind: stage ? stage.scanKind : trigger === 'rescan' ? 'rescan' : 'initial',
      trigger,
      engine,
      eventId: event.eventId,
      correlationId: event.correlationId,
      requiredEngines: [...this.options.requiredEngines],
      deadlineSeconds: this.options.deadlineSeconds,
      now: startedAt,
      ...(stage ? { scanId: BigInt(stage.scanId) } : {}),
    });
    if (opened.kind === 'skip') {
      const outcome = await store.recordNoop(this.consumer, event.eventId);
      metrics.skip(engine, opened.reason);
      if (opened.reason === 'stage_round_missing') {
        this.logger.warn(
          { ...ids, scanId: stage?.scanId },
          'stage trigger names a round that does not exist with its scan id; skipped',
        );
      } else {
        this.logger.info({ ...ids, reason: opened.reason }, 'scan trigger skipped');
      }
      return opened.reason === 'already_final' ? 'duplicate' : outcome;
    }
    const scan = opened.round;
    if (opened.opened)
      this.logger.info({ ...ids, scanId: scan.scanId.toString() }, 'scan round opened');
    if (opened.finalExists) {
      // A redelivery after this engine finalized: only the completion re-check remains.
      return this.finalize(event, scan, null, ids);
    }

    // 4. Scan, outside any transaction.
    const attempt = opened.attempts + 1;
    let outcome: EngineScanOutcome;
    if (!keyOk) {
      outcome = this.failure('eml_key_mismatch', false);
      this.logger.warn(ids, 'EML key of the event does not match the organization or the row');
    } else if (opened.attempts >= this.options.budget.maxAttempts) {
      outcome = this.failure('max_attempts_exceeded', false);
    } else {
      outcome = await this.scan(message, scan);
    }

    // 5. Record.
    const now = this.now();
    if (outcome.kind === 'failure') metrics.failure(engine, failureMetricReason(outcome));
    // `scan_engine_duration_seconds` is the duration of an engine call: a failure that made none
    // (open breaker, missing EML, refused request, exhausted budget) is counted but not observed,
    // so an outage does not pull the latency quantiles toward zero.
    const calledEngine = outcome.kind === 'definite' || outcome.engineFault !== false;
    if (
      outcome.kind === 'failure' &&
      outcome.retryable &&
      attempt < this.options.budget.maxAttempts &&
      now.getTime() < scan.deadlineAt.getTime()
    ) {
      await store.recordAttempt({
        round: scan,
        engine,
        attempt,
        outcome: outcome.outcome,
        errorCode: outcome.errorCode,
        reasonCode: failureReasonCode(outcome),
        durationMs: outcome.durationMs,
        engineVersion: outcome.engineVersion,
        settingsVersion: null,
        completedAt: now,
      });
      metrics.result(
        engine,
        outcome.outcome,
        false,
        calledEngine ? outcome.durationMs / 1000 : null,
      );
      this.logger.warn(
        { ...ids, attempt, outcome: outcome.outcome, errorCode: outcome.errorCode },
        'scan engine attempt failed; it will be retried',
      );
      throw new EngineAttemptFailedError(engine, attempt, outcome.errorCode);
    }
    const final = this.finalRow(outcome, attempt);
    return this.finalize(event, scan, final, ids, calledEngine);
  }

  /** Step 5 (second branch) and 6: the final row and the completion check, with the ledger row. */
  private async finalize(
    event: ScanTriggerEvent,
    scan: ScanRound,
    final: FinalRowInput | null,
    ids: Record<string, string | number>,
    calledEngine = true,
  ): Promise<HandleOutcome> {
    const { store, metrics } = this.options;
    const now = this.now();
    const result = await store.finalize({
      consumer: this.consumer,
      eventId: event.eventId,
      round: scan,
      final,
      completion: { causationEventId: event.eventId, correlationId: event.correlationId, now },
    });
    if (result.kind === 'duplicate') {
      metrics.skip(this.engine, 'duplicate');
      return 'duplicate';
    }
    for (const triggered of result.stageTriggers) {
      metrics.stageTriggered(triggered);
      this.logger.info(
        { ...ids, scanId: scan.scanId.toString(), stageEngine: triggered },
        'stage-2 engine triggered',
      );
    }
    if (final && result.inserted) {
      metrics.result(
        this.engine,
        final.outcome,
        true,
        calledEngine ? final.durationMs / 1000 : null,
      );
      this.logger.info(
        {
          ...ids,
          scanId: scan.scanId.toString(),
          attempt: final.attempt,
          outcome: final.outcome,
          reasonCodes: final.reasonCodes,
          durationMs: final.durationMs,
          ...(final.errorCode ? { errorCode: final.errorCode } : {}),
        },
        'scan engine result recorded',
      );
    } else if (final) {
      metrics.skip(this.engine, 'already_final');
    }
    reportCompletion(result.completion, metrics, this.logger, [this.engine], ids, now);
    return 'handled';
  }

  private async scan(message: ScanMessageRecord, scan: ScanRound): Promise<EngineScanOutcome> {
    const { registration, adapter, breaker, budget } = this.options;
    const settings = await this.options.settings.resolve(registration, message.organizationId);
    const permit = breaker.tryAcquire();
    if (!permit) return this.failure('circuit_open', true);
    const ctx: EngineScanContext = {
      organizationId: message.organizationId,
      messageId: message.id,
      receivedAt: message.receivedAt,
      round: scan.round,
      scanId: scan.scanId,
      scanKind: scan.scanKind,
      direction: message.direction,
      envelope: {
        clientIp: message.clientIp,
        clientHelo: message.clientHelo,
        clientName: message.clientName,
        envelopeFrom: message.envelopeFrom,
        recipients: message.recipients,
        queueId: message.mtaQueueId,
      },
      eml: {
        key: message.emlObjectKey,
        sizeBytes: message.sizeBytes,
        open: (signal) => this.options.openEml(message.emlObjectKey, signal),
      },
      settings: settings.settings,
      settingsVersion: settings.settingsVersion,
    };
    const started = performance.now();
    let outcome: EngineScanOutcome;
    try {
      outcome = await adapter.scan(ctx, AbortSignal.timeout(budget.timeoutMs));
    } catch (err) {
      // Infrastructure (S3, network): says nothing about the engine.
      permit.release();
      this.logger.warn(
        { messageId: message.id.toString(), ...errorFields(err) },
        'scan attempt failed on infrastructure; it will be retried',
      );
      throw err;
    }
    if (outcome.kind === 'definite') permit.success();
    else if (outcome.engineFault ?? true) permit.failure();
    else permit.release();
    const version =
      outcome.kind === 'definite' ? outcome.result.engineVersion : outcome.engineVersion;
    if (version !== null && version !== 'unknown') {
      const previous = this.options.metrics.engineVersion(this.engine, version);
      if (previous !== null) {
        this.logger.info({ previous, version }, 'scan engine version changed');
      }
    }
    if (outcome.kind === 'failure' && outcome.durationMs === 0) {
      return { ...outcome, durationMs: Math.round(performance.now() - started) };
    }
    return outcome;
  }

  private failure(errorCode: string, retryable: boolean): EngineFailure {
    return {
      kind: 'failure',
      outcome: 'error',
      errorCode,
      retryable,
      engineFault: false,
      durationMs: 0,
      engineVersion: null,
    };
  }

  private finalRow(outcome: EngineScanOutcome, attempt: number): FinalRowInput {
    if (outcome.kind === 'failure') {
      return {
        engine: this.engine,
        attempt,
        outcome: outcome.outcome,
        errorCode: outcome.errorCode,
        engineVersion: outcome.engineVersion,
        score: null,
        requiredScore: null,
        action: null,
        reasonCodes: [failureReasonCode(outcome)],
        evidence: null,
        durationMs: outcome.durationMs,
        settingsVersion: null,
        auth: null,
      };
    }
    const { result } = outcome;
    return {
      engine: this.engine,
      attempt,
      outcome: result.outcome,
      errorCode: null,
      engineVersion: result.engineVersion,
      score: result.score,
      requiredScore: result.requiredScore,
      action: result.action,
      reasonCodes: result.reasonCodes,
      evidence: {
        signals: result.signals,
        ...(result.auth ? { auth: result.auth } : {}),
        ...(outcome.evidence ?? {}),
      },
      durationMs: result.durationMs,
      settingsVersion: result.settingsVersion,
      auth: result.auth ?? null,
      ...(outcome.childRows ? { childRows: outcome.childRows } : {}),
    };
  }
}
