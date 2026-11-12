import {
  type AmqpConnection,
  type ConfirmPublisher,
  type ConsumerProgressRecorder,
  type EventFeed,
  type EventHandler,
  type MessagingMetrics,
  processOnceHandler,
  QueueConsumer,
} from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import { EventTypes, type RetryPolicy } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { PolicyMetrics } from '../metrics/policy-metrics';
import type { QuarantineMetrics } from '../metrics/quarantine-metrics';
import {
  type EvaluationOutcome,
  POLICY_EVALUATE_CONSUMER,
  type PolicyEvaluationService,
  splitMetricLabel,
  type TriggerPayload,
} from './evaluation.service';

/** The queue the engine consumes (topology v9, work policy, P13). */
export const POLICY_EVALUATE_QUEUE = 'email.policy.evaluate';
/** The trigger events (bindings of `email.policy.evaluate`). */
export const POLICY_EVENT_TYPES = [EventTypes.MessageScanned, EventTypes.MessageParseFailed];

/**
 * The `QueueConsumer` of `email.policy.evaluate` (P13): `mail.message.scanned.v1` and
 * `mail.message.parse_failed.v1`, prefetch `POLICY_EVALUATE_PREFETCH`, the topology's retry
 * policy (`hold`, 10 attempts, 2 s – 1 min, 24 h), default classification (database/network
 * outages transient, `NonRetryableError` fatal → dead letter, anything else — an echo-check
 * mismatch, a unique-key conflict — retryable), `PrismaConsumerProgress` for the reconciler.
 */
export function createPolicyEvaluateFeed(options: {
  connection: AmqpConnection;
  publisher: ConfirmPublisher;
  prefetch: number;
  logger: Logger;
  metrics?: MessagingMetrics;
  consumer?: string;
  retry?: Partial<RetryPolicy>;
  progress?: ConsumerProgressRecorder;
}): QueueConsumer<TriggerPayload> {
  return new QueueConsumer<TriggerPayload>({
    connection: options.connection,
    publisher: options.publisher,
    queue: POLICY_EVALUATE_QUEUE,
    consumer: options.consumer ?? POLICY_EVALUATE_CONSUMER,
    eventTypes: POLICY_EVENT_TYPES,
    prefetch: options.prefetch,
    logger: options.logger,
    ...(options.metrics ? { metrics: options.metrics } : {}),
    ...(options.retry ? { retry: options.retry } : {}),
    ...(options.progress ? { progress: options.progress } : {}),
  });
}

/** Counts a committed outcome (never inside the transaction: a rollback would over-count). */
export function recordOutcome(
  metrics: PolicyMetrics,
  outcome: EvaluationOutcome,
  quarantine?: QuarantineMetrics,
): void {
  if (outcome.status === 'skipped') {
    metrics.lifecycleSkipped.inc({ result: outcome.result });
    return;
  }
  const r = outcome.result;
  metrics.evaluations.inc({
    trigger: r.round.trigger,
    disposition: r.disposition,
    source: r.decisive.source,
    direction: r.round.direction,
  });
  metrics.duration.observe(outcome.durationSeconds);
  for (const reason of r.floor.reasons) {
    metrics.floorRaises.inc({ reason: reason.replace(/^policy\.floor\./, '') });
  }
  if (r.override !== null) metrics.overrides.inc({ result: 'applied' });
  if (r.clamps.length > 0) metrics.overrides.inc({ result: 'clamped' });
  r.actions.forEach((a, i) => metrics.actions.inc({ type: a.type, status: outcome.statuses[i]! }));
  metrics.snapshotCache.inc({ result: outcome.cache });
  if (outcome.invalidVersions > 0) metrics.snapshotInvalidVersions.inc(outcome.invalidVersions);
  if (outcome.copy !== null) metrics.copies.inc({ result: outcome.copy });
  if (outcome.riskMissing) metrics.riskMissing.inc();
  metrics.recipientSplit.inc({ result: splitMetricLabel(outcome.split) });
  if (outcome.urlRewrite !== null) metrics.urlRewrites.inc({ result: outcome.urlRewrite });
  if (outcome.banner !== null) metrics.bodyBanners.inc({ result: outcome.banner });
  if (quarantine === undefined) return;
  for (const e of outcome.entries) {
    quarantine.entriesCreated.inc({
      origin: 'policy',
      kind: e.kind,
      reason: e.reason,
      direction: e.direction,
    });
  }
  if (outcome.superseded > 0) quarantine.superseded.inc(outcome.superseded);
  if (outcome.notifications > 0) {
    quarantine.notifications.inc({ kind: 'approval_requested' }, outcome.notifications);
  }
}

/**
 * Consumer `policy-engine.evaluate`: every event runs `PolicyEvaluationService.evaluate` inside
 * the consumer's idempotency transaction (`processOnceHandler` on the writer, budget
 * `POLICY_DB_TX_TIMEOUT_MS`); a duplicate delivery is absorbed by the ledger. Metrics of an
 * evaluation are recorded only after its transaction committed (outcomes are kept per event id,
 * the consumer runs up to `prefetch` events at once).
 */
export class PolicyEvaluateConsumer {
  private readonly pending = new Map<string, EvaluationOutcome>();
  readonly handler: EventHandler<TriggerPayload>;

  constructor(
    private readonly feed: EventFeed<TriggerPayload>,
    service: PolicyEvaluationService,
    prisma: PrismaClient,
    private readonly metrics: PolicyMetrics,
    txTimeoutMs: number,
    consumer: string = POLICY_EVALUATE_CONSUMER,
    private readonly quarantine?: QuarantineMetrics,
  ) {
    const inner = processOnceHandler<TriggerPayload>(
      prisma,
      consumer,
      async (event, tx) => {
        this.pending.set(event.eventId, await service.evaluate(event, tx));
      },
      { txTimeoutMs },
    );
    this.handler = async (event) => {
      this.pending.delete(event.eventId);
      try {
        const handled = await inner(event);
        const outcome = this.pending.get(event.eventId);
        if (handled === 'handled' && outcome !== undefined) {
          recordOutcome(this.metrics, outcome, this.quarantine);
        }
        return handled;
      } finally {
        this.pending.delete(event.eventId);
      }
    };
  }

  start(): void {
    this.feed.start(this.handler);
  }

  stop(): Promise<void> {
    return this.feed.stop();
  }
}
