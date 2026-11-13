import {
  type HandleOutcome,
  NonRetryableError,
  uuidv7,
  withTransactionDefaults,
} from '@email-gateway/common';
import { type Prisma, type PrismaClient, processOnce } from '@email-gateway/database';
import type { EventEnvelope } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  ALERT_SCOPE_NONE,
  type AlertKind,
  alertKindSettings,
  buildEnvelope,
  WebhookEnvelopeError,
  WebhookPayloadError,
} from '@email-gateway/webhooks';
import { ZodError } from 'zod';
import type { WebhookMetrics } from '../metrics/webhook-metrics';
import { requestAlert } from '../shared/alerts';
import { WEBHOOK_PAYLOAD_INVALID, WEBHOOK_PAYLOAD_UNSAFE } from '../shared/errors';
import { buildPublicEvents, type FactsSource, type PublicEvent } from './builders';
import type { FanoutReads } from './facts';
import { type Candidate, projectCandidates } from './projection';
import {
  alertEnabled,
  matchingSubscriptions,
  type OrganizationIndex,
  type SubscriptionIndex,
} from './subscription-index';

/** The ledger consumer of the fanout (topology v11 `email.webhooks`). */
export const FANOUT_CONSUMER = 'webhook-worker.fanout';
/** The per-subscription pending count is cached this long (W10 backlog bound). */
export const PENDING_COUNT_TTL_MS = 30_000;

/**
 * Pending deliveries per subscription, counted at most every 30 s (W10): a subscription with more
 * than `WEBHOOK_MAX_PENDING_PER_SUBSCRIPTION` pending deliveries gets new deliveries inserted as
 * `dead` (`backlog_exceeded`). The count is bounded (`LIMIT max + 1`) and uses the
 * `(status, organization_id, next_attempt_at)` index.
 */
export class PendingCounts {
  private readonly cache = new Map<string, { count: number; at: number }>();

  constructor(
    private readonly max: number,
    private readonly now: () => number = Date.now,
  ) {}

  async exceeded(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    subscriptionId: bigint,
  ): Promise<boolean> {
    const key = subscriptionId.toString();
    const cached = this.cache.get(key);
    if (cached === undefined || this.now() - cached.at >= PENDING_COUNT_TTL_MS) {
      const [row] = await tx.$queryRaw<Array<{ n: bigint | number }>>`
        SELECT COUNT(*) AS n FROM (
          SELECT 1 FROM webhook_deliveries
          WHERE status = 'pending' AND organization_id = ${organizationId}
            AND subscription_id = ${subscriptionId}
          LIMIT ${this.max + 1}
        ) AS bounded`;
      this.cache.set(key, { count: Number(row?.n ?? 0), at: this.now() });
    }
    return (this.cache.get(key)?.count ?? 0) > this.max;
  }

  /** Counts a pending delivery just inserted (keeps the cached value roughly current). */
  added(subscriptionId: bigint): void {
    const cached = this.cache.get(subscriptionId.toString());
    if (cached !== undefined) cached.count += 1;
  }

  clear(): void {
    this.cache.clear();
  }
}

export interface FanoutOptions {
  /** The writer client (transaction defaults are applied here). */
  prisma: PrismaClient;
  index: SubscriptionIndex;
  reads: FanoutReads;
  pending: PendingCounts;
  metrics: WebhookMetrics;
  logger: Logger;
  /** WEBHOOK_FANOUT_TX_TIMEOUT_MS. */
  txTimeoutMs: number;
  /** Ledger consumer name (default `webhook-worker.fanout`; integration tests use their own). */
  consumer?: string;
  now?: () => Date;
}

interface ProjectionReport {
  events: Array<{ type: string; inserted: boolean }>;
  deliveries: Array<{ type: string; dead: boolean }>;
  alerts: Array<{ kind: AlertKind; result: 'requested' | 'throttled' | 'disabled' }>;
}

/** Binds `FanoutReads` to one transaction (the `FactsSource` of the builders). */
function factsIn(tx: Prisma.TransactionClient, reads: FanoutReads): FactsSource {
  return {
    message: (key) => reads.message(tx, key),
    scanReasonCodes: (key, scanId) => reads.scanReasonCodes(tx, key, scanId),
    executionLog: (key, round) => reads.executionLog(tx, key, round),
    quarantineEntries: (key, round, origin) => reads.quarantineEntries(tx, key, round, origin),
    release: (key, seq) => reads.release(tx, key, seq),
    recipientOutcomes: (key) => reads.recipientOutcomes(tx, key),
    sandboxSubmission: (key, id) => reads.sandboxSubmission(tx, key, id),
    domain: (org, id, publicId) => reads.domain(tx, org, id, publicId),
  };
}

/**
 * The fanout (step 6.2 W1, W3, W5, N2). For each internal event: the projection candidates from
 * the payload, the cheap pre-filter against the cached subscription index and the tenant alert
 * settings; nothing wanted → acknowledged **without a transaction and without a ledger row**
 * (a pure function of cached state: a redelivery repeats the same no-op). Otherwise, in one
 * writer transaction under the ledger (`processOnce`, budget `WEBHOOK_FANOUT_TX_TIMEOUT_MS`):
 * the echo-checked reads, the envelopes (payload guard), `webhook_events` and
 * `webhook_deliveries` (insert-ignore on their unique keys), the alert windows and the
 * `notification.alert_requested.v1` outbox rows. Only subscriptions of the envelope's
 * organization are ever matched (§2.0 invariant 2).
 */
export class FanoutService {
  private readonly tx: PrismaClient;
  private readonly consumer: string;
  private readonly now: () => Date;

  constructor(private readonly options: FanoutOptions) {
    this.tx = withTransactionDefaults(options.prisma, { timeoutMs: options.txTimeoutMs });
    this.consumer = options.consumer ?? FANOUT_CONSUMER;
    this.now = options.now ?? (() => new Date());
  }

  /** The `EventHandler` of the `email.webhooks` consumer. */
  readonly handle = async (event: EventEnvelope<unknown>): Promise<HandleOutcome> => {
    const sourceType = event.eventType;
    const count = (result: string): void =>
      this.options.metrics.fanoutEvents.inc({ source_type: sourceType, result });
    try {
      const candidates = projectCandidates(event);
      if (candidates.length === 0) {
        count('noop');
        return 'handled';
      }
      const index = await this.options.index.get(BigInt(event.organizationId));
      const occurredAt = new Date(event.occurredAt);
      const wanted = index === null ? [] : this.prefilter(candidates, index, occurredAt);
      if (index === null || wanted.length === 0) {
        count('noop');
        return 'handled';
      }
      const outcome = await processOnce(this.tx, this.consumer, event.eventId, (tx) =>
        this.project(tx, event, wanted, index, occurredAt),
      );
      if (outcome.status === 'duplicate') {
        count('duplicate');
        return 'duplicate';
      }
      this.record(outcome.result);
      count('projected');
      return 'handled';
    } catch (error) {
      if (error instanceof WebhookPayloadError) {
        count('unsafe');
        this.options.logger.error(
          { eventId: event.eventId, eventType: sourceType, code: error.code, path: error.path },
          'webhook payload refused by the payload guard; source event dead-lettered',
        );
        throw new NonRetryableError(WEBHOOK_PAYLOAD_UNSAFE);
      }
      if (error instanceof WebhookEnvelopeError || error instanceof ZodError) {
        count('invalid');
        this.options.logger.error(
          { eventId: event.eventId, eventType: sourceType, errName: (error as Error).name },
          'webhook payload failed its strict schema; source event dead-lettered',
        );
        throw new NonRetryableError(WEBHOOK_PAYLOAD_INVALID);
      }
      count('error');
      throw error;
    }
  };

  /** Candidates that may match a subscription (domain unknown → passes) or request an alert. */
  prefilter(
    candidates: readonly Candidate[],
    index: OrganizationIndex,
    occurredAt: Date,
  ): Candidate[] {
    return candidates.filter((c) => {
      const matchable = {
        type: c.type,
        severity: c.severity,
        ...(c.direction !== undefined ? { direction: c.direction } : {}),
        ...(c.verdict !== undefined ? { verdict: c.verdict } : {}),
      };
      if (matchingSubscriptions(index, matchable, occurredAt).length > 0) return true;
      return c.alert !== null && alertEnabled(index.settings, c.alert, c.severity);
    });
  }

  private async project(
    tx: Prisma.TransactionClient,
    event: EventEnvelope<unknown>,
    wanted: readonly Candidate[],
    index: OrganizationIndex,
    occurredAt: Date,
  ): Promise<ProjectionReport> {
    const report: ProjectionReport = { events: [], deliveries: [], alerts: [] };
    const organizationId = index.organizationId;
    const publicEvents = await buildPublicEvents(event, wanted, factsIn(tx, this.options.reads));
    for (const pe of publicEvents) {
      const subscriptions = matchingSubscriptions(index, pe.matchable, occurredAt);
      const alert =
        pe.candidate.alert !== null && alertEnabled(index.settings, pe.candidate.alert, pe.severity)
          ? pe.candidate.alert
          : null;
      if (pe.candidate.alert !== null && alert === null) {
        report.alerts.push({ kind: pe.candidate.alert, result: 'disabled' });
      }
      if (subscriptions.length === 0 && alert === null) continue;
      const built = buildEnvelope({
        type: pe.type,
        occurredAt,
        organizationPublicId: index.publicId,
        sourceEventId: event.eventId,
        subKey: pe.subKey,
        data: pe.data as never,
      });
      const inserted = await tx.$executeRaw`
        INSERT INTO webhook_events
          (occurred_at, organization_id, event_id, event_type, source_event_id, source_event_type,
           message_id, message_received_at, domain_id, severity, payload_json, payload_sha256,
           created_at)
        VALUES (${occurredAt}, ${organizationId}, ${built.envelope.id}, ${pe.type},
                ${event.eventId}, ${event.eventType}, ${pe.message?.messageId ?? null},
                ${pe.message?.receivedAt ?? null}, ${pe.domainId}, ${pe.severity}, ${built.json},
                ${built.sha256}, NOW(3))
        ON DUPLICATE KEY UPDATE id = id`;
      report.events.push({ type: pe.type, inserted: inserted === 1 });
      for (const subscription of subscriptions) {
        const dead = await this.options.pending.exceeded(tx, organizationId, subscription.id);
        const created = await tx.$executeRaw`
          INSERT INTO webhook_deliveries
            (event_occurred_at, public_id, subscription_id, organization_id, event_id, event_type,
             delivery_seq, \`trigger\`, status, attempt_count, next_attempt_at, last_error,
             completed_at, created_at, updated_at)
          VALUES (${occurredAt}, ${uuidv7()}, ${subscription.id}, ${organizationId},
                  ${built.envelope.id}, ${pe.type}, 0, 'event', ${dead ? 'dead' : 'pending'}, 0,
                  ${dead ? null : this.now()}, ${dead ? 'backlog_exceeded' : null},
                  ${dead ? this.now() : null}, NOW(3), NOW(3))
          ON DUPLICATE KEY UPDATE id = id`;
        if (created === 1) {
          report.deliveries.push({ type: pe.type, dead });
          if (!dead) this.options.pending.added(subscription.id);
        }
      }
      if (alert !== null) {
        report.alerts.push({
          kind: alert,
          result: (await this.alert(tx, event, pe, alert, built.envelope.id, index, occurredAt))
            .result,
        });
      }
    }
    return report;
  }

  private alert(
    tx: Prisma.TransactionClient,
    event: EventEnvelope<unknown>,
    pe: PublicEvent,
    kind: AlertKind,
    webhookEventId: string,
    index: OrganizationIndex,
    occurredAt: Date,
  ) {
    const refs =
      kind === 'threat_detected'
        ? {
            webhookEventId,
            messageId: pe.message!.messageId.toString(),
            receivedAt: pe.message!.receivedAt.toISOString(),
          }
        : { webhookEventId, domainId: (pe.domainId ?? 0n).toString() };
    return requestAlert(tx, {
      organizationId: index.organizationId,
      kind,
      severity: pe.severity,
      scopeKey:
        kind === 'threat_detected' ? ALERT_SCOPE_NONE : (pe.domainPublicId ?? ALERT_SCOPE_NONE),
      occurredAt,
      throttleMinutes: alertKindSettings(index.settings, kind).throttleMinutes,
      sourceEventId: event.eventId,
      correlationId: event.correlationId,
      refs,
      now: this.now(),
    });
  }

  /** Metrics of a committed projection (never inside the transaction). */
  private record(report: ProjectionReport): void {
    const m = this.options.metrics;
    for (const e of report.events) if (e.inserted) m.eventsCreated.inc({ type: e.type });
    for (const d of report.deliveries) {
      m.deliveriesCreated.inc({ type: d.type, trigger: 'event' });
      if (d.dead) m.dead.inc();
    }
    for (const a of report.alerts) m.alertRequests.inc({ kind: a.kind, result: a.result });
  }
}
