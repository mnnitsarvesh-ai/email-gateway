import { backoffDelay, sleep as defaultSleep } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { GuardedPoster, PostResult } from '@email-gateway/url-security';
import { signatureHeader, WEBHOOK_SIGNATURE_HEADER } from '@email-gateway/webhooks';
import type { WebhookMetrics } from '../metrics/webhook-metrics';
import { idOf, type InconsistencySink, wrongRead } from '../shared/errors';
import { type ClaimedDelivery, type DeliveryClaimer, shuffle } from './claimer';
import type { InflightCounters } from './inflight';
import type { AttemptResult, DeliveryRecorder } from './recorder';
import { type SecretProvider, SecretUnavailableError } from './secrets';

export interface DeliveryLoopOptions {
  prisma: PrismaClient;
  claimer: DeliveryClaimer;
  recorder: DeliveryRecorder;
  counters: InflightCounters;
  poster: Pick<GuardedPoster, 'post'>;
  secrets: SecretProvider;
  metrics: WebhookMetrics;
  sink: InconsistencySink;
  logger: Logger;
  /** WEBHOOK_DELIVERY_POLL_INTERVAL_MS. */
  pollIntervalMs: number;
  /** WEBHOOK_DELIVERY_CONCURRENCY: attempts in flight in this process. */
  concurrency: number;
  /** WEBHOOK_MAX_INFLIGHT_PER_ORG. */
  maxPerOrganization: number;
  now?: () => Date;
  random?: () => number;
  sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
}

export interface TickReport {
  outcome: 'idle' | 'claimed' | 'store_unavailable' | 'database_error' | 'saturated';
  organizations: number;
  claimed: number;
}

/**
 * The delivery loop (step 6.2 W8). Every WEBHOOK_DELIVERY_POLL_INTERVAL_MS while this process
 * has free slots (WEBHOOK_DELIVERY_CONCURRENCY):
 *
 * 1. the organizations with due work, shuffled (fairness);
 * 2. per organization, free organization slots = WEBHOOK_MAX_INFLIGHT_PER_ORG − the Redis
 *    counter; one short claim transaction (`DeliveryClaimer`) bounded by those slots;
 * 3. each claimed delivery is **sent outside any transaction** (in the background: a slow
 *    endpoint holds only its own slots, other organizations are claimed in the same tick):
 *    the stored envelope (byte-identical on every attempt and replay), the secrets (current and
 *    unexpired previous), `EG-Signature` and the §4.2 headers, one guarded POST;
 * 4. the attempt is recorded with a CAS (`DeliveryRecorder`) and the Redis slots are released.
 *
 * Redis unavailable → the tick sends nothing (fail closed, `webhook_rate_limit_store_errors_total`).
 */
export class DeliveryLoop {
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private readonly inFlight = new Set<Promise<void>>();
  private abort = new AbortController();
  private loop: Promise<void> | undefined;
  private failures = 0;

  constructor(private readonly options: DeliveryLoopOptions) {
    this.logger = options.logger.child({ component: 'webhook-delivery' });
    this.now = options.now ?? (() => new Date());
    this.sleepFn = options.sleep ?? defaultSleep;
  }

  get running(): boolean {
    return this.loop !== undefined;
  }

  /** Attempts currently in flight in this process. */
  get active(): number {
    return this.inFlight.size;
  }

  start(): void {
    if (this.loop) return;
    this.abort = new AbortController();
    this.loop = this.run(this.abort.signal);
    this.logger.info(
      { pollIntervalMs: this.options.pollIntervalMs, concurrency: this.options.concurrency },
      'webhook delivery loop started',
    );
  }

  /** Stops claiming and waits for the attempts in flight (their results are recorded). */
  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop;
    this.loop = undefined;
    await this.drain();
  }

  /** Waits until every attempt dispatched so far is recorded (tests, shutdown). */
  async drain(): Promise<void> {
    while (this.inFlight.size > 0) await Promise.allSettled([...this.inFlight]);
  }

  async tick(): Promise<TickReport> {
    const free = this.options.concurrency - this.inFlight.size;
    if (free <= 0) return { outcome: 'saturated', organizations: 0, claimed: 0 };
    const m = this.options.metrics;
    try {
      await this.options.counters.ping();
    } catch {
      m.rateLimitStoreErrors.inc();
      return { outcome: 'store_unavailable', organizations: 0, claimed: 0 };
    }
    const now = this.now();
    let organizations: bigint[];
    try {
      organizations = shuffle(
        await this.options.claimer.dueOrganizations(now),
        this.options.random,
      );
    } catch (error) {
      this.logger.warn({ errName: (error as Error).name }, 'due organizations query failed');
      return { outcome: 'database_error', organizations: 0, claimed: 0 };
    }
    let slots = free;
    let claimed = 0;
    for (const organizationId of organizations) {
      if (slots <= 0 || this.abort.signal.aborted) break;
      let inflight: number;
      try {
        inflight = await this.options.counters.organization(organizationId);
      } catch {
        m.rateLimitStoreErrors.inc();
        return { outcome: 'store_unavailable', organizations: organizations.length, claimed };
      }
      const take = Math.min(slots, this.options.maxPerOrganization - inflight);
      if (take <= 0) {
        m.rateLimited.inc({ scope: 'organization' });
        continue;
      }
      try {
        const report = await this.options.claimer.claim(organizationId, take, now);
        for (const c of report.cancelled) m.cancelled.inc({ reason: c.reason });
        for (const scope of report.limited) m.rateLimited.inc({ scope });
        for (const delivery of report.claimed) this.dispatch(delivery);
        slots -= report.claimed.length;
        claimed += report.claimed.length;
      } catch (error) {
        // One organization's claim failing (lock wait, Redis error) never stops the others.
        if (isRedisError(error)) m.rateLimitStoreErrors.inc();
        this.logger.warn(
          { errName: (error as Error).name, errCode: (error as { code?: string }).code },
          'webhook claim failed; retried next tick',
        );
      }
    }
    return {
      outcome: claimed > 0 ? 'claimed' : 'idle',
      organizations: organizations.length,
      claimed,
    };
  }

  private dispatch(delivery: ClaimedDelivery): void {
    const task = this.attempt(delivery).finally(() => {
      this.inFlight.delete(task);
    });
    this.inFlight.add(task);
  }

  /** One attempt: never throws (a failure to record leaves the lease to expire). */
  private async attempt(delivery: ClaimedDelivery): Promise<void> {
    const m = this.options.metrics;
    try {
      const event = await this.loadEvent(delivery);
      if (event === null) {
        await this.options.recorder.expire(delivery, this.now());
        return;
      }
      const attemptedAt = this.now();
      const result = await this.send(delivery, event, attemptedAt);
      m.attempts.inc({ outcome: result.outcome });
      m.attemptDuration.observe({ outcome: result.outcome }, result.latencyMs / 1000);
      if (result.outcome === 'blocked' && result.errorCode?.startsWith('blocked:')) {
        m.ssrfBlocked.inc({ reason: result.errorCode.slice('blocked:'.length) });
      }
      const report = await this.options.recorder.record(delivery, result, this.now());
      if (report.state === 'dead') m.dead.inc();
      if (report.disabled) m.subscriptionsDisabled.inc({ reason: 'sustained_failure' });
      if (report.alert !== null) {
        m.alertRequests.inc({ kind: 'webhook_disabled', result: report.alert });
      }
    } catch (error) {
      this.logger.warn(
        {
          deliveryId: delivery.publicId,
          errName: (error as Error).name,
          errCode: (error as { code?: string }).code,
        },
        'webhook attempt could not be recorded; the lease expires and the delivery is retried',
      );
    } finally {
      await this.options.counters.release(delivery.reservation).catch(() => undefined);
    }
  }

  /** The stored envelope (byte-identical on every attempt), echo-checked; null when expired. */
  private async loadEvent(
    delivery: ClaimedDelivery,
  ): Promise<{ json: string; type: string } | null> {
    const rows = await this.options.prisma.$queryRaw<
      Array<{ organization_id: bigint; event_id: string; event_type: string; payload_json: string }>
    >`
      SELECT organization_id, event_id, event_type, payload_json FROM webhook_events
      WHERE event_id = ${delivery.eventId} AND occurred_at = ${delivery.eventOccurredAt}`;
    const row = rows[0];
    if (row === undefined) return null;
    if (
      idOf(row.organization_id) !== delivery.organizationId ||
      row.event_id !== delivery.eventId
    ) {
      wrongRead(this.options.sink, 'event', 'organization or event id');
    }
    return { json: row.payload_json, type: row.event_type };
  }

  private async send(
    delivery: ClaimedDelivery,
    event: { json: string; type: string },
    attemptedAt: Date,
  ): Promise<AttemptResult> {
    let secrets: string[];
    try {
      secrets = this.options.secrets.secrets(delivery.subscription);
    } catch (error) {
      if (!(error instanceof SecretUnavailableError)) throw error;
      return {
        outcome: 'secret_unavailable',
        httpStatus: null,
        latencyMs: 0,
        retryAfter: null,
        snippetBytes: null,
        errorCode: 'secret_unavailable',
        signatureCount: 0,
        attemptedAt,
      };
    }
    const timestamp = Math.floor(attemptedAt.getTime() / 1000);
    const headers: Record<string, string> = {
      [WEBHOOK_SIGNATURE_HEADER]: signatureHeader(secrets, timestamp, event.json),
      'EG-Event-Id': delivery.eventId,
      'EG-Event-Type': event.type,
      'EG-Delivery-Id': delivery.publicId,
      'EG-Delivery-Attempt': String(delivery.attemptNo),
      'EG-Subscription-Id': delivery.subscription.publicId,
      'Idempotency-Key': delivery.eventId,
    };
    const result: PostResult = await this.options.poster.post({
      url: delivery.subscription.url,
      headers,
      // No stop signal: an attempt in flight at shutdown completes (bounded by the total
      // timeout) and is recorded, so it never counts as an expired lease.
      body: event.json,
    });
    return {
      outcome: result.outcome,
      httpStatus: result.httpStatus,
      latencyMs: result.latencyMs,
      retryAfter: result.retryAfter,
      snippetBytes: result.snippetBytes,
      errorCode: result.errorCode,
      signatureCount: secrets.length,
      attemptedAt,
    };
  }

  private async run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      let delay = this.options.pollIntervalMs;
      try {
        const report = await this.tick();
        if (report.outcome === 'database_error' || report.outcome === 'store_unavailable') {
          this.failures += 1;
          delay = Math.max(delay, backoffDelay(this.failures, { baseMs: 500, maxMs: 30_000 }));
        } else {
          this.failures = 0;
        }
      } catch (error) {
        this.failures += 1;
        delay = Math.max(delay, backoffDelay(this.failures, { baseMs: 500, maxMs: 30_000 }));
        this.logger.warn({ errName: (error as Error).name }, 'webhook delivery tick failed');
      }
      if (!(await this.sleepFn(delay, signal))) break;
    }
  }
}

function isRedisError(error: unknown): boolean {
  const name = (error as { name?: unknown } | null)?.name;
  return (
    typeof name === 'string' &&
    (name === 'ReplyError' || name.startsWith('Redis') || name === 'MaxRetriesPerRequestError')
  );
}
