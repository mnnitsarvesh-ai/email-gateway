import { withTransactionDefaults } from '@email-gateway/common';
import type { Prisma, PrismaClient } from '@email-gateway/database';
import {
  alertKindSettings,
  nextAttempt,
  parseRetryAfter,
  resolveNotificationSettings,
  responseSnippet,
  type WebhookRetryConfig,
} from '@email-gateway/webhooks';
import { requestAlert } from '../shared/alerts';
import { type InconsistencySink, wrongRead } from '../shared/errors';
import { alertEnabled } from '../fanout/subscription-index';
import type { ClaimedDelivery } from './claimer';

/** Outcomes of an attempt row (`webhook_delivery_attempts.outcome`). */
export type AttemptOutcome =
  | 'succeeded'
  | 'http_error'
  | 'redirect'
  | 'timeout'
  | 'dns_error'
  | 'connection_error'
  | 'tls_error'
  | 'blocked'
  | 'too_large'
  | 'secret_unavailable';

export interface AttemptResult {
  outcome: AttemptOutcome;
  httpStatus: number | null;
  latencyMs: number;
  /** Raw `Retry-After` (honored on any non-2xx, W10). */
  retryAfter: string | null;
  snippetBytes: Buffer | null;
  /** Bounded code (`http_503`, `ECONNREFUSED`, `blocked:loopback`, `secret_unavailable`). */
  errorCode: string | null;
  /** `v1=` signatures sent (0 when nothing was sent). */
  signatureCount: number;
  attemptedAt: Date;
}

export type RecordedState = 'succeeded' | 'retry' | 'failed' | 'dead' | 'lost';

export interface RecordReport {
  state: RecordedState;
  nextAttemptAt: Date | null;
  disabled: boolean;
  alert: 'requested' | 'throttled' | 'disabled' | null;
}

export interface AutoDisableConfig {
  /** WEBHOOK_DISABLE_AFTER_FAILURES. */
  failures: number;
  /** WEBHOOK_DISABLE_AFTER_HOURS. */
  hours: number;
}

/** The audit action of the automatic disable (W11). */
export const AUTO_DISABLE_ACTION = 'webhook.auto_disabled';
/** `audit_logs.resource_type` of webhook subscriptions. */
export const WEBHOOK_RESOURCE_TYPE = 'webhook';
export const SUSTAINED_FAILURE = 'sustained_failure';

const MAX_RETRY_AFTER_SECONDS = 4_294_967_295;
const ERROR_CODE_MAX = 64;

/**
 * Records one attempt (step 6.2 W8 step 4, W10, W11) in one writer transaction with a CAS on the
 * claimed lease (`id`, `event_occurred_at`, `status = pending`, `attempt_count = <claimed>`): a
 * lost CAS (the row changed: cancelled, or a later claim after an expired lease) writes nothing
 * and is counted. Otherwise: the `webhook_delivery_attempts` row (snippet sanitized, never
 * headers), the delivery's new state (succeeded; retry at `nextAttempt` honoring `Retry-After`;
 * `failed` with `blocked:<reason>`; `dead` after max attempts / max age), the subscription's
 * failure counters and, past both thresholds, the automatic disable with its audit row and the
 * `webhook_disabled` alert request (through its throttle window).
 */
export class DeliveryRecorder {
  private readonly tx: PrismaClient;

  constructor(
    prisma: PrismaClient,
    private readonly options: {
      retry: WebhookRetryConfig;
      autoDisable: AutoDisableConfig;
      sink: InconsistencySink;
      random?: () => number;
      txTimeoutMs?: number;
    },
  ) {
    this.tx = withTransactionDefaults(prisma, { timeoutMs: options.txTimeoutMs ?? 30_000 });
  }

  /** The next state of a delivery after `attempt` (pure; unit-tested). */
  nextState(
    claimed: Pick<ClaimedDelivery, 'attemptNo' | 'firstAttemptAt'>,
    attempt: AttemptResult,
    now: Date,
  ): {
    status: 'succeeded' | 'pending' | 'failed' | 'dead';
    nextAttemptAt: Date | null;
    lastError: string | null;
    retryAfterSeconds: number | null;
  } {
    if (attempt.outcome === 'succeeded') {
      return { status: 'succeeded', nextAttemptAt: null, lastError: null, retryAfterSeconds: null };
    }
    const code = (attempt.errorCode ?? attempt.outcome).slice(0, ERROR_CODE_MAX);
    if (attempt.outcome === 'blocked') {
      return { status: 'failed', nextAttemptAt: null, lastError: code, retryAfterSeconds: null };
    }
    const retryAfterMs =
      attempt.httpStatus !== null ? parseRetryAfter(attempt.retryAfter, now) : null;
    const retryAfterSeconds =
      retryAfterMs === null
        ? null
        : Math.min(Math.ceil(retryAfterMs / 1000), MAX_RETRY_AFTER_SECONDS);
    const next = nextAttempt({
      attemptNo: claimed.attemptNo,
      firstAttemptAt: claimed.firstAttemptAt,
      now,
      retryAfterMs,
      cfg: this.options.retry,
      ...(this.options.random ? { random: this.options.random } : {}),
    });
    if (next.kind === 'dead') {
      return { status: 'dead', nextAttemptAt: null, lastError: code, retryAfterSeconds };
    }
    return { status: 'pending', nextAttemptAt: next.at, lastError: code, retryAfterSeconds };
  }

  async record(claimed: ClaimedDelivery, attempt: AttemptResult, now: Date): Promise<RecordReport> {
    const next = this.nextState(claimed, attempt, now);
    const terminal = next.status !== 'pending';
    return this.tx.$transaction(async (tx) => {
      const updated = await tx.$executeRaw`
        UPDATE webhook_deliveries
        SET status = ${next.status}, next_attempt_at = ${next.nextAttemptAt},
            last_response_code = ${attempt.httpStatus}, last_latency_ms = ${Math.max(0, Math.round(attempt.latencyMs))},
            last_error = ${next.lastError}, completed_at = ${terminal ? now : null}
        WHERE id = ${claimed.id} AND event_occurred_at = ${claimed.eventOccurredAt}
          AND status = 'pending' AND attempt_count = ${claimed.attemptNo}
          AND organization_id = ${claimed.organizationId}`;
      if (updated !== 1) {
        this.options.sink('delivery_cas');
        return { state: 'lost', nextAttemptAt: null, disabled: false, alert: null };
      }
      await tx.webhookDeliveryAttempt.create({
        data: {
          attemptedAt: attempt.attemptedAt,
          organizationId: claimed.organizationId,
          subscriptionId: claimed.subscriptionId,
          deliveryId: claimed.id,
          deliveryEventOccurredAt: claimed.eventOccurredAt,
          attemptNo: claimed.attemptNo,
          outcome: attempt.outcome,
          httpStatus: attempt.httpStatus,
          latencyMs: Math.max(0, Math.round(attempt.latencyMs)),
          responseSnippet: responseSnippet(attempt.snippetBytes),
          retryAfterSeconds: next.retryAfterSeconds,
          errorCode: attempt.outcome === 'succeeded' ? null : next.lastError,
          signatureCount: attempt.signatureCount,
          nextAttemptAt: next.nextAttemptAt,
        },
        select: { id: true },
      });
      const state: RecordedState =
        next.status === 'succeeded'
          ? 'succeeded'
          : next.status === 'pending'
            ? 'retry'
            : next.status;
      if (attempt.outcome === 'succeeded') {
        await tx.$executeRaw`
          UPDATE webhook_subscriptions
          SET consecutive_failures = 0, failing_since = NULL, last_success_at = ${now}
          WHERE id = ${claimed.subscriptionId} AND organization_id = ${claimed.organizationId}`;
        return { state, nextAttemptAt: null, disabled: false, alert: null };
      }
      // `secret_unavailable` is our failure, not the endpoint's: never counted toward auto-disable.
      if (attempt.outcome === 'secret_unavailable') {
        return { state, nextAttemptAt: next.nextAttemptAt, disabled: false, alert: null };
      }
      const disable = await this.countFailure(tx, claimed, now);
      return { state, nextAttemptAt: next.nextAttemptAt, ...disable };
    });
  }

  /** A delivery whose stored event is gone (partition dropped): `failed`, no attempt row. */
  async expire(claimed: ClaimedDelivery, now: Date): Promise<boolean> {
    const updated = await this.tx.$executeRaw`
      UPDATE webhook_deliveries
      SET status = 'failed', next_attempt_at = NULL, completed_at = ${now},
          last_error = 'event_expired'
      WHERE id = ${claimed.id} AND event_occurred_at = ${claimed.eventOccurredAt}
        AND status = 'pending' AND attempt_count = ${claimed.attemptNo}`;
    return updated === 1;
  }

  private async countFailure(
    tx: Prisma.TransactionClient,
    claimed: ClaimedDelivery,
    now: Date,
  ): Promise<{ disabled: boolean; alert: RecordReport['alert'] }> {
    await tx.$executeRaw`
      UPDATE webhook_subscriptions
      SET consecutive_failures = consecutive_failures + 1,
          failing_since = COALESCE(failing_since, ${now}), last_failure_at = ${now}
      WHERE id = ${claimed.subscriptionId} AND organization_id = ${claimed.organizationId}`;
    const [sub] = await tx.$queryRaw<
      Array<{
        id: bigint;
        organization_id: bigint;
        public_id: string;
        status: string;
        consecutive_failures: number | bigint;
        failing_since: Date | null;
      }>
    >`
      SELECT id, organization_id, public_id, status, consecutive_failures, failing_since
      FROM webhook_subscriptions
      WHERE id = ${claimed.subscriptionId} AND organization_id = ${claimed.organizationId}
      FOR UPDATE`;
    if (sub === undefined) return { disabled: false, alert: null };
    if (
      BigInt(sub.id) !== claimed.subscriptionId ||
      BigInt(sub.organization_id) !== claimed.organizationId
    ) {
      wrongRead(this.options.sink, 'subscriptions', 'id or organization');
    }
    const failures = Number(sub.consecutive_failures);
    const since = sub.failing_since;
    const { failures: threshold, hours } = this.options.autoDisable;
    if (
      sub.status !== 'active' ||
      failures < threshold ||
      since === null ||
      now.getTime() - since.getTime() < hours * 3_600_000
    ) {
      return { disabled: false, alert: null };
    }
    const disabled = await tx.$executeRaw`
      UPDATE webhook_subscriptions
      SET status = 'disabled', disabled_reason = ${SUSTAINED_FAILURE}, disabled_at = ${now},
          row_version = row_version + 1
      WHERE id = ${claimed.subscriptionId} AND organization_id = ${claimed.organizationId}
        AND status = 'active'`;
    if (disabled !== 1) return { disabled: false, alert: null };
    // Same column semantics as the api's AuditService for a system actor: actor_id NULL,
    // metadata ids/counts only (never the URL, the name or a secret).
    await tx.auditLog.create({
      data: {
        organizationId: claimed.organizationId,
        actorType: 'system',
        actorId: null,
        action: AUTO_DISABLE_ACTION,
        resourceType: WEBHOOK_RESOURCE_TYPE,
        resourceId: sub.public_id,
        correlationId: `webhook-delivery:${claimed.publicId}`,
        sourceIp: null,
        metadata: {
          subscriptionId: sub.public_id,
          consecutiveFailures: failures,
          failingSince: since.toISOString(),
        },
      },
      select: { id: true },
    });
    const stored = await tx.notificationSettings.findUnique({
      where: { organizationId: claimed.organizationId },
      select: { organizationId: true, settings: true },
    });
    if (stored !== null && stored.organizationId !== claimed.organizationId) {
      wrongRead(this.options.sink, 'notification_settings', 'organization');
    }
    const settings = resolveNotificationSettings(stored?.settings ?? null).settings;
    if (!alertEnabled(settings, 'webhook_disabled', 'high'))
      return { disabled: true, alert: 'disabled' };
    const alert = await requestAlert(tx, {
      organizationId: claimed.organizationId,
      kind: 'webhook_disabled',
      severity: 'high',
      scopeKey: sub.public_id,
      occurredAt: now,
      throttleMinutes: alertKindSettings(settings, 'webhook_disabled').throttleMinutes,
      sourceEventId: claimed.publicId,
      correlationId: `webhook-delivery:${claimed.publicId}`,
      refs: { subscriptionId: sub.public_id },
      now,
    });
    return { disabled: true, alert: alert.result };
  }
}
