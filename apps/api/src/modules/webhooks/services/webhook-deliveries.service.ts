import { BadRequestException, Inject, Injectable, Logger } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import { parseStoredEnvelope } from '@email-gateway/webhooks';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { ApiConventionMetrics } from '../../../http/api-metrics';
import { CursorCodec, cursorInvalid } from '../../../http/cursor/cursor-codec';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import { rangeWindow, resolveRange } from '../../../http/listing/range';
import { decideKeysetPage, decideScanPage } from '../../../http/listing/scan-budget';
import {
  decodeListCursor,
  encodeListCursor,
  listBinding,
  type TimeIdKey,
  timeIdKeyOf,
  timeIdKeys,
} from '../../messages/domain/v1-list';
import {
  type DeliveryFilters,
  type DeliveryRow,
  WebhookDeliveriesRepository,
} from '../repositories/webhook-deliveries.repository';
import { WebhookSubscriptionsRepository } from '../repositories/webhook-subscriptions.repository';
import {
  webhookDeliveryNotFound,
  webhookEventExpired,
  webhookNotFound,
  webhookReplayInProgress,
  webhookReplayLimit,
  webhookReplayNotFound,
} from '../webhooks.errors';
import { toAttemptView, toDeliveryView, toReplayView } from '../webhooks.mapper';
import {
  type CreateReplayBody,
  CreateReplayBodySchema,
  DEFAULT_REPLAY_STATUSES,
  DELIVERY_RETENTION_DAYS,
  type DeliveryDetailView,
  type DeliveryListQuery,
  type DeliveryPage,
  type DeliveryReplayAccepted,
  type ReplayAccepted,
  type ReplayView,
  WEBHOOK_DELIVERIES_RESOURCE,
} from '../webhooks.schemas';
import {
  parseBody,
  parsePublicId,
  requester,
  WEBHOOK_AUDIT,
  WEBHOOK_OPERATIONS,
  WEBHOOK_RESOURCE_TYPE,
  WEBHOOK_TX_TIMEOUT_MS,
} from './webhook-common';
import { WebhooksService } from './webhooks.service';

type Config = Pick<
  ApiConfig,
  | 'API_LIST_SCAN_BUDGET_ROWS'
  | 'WEBHOOK_HISTORY_MAX_RANGE_DAYS'
  | 'WEBHOOK_REPLAY_MAX_RANGE_HOURS'
  | 'WEBHOOK_REPLAY_MAX_PER_DELIVERY'
>;

const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
/** Clock skew tolerated for a replay range end (`to`) in the future. */
const FUTURE_SKEW_MS = 5 * 60_000;

/** The validated range replay body: `from < to`, within the bounds and the retention (W12). */
export function checkReplayRange(
  body: CreateReplayBody,
  bounds: { maxRangeHours: number; now: Date },
): { from: Date; to: Date } {
  const from = new Date(body.from);
  const to = new Date(body.to);
  const issues: string[] = [];
  if (from.getTime() >= to.getTime()) issues.push('from: must be before to');
  else if (to.getTime() - from.getTime() > bounds.maxRangeHours * HOUR_MS) {
    issues.push(`to: the range may cover at most ${bounds.maxRangeHours} hours`);
  }
  if (from.getTime() < bounds.now.getTime() - DELIVERY_RETENTION_DAYS * DAY_MS) {
    issues.push(`from: must be within the delivery retention (${DELIVERY_RETENTION_DAYS} days)`);
  }
  if (to.getTime() > bounds.now.getTime() + FUTURE_SKEW_MS) {
    issues.push('to: must not be in the future');
  }
  if (issues.length > 0) throw new BadRequestException(issues);
  return { from, to };
}

/**
 * Delivery history and replays of a subscription (step 6.2 W8, W12, §6.1): the history from the
 * read replica (bounded range on `event_occurred_at` for partition pruning, keyset
 * `(event_occurred_at, id)` over `(subscription_id, event_occurred_at, id)`, scan-bounded when
 * filtered, D6), the delivery detail with its attempts and stored envelope, the single replay
 * (the replay delivery is inserted in the api transaction) and the range replay request (a
 * `webhook_replays` row the webhook-worker executes). Replays need an active subscription and
 * the feature; both are keyed transactionally (`sensitive`).
 */
@Injectable()
export class WebhookDeliveriesService {
  private readonly logger = new Logger(WebhookDeliveriesService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly subscriptions: WebhookSubscriptionsRepository,
    private readonly deliveries: WebhookDeliveriesRepository,
    private readonly webhooks: WebhooksService,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
    private readonly metrics: ApiConventionMetrics,
  ) {}

  now(): Date {
    return new Date();
  }

  private async subscription(scope: TenantScope, rawId: unknown) {
    const row = await this.subscriptions.find(scope, parsePublicId(rawId, 'webhookId'));
    if (!row) throw webhookNotFound();
    return row;
  }

  async list(
    principal: Principal,
    scope: TenantScope,
    rawWebhookId: unknown,
    query: DeliveryListQuery,
  ): Promise<DeliveryPage> {
    const webhookId = parsePublicId(rawWebhookId, 'webhookId');
    const binding = listBinding({
      resource: WEBHOOK_DELIVERIES_RESOURCE,
      principal,
      // The subscription is part of the binding: a cursor never moves to another webhook.
      filters: { ...query.filters, webhookId: { values: [webhookId] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    if (decoded && !decoded.window) throw cursorInvalid();
    const range = resolveRange(query, {
      defaultMs: DAY_MS,
      maxDays: this.config.WEBHOOK_HISTORY_MAX_RANGE_DAYS,
      now: this.now(),
      cursorWindow: decoded?.window,
    });
    const sub = await this.subscription(scope, webhookId);
    const filters: DeliveryFilters = {
      statuses: query.filters.status?.values,
      eventTypes: query.filters.eventType?.values,
      triggers: query.filters.trigger?.values,
    };
    const filtered = [filters.statuses, filters.eventTypes, filters.triggers].some(
      (v) => (v?.length ?? 0) > 0,
    );
    const base = {
      subscriptionId: sub.id,
      range,
      after: timeIdKeyOf(decoded),
      direction: binding.direction,
      take: query.limit + 1,
    };
    const keyOf = (d: DeliveryRow): TimeIdKey => ({ at: d.eventOccurredAt, id: d.id });
    let rows: DeliveryRow[];
    let next: TimeIdKey | null;
    if (!filtered) {
      const fetched = await this.deliveries.deliveries(scope, base);
      const decision = decideKeysetPage({ fetched, limit: query.limit, keyOf });
      rows = fetched.slice(0, decision.rows);
      next = decision.next;
    } else {
      const boundary = await this.deliveries.deliveriesBoundary(scope, {
        ...base,
        budget: this.config.API_LIST_SCAN_BUDGET_ROWS,
      });
      const fetched = await this.deliveries.deliveries(scope, { ...base, boundary, filters });
      const decision = decideScanPage({ fetched, limit: query.limit, boundary, keyOf });
      if (decision.budgetExhausted) {
        this.metrics.scanBudgetExhausted.inc({ resource: WEBHOOK_DELIVERIES_RESOURCE });
      }
      rows = fetched.slice(0, decision.rows);
      next = decision.next;
    }
    return {
      data: rows.map(toDeliveryView),
      nextCursor: next
        ? encodeListCursor(this.codec, binding, timeIdKeys(next), rangeWindow(range))
        : null,
    };
  }

  async get(
    scope: TenantScope,
    rawWebhookId: unknown,
    rawDeliveryId: unknown,
  ): Promise<DeliveryDetailView> {
    const webhookId = parsePublicId(rawWebhookId, 'webhookId');
    const deliveryId = parsePublicId(rawDeliveryId, 'deliveryId');
    const sub = await this.subscription(scope, webhookId);
    const delivery = await this.deliveries.findDelivery(scope, sub.id, deliveryId);
    if (!delivery) throw webhookDeliveryNotFound();
    const [attempts, json] = await Promise.all([
      this.deliveries.attempts(scope, delivery),
      this.deliveries.storedEvent(scope, delivery.eventId, delivery.eventOccurredAt),
    ]);
    return {
      ...toDeliveryView(delivery),
      attempts: attempts.map(toAttemptView),
      event: this.envelopeOf(json),
    };
  }

  /** The stored envelope as an object; null when gone or (never expected) unparseable. */
  private envelopeOf(json: string | null): Record<string, unknown> | null {
    if (json === null) return null;
    try {
      return parseStoredEnvelope(json) as unknown as Record<string, unknown>;
    } catch {
      this.logger.warn({ message: 'stored webhook envelope does not parse; not served' });
      return null;
    }
  }

  /**
   * `POST /webhooks/{webhookId}/deliveries/{deliveryId}/replay` (W12): in one writer
   * transaction under the subscription row lock, a new pending delivery of the same stored event
   * (`delivery_seq = max + 1`, `trigger = replay`). `409 webhook_not_active`, `409
   * webhook_replay_limit` (WEBHOOK_REPLAY_MAX_PER_DELIVERY), `410 webhook_event_expired`.
   */
  async replayDelivery(
    principal: Principal,
    scope: TenantScope,
    input: { webhookId: unknown; deliveryId: unknown; idempotencyKey: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<DeliveryReplayAccepted>> {
    const webhookId = parsePublicId(input.webhookId, 'webhookId');
    const deliveryId = parsePublicId(input.deliveryId, 'deliveryId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const operation = WEBHOOK_OPERATIONS.deliveryReplay;
    return this.idempotency.execute<DeliveryReplayAccepted>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: webhookId,
        fingerprint: requestFingerprint({ operation, resourceId: webhookId, body: { deliveryId } }),
      },
      async (tx) => {
        const sub = await this.webhooks.lockActive(tx, scope, webhookId);
        const original = await this.deliveries.findDeliveryTx(tx, scope, sub.id, deliveryId);
        if (!original) throw webhookDeliveryNotFound();
        if (
          !(await this.deliveries.eventExists(
            tx,
            scope,
            original.eventId,
            original.eventOccurredAt,
          ))
        ) {
          throw webhookEventExpired();
        }
        const sequence = await this.deliveries.sequence(tx, scope, {
          subscriptionId: sub.id,
          eventId: original.eventId,
          eventOccurredAt: original.eventOccurredAt,
        });
        const max = this.config.WEBHOOK_REPLAY_MAX_PER_DELIVERY;
        if (sequence.replays >= max) throw webhookReplayLimit(max);
        const now = this.now();
        const replay = await this.deliveries.insertDelivery(tx, scope, {
          publicId: uuidv7(now.getTime()),
          subscriptionId: sub.id,
          eventId: original.eventId,
          eventType: original.eventType,
          eventOccurredAt: original.eventOccurredAt,
          deliverySeq: sequence.maxSeq + 1,
          trigger: 'replay',
          now,
        });
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: WEBHOOK_AUDIT.deliveryReplayed,
            resourceType: WEBHOOK_RESOURCE_TYPE,
            resourceId: sub.publicId,
            sourceIp,
            metadata: {
              deliveryId: original.publicId,
              replayDeliveryId: replay.publicId,
              eventId: original.eventId,
              eventType: original.eventType,
              deliverySeq: replay.deliverySeq,
            },
          },
          tx,
        );
        return { statusCode: 202, body: { deliveryId: replay.publicId } };
      },
      { timeoutMs: WEBHOOK_TX_TIMEOUT_MS },
    );
  }

  /**
   * `POST /webhooks/{webhookId}/replays` (W12): a queued `webhook_replays` row over the
   * subscription's original deliveries of `[from, to)`; one queued or running replay per
   * subscription (`409 webhook_replay_in_progress`).
   */
  async createReplay(
    principal: Principal,
    scope: TenantScope,
    input: { webhookId: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<ReplayAccepted>> {
    const webhookId = parsePublicId(input.webhookId, 'webhookId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(CreateReplayBodySchema, input.body);
    const range = checkReplayRange(body, {
      maxRangeHours: this.config.WEBHOOK_REPLAY_MAX_RANGE_HOURS,
      now: this.now(),
    });
    const statuses = [...(body.statuses ?? DEFAULT_REPLAY_STATUSES)];
    const eventTypes = body.eventTypes ? [...body.eventTypes] : null;
    const operation = WEBHOOK_OPERATIONS.rangeReplay;
    return this.idempotency.execute<ReplayAccepted>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: webhookId,
        fingerprint: requestFingerprint({
          operation,
          resourceId: webhookId,
          body: {
            from: range.from.toISOString(),
            to: range.to.toISOString(),
            statuses,
            eventTypes,
          },
        }),
      },
      async (tx) => {
        const sub = await this.webhooks.lockActive(tx, scope, webhookId);
        const active = await this.deliveries.activeReplay(tx, scope, sub.id);
        if (active) throw webhookReplayInProgress(active.publicId);
        const who = requester(principal);
        const row = await this.deliveries.insertReplay(tx, scope, {
          publicId: uuidv7(),
          subscriptionId: sub.id,
          requestedByType: who.type,
          requestedById: who.id,
          rangeFrom: range.from,
          rangeTo: range.to,
          statuses,
          eventTypes,
        });
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: WEBHOOK_AUDIT.replayRequested,
            resourceType: WEBHOOK_RESOURCE_TYPE,
            resourceId: sub.publicId,
            sourceIp,
            metadata: {
              replayId: row.publicId,
              from: range.from.toISOString(),
              to: range.to.toISOString(),
              statuses,
              eventTypes,
            },
          },
          tx,
        );
        return { statusCode: 202, body: { replayId: row.publicId, status: 'queued' } };
      },
      { timeoutMs: WEBHOOK_TX_TIMEOUT_MS },
    );
  }

  async getReplay(
    scope: TenantScope,
    rawWebhookId: unknown,
    rawReplayId: unknown,
  ): Promise<ReplayView> {
    const webhookId = parsePublicId(rawWebhookId, 'webhookId');
    const replayId = parsePublicId(rawReplayId, 'replayId');
    const sub = await this.subscription(scope, webhookId);
    const row = await this.deliveries.findReplay(scope, sub.id, replayId);
    if (!row) throw webhookReplayNotFound();
    return toReplayView(row);
  }
}
