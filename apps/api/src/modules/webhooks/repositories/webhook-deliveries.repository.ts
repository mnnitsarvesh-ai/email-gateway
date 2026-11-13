import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import {
  Prisma,
  type WebhookDeliveryStatus,
  type WebhookDeliveryTrigger,
  type WebhookEventSeverity,
  type WebhookRequesterType,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { CursorDirection } from '../../../http/cursor/cursor-codec';
import { assertEcho, InconsistentReadError } from '../../../http/listing/echo-check';
import { boundaryOffset } from '../../../http/listing/scan-budget';
import type { TimeIdKey } from '../../messages/domain/v1-list';
import {
  afterKey,
  allOf,
  column,
  keysetOrder,
  upToKey,
} from '../../messages/repositories/keyset-sql';
import { clampTake } from '../../tenant-data/page';

type Tx = Prisma.TransactionClient;

const DAY_MS = 86_400_000;

/** The history keyset index (W12, §6.1): `(subscription_id, event_occurred_at, id)`. */
export const DELIVERIES_INDEX = 'webhook_deliveries_sub_occurred_id_idx';
const forceDeliveriesIndex = () => Prisma.raw(`FORCE INDEX (${DELIVERIES_INDEX})`);

const OCCURRED_AT = column('event_occurred_at');
const ID = column('id');

const DELIVERY_COLUMNS = Prisma.sql`id, event_occurred_at, public_id, subscription_id,
  organization_id, event_id, event_type, delivery_seq, \`trigger\`, status, attempt_count,
  next_attempt_at, first_attempt_at, last_attempt_at, last_response_code, last_latency_ms,
  last_error, completed_at, created_at`;

/** Most attempts shown with a delivery (WEBHOOK_MAX_ATTEMPTS ≤ 15). */
const MAX_ATTEMPTS_SHOWN = 100;
/** Pending deliveries cancelled per statement, and statements per transaction (W5, W13). */
const CANCEL_BATCH = 5_000;
const CANCEL_MAX_BATCHES = 20;

export const deliverySelect = {
  id: true,
  eventOccurredAt: true,
  publicId: true,
  subscriptionId: true,
  organizationId: true,
  eventId: true,
  eventType: true,
  deliverySeq: true,
  trigger: true,
  status: true,
  attemptCount: true,
  nextAttemptAt: true,
  firstAttemptAt: true,
  lastAttemptAt: true,
  lastResponseCode: true,
  lastLatencyMs: true,
  lastError: true,
  completedAt: true,
  createdAt: true,
} satisfies Prisma.WebhookDeliverySelect;

export type DeliveryRow = Prisma.WebhookDeliveryGetPayload<{ select: typeof deliverySelect }>;

const attemptSelect = {
  organizationId: true,
  deliveryId: true,
  attemptNo: true,
  attemptedAt: true,
  outcome: true,
  httpStatus: true,
  latencyMs: true,
  responseSnippet: true,
  retryAfterSeconds: true,
  errorCode: true,
  signatureCount: true,
} satisfies Prisma.WebhookDeliveryAttemptSelect;

export type DeliveryAttemptRow = Prisma.WebhookDeliveryAttemptGetPayload<{
  select: typeof attemptSelect;
}>;

const replaySelect = {
  id: true,
  publicId: true,
  organizationId: true,
  subscriptionId: true,
  status: true,
  rangeFrom: true,
  rangeTo: true,
  statuses: true,
  eventTypes: true,
  matchedCount: true,
  createdCount: true,
  truncated: true,
  errorCode: true,
  createdAt: true,
  startedAt: true,
  completedAt: true,
} satisfies Prisma.WebhookReplaySelect;

export type ReplayRow = Prisma.WebhookReplayGetPayload<{ select: typeof replaySelect }>;

export interface DeliveryFilters {
  statuses?: readonly string[] | undefined;
  eventTypes?: readonly string[] | undefined;
  triggers?: readonly string[] | undefined;
}

export interface DeliveryPlanInput {
  organizationId: bigint;
  subscriptionId: bigint;
  range: { from: Date; to: Date };
  after?: TimeIdKey | undefined;
  direction: CursorDirection;
  take: number;
}

/** Filter predicates; column names are code constants, values bound parameters (D4). */
export function deliveryFilterSql(filters: DeliveryFilters): Prisma.Sql[] {
  const parts: Prisma.Sql[] = [];
  if (filters.statuses && filters.statuses.length > 0) {
    parts.push(Prisma.sql`status IN (${Prisma.join([...filters.statuses])})`);
  }
  if (filters.eventTypes && filters.eventTypes.length > 0) {
    parts.push(Prisma.sql`event_type IN (${Prisma.join([...filters.eventTypes])})`);
  }
  if (filters.triggers && filters.triggers.length > 0) {
    parts.push(Prisma.sql`\`trigger\` IN (${Prisma.join([...filters.triggers])})`);
  }
  return parts;
}

/**
 * One history page: keyset `(event_occurred_at, id)` over
 * `webhook_deliveries_sub_occurred_id_idx` within the bounded range (partition pruning on
 * `event_occurred_at`), between the cursor and the scan boundary when filtered.
 */
export function deliveriesPageSql(
  input: DeliveryPlanInput & { boundary?: TimeIdKey | null; filters?: DeliveryFilters },
): Prisma.Sql {
  return Prisma.sql`SELECT ${DELIVERY_COLUMNS} FROM webhook_deliveries ${forceDeliveriesIndex()}
    WHERE organization_id = ${input.organizationId}
      AND subscription_id = ${input.subscriptionId}
      AND event_occurred_at >= ${input.range.from} AND event_occurred_at < ${input.range.to}
      AND ${afterKey(OCCURRED_AT, ID, input.after, input.direction)}
      AND ${upToKey(OCCURRED_AT, ID, input.boundary ?? null, input.direction)}
      AND ${allOf(deliveryFilterSql(input.filters ?? {}))}
    ${keysetOrder(OCCURRED_AT, ID, input.direction)} LIMIT ${clampTake(input.take)}`;
}

/** Scan boundary (D6): the key of the `budget`-th index entry after the cursor. */
export function deliveriesBoundarySql(input: DeliveryPlanInput & { budget: number }): Prisma.Sql {
  return Prisma.sql`SELECT event_occurred_at, id FROM webhook_deliveries ${forceDeliveriesIndex()}
    WHERE organization_id = ${input.organizationId}
      AND subscription_id = ${input.subscriptionId}
      AND event_occurred_at >= ${input.range.from} AND event_occurred_at < ${input.range.to}
      AND ${afterKey(OCCURRED_AT, ID, input.after, input.direction)}
    ${keysetOrder(OCCURRED_AT, ID, input.direction)} LIMIT 1 OFFSET ${boundaryOffset(input.budget)}`;
}

interface RawDeliveryRow {
  id: bigint;
  event_occurred_at: Date;
  public_id: string;
  subscription_id: bigint;
  organization_id: bigint;
  event_id: string;
  event_type: string;
  delivery_seq: number;
  trigger: WebhookDeliveryTrigger;
  status: WebhookDeliveryStatus;
  attempt_count: number;
  next_attempt_at: Date | null;
  first_attempt_at: Date | null;
  last_attempt_at: Date | null;
  last_response_code: number | null;
  last_latency_ms: number | null;
  last_error: string | null;
  completed_at: Date | null;
  created_at: Date;
}

const num = (v: number | bigint | null): number | null => (v === null ? null : Number(v));

export const toDeliveryRow = (r: RawDeliveryRow): DeliveryRow => ({
  id: BigInt(r.id),
  eventOccurredAt: r.event_occurred_at,
  publicId: r.public_id,
  subscriptionId: BigInt(r.subscription_id),
  organizationId: BigInt(r.organization_id),
  eventId: r.event_id,
  eventType: r.event_type,
  deliverySeq: Number(r.delivery_seq),
  trigger: r.trigger,
  status: r.status,
  attemptCount: Number(r.attempt_count),
  nextAttemptAt: r.next_attempt_at,
  firstAttemptAt: r.first_attempt_at,
  lastAttemptAt: r.last_attempt_at,
  lastResponseCode: num(r.last_response_code),
  lastLatencyMs: num(r.last_latency_ms),
  lastError: r.last_error,
  completedAt: r.completed_at,
  createdAt: r.created_at,
});

export interface NewDelivery {
  publicId: string;
  subscriptionId: bigint;
  eventId: string;
  eventType: string;
  eventOccurredAt: Date;
  deliverySeq: number;
  trigger: WebhookDeliveryTrigger;
  now: Date;
}

export interface NewWebhookEvent {
  eventId: string;
  eventType: string;
  occurredAt: Date;
  sourceEventId: string;
  sourceEventType: string;
  severity: WebhookEventSeverity;
  payloadJson: string;
  payloadSha256: string;
}

export interface NewReplay {
  publicId: string;
  subscriptionId: bigint;
  requestedByType: WebhookRequesterType;
  requestedById: string;
  rangeFrom: Date;
  rangeTo: Date;
  statuses: string[];
  eventTypes: string[] | null;
}

/**
 * Delivery history, stored events, attempts and replays of the scope (step 6.2 W8, W12, D15):
 * replica reads for the history (partition-pruned on `event_occurred_at` / `occurred_at` /
 * `attempted_at`), writer reads and writes inside the caller's transaction for the replay and
 * test routes. Every returned row is echo-checked.
 */
@Injectable()
export class WebhookDeliveriesRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  async deliveries(
    scope: TenantScope,
    input: Omit<DeliveryPlanInput, 'organizationId'> & {
      boundary?: TimeIdKey | null;
      filters?: DeliveryFilters;
    },
  ): Promise<DeliveryRow[]> {
    const raw = await this.db.$queryRaw<RawDeliveryRow[]>(
      deliveriesPageSql({ ...input, organizationId: scope.organizationId }),
    );
    const rows = raw.map(toDeliveryRow);
    assertEcho('webhookDeliveries.list', rows, {
      organizationId: scope.organizationId,
      subscriptionId: input.subscriptionId,
    });
    for (const row of rows) {
      const at = row.eventOccurredAt.getTime();
      if (at < input.range.from.getTime() || at >= input.range.to.getTime()) {
        throw new InconsistentReadError('webhookDeliveries.list');
      }
    }
    return rows;
  }

  async deliveriesBoundary(
    scope: TenantScope,
    input: Omit<DeliveryPlanInput, 'organizationId'> & { budget: number },
  ): Promise<TimeIdKey | null> {
    const rows = await this.db.$queryRaw<Array<{ event_occurred_at: Date; id: bigint }>>(
      deliveriesBoundarySql({ ...input, organizationId: scope.organizationId }),
    );
    const row = rows[0];
    return row ? { at: row.event_occurred_at, id: BigInt(row.id) } : null;
  }

  /** A delivery of the subscription by public id (replica), or null. */
  async findDelivery(
    scope: TenantScope,
    subscriptionId: bigint,
    publicId: string,
  ): Promise<DeliveryRow | null> {
    const row = await this.db.webhookDelivery.findFirst({
      where: tenantWhere(scope, { subscriptionId, publicId }),
      select: deliverySelect,
    });
    if (!row) return null;
    assertEcho('webhookDeliveries.find', [row], {
      organizationId: scope.organizationId,
      subscriptionId,
      publicId,
    });
    return row;
  }

  /**
   * The attempts of a delivery, by attempt number. Pruned on `attempted_at`: an attempt is never
   * older than its delivery row (one day of slack for clock skew between writers).
   */
  async attempts(scope: TenantScope, delivery: DeliveryRow): Promise<DeliveryAttemptRow[]> {
    const rows = await this.db.webhookDeliveryAttempt.findMany({
      where: tenantWhere(scope, {
        deliveryId: delivery.id,
        deliveryEventOccurredAt: delivery.eventOccurredAt,
        attemptedAt: { gte: new Date(delivery.createdAt.getTime() - DAY_MS) },
      }),
      select: attemptSelect,
      orderBy: { attemptNo: 'asc' },
      take: MAX_ATTEMPTS_SHOWN,
    });
    assertEcho('webhookDeliveries.attempts', rows, {
      organizationId: scope.organizationId,
      deliveryId: delivery.id,
    });
    return rows;
  }

  /** The stored envelope JSON of an event (replica), or null after its partition dropped. */
  async storedEvent(scope: TenantScope, eventId: string, occurredAt: Date): Promise<string | null> {
    const row = await this.db.webhookEvent.findFirst({
      where: tenantWhere(scope, { eventId, occurredAt }),
      select: { organizationId: true, eventId: true, payloadJson: true },
    });
    if (!row) return null;
    assertEcho('webhookDeliveries.event', [row], { organizationId: scope.organizationId, eventId });
    return row.payloadJson;
  }

  async findReplay(
    scope: TenantScope,
    subscriptionId: bigint,
    publicId: string,
  ): Promise<ReplayRow | null> {
    const row = await this.db.webhookReplay.findFirst({
      where: tenantWhere(scope, { subscriptionId, publicId }),
      select: replaySelect,
    });
    if (!row) return null;
    assertEcho('webhookReplays.find', [row], {
      organizationId: scope.organizationId,
      subscriptionId,
      publicId,
    });
    return row;
  }

  // ---- Writer (inside the caller's transaction) -------------------------------------------

  /**
   * Cancels the subscription's pending deliveries (delete, manual disable; W5) in bounded
   * statements over `webhook_deliveries_status_org_next_idx`. Returns how many were cancelled;
   * beyond CANCEL_MAX_BATCHES × CANCEL_BATCH (only past the backlog bound) the worker's claimer
   * and maintenance pass cancel the rest.
   */
  async cancelPending(
    tx: Tx,
    scope: TenantScope,
    subscriptionId: bigint,
    reason: 'deleted' | 'disabled',
    now: Date,
  ): Promise<number> {
    let total = 0;
    for (let batch = 0; batch < CANCEL_MAX_BATCHES; batch += 1) {
      const count = await tx.$executeRaw`
        UPDATE webhook_deliveries
        SET status = 'cancelled', next_attempt_at = NULL, completed_at = ${now},
            last_error = ${`cancelled:${reason}`}, updated_at = ${now}
        WHERE status = 'pending' AND organization_id = ${scope.organizationId}
          AND subscription_id = ${subscriptionId}
        LIMIT ${CANCEL_BATCH}`;
      total += count;
      if (count < CANCEL_BATCH) break;
    }
    return total;
  }

  /**
   * Pause (W5): parks the subscription's pending deliveries (`next_attempt_at = NULL`) so they
   * leave the worker's due index — a paused backlog never hides the organization's other
   * subscriptions from the claimer, nor counts as due backlog. Bounded statements like
   * `cancelPending`; rows beyond the bound (or in flight now) are parked by the worker's claimer
   * when they come due.
   */
  async parkPending(tx: Tx, scope: TenantScope, subscriptionId: bigint): Promise<number> {
    let total = 0;
    for (let batch = 0; batch < CANCEL_MAX_BATCHES; batch += 1) {
      const count = await tx.$executeRaw`
        UPDATE webhook_deliveries
        SET next_attempt_at = NULL
        WHERE status = 'pending' AND organization_id = ${scope.organizationId}
          AND subscription_id = ${subscriptionId} AND next_attempt_at IS NOT NULL
        LIMIT ${CANCEL_BATCH}`;
      total += count;
      if (count < CANCEL_BATCH) break;
    }
    return total;
  }

  /**
   * Resume (W5): parked pending deliveries of the subscription become due now. Bounded like
   * `parkPending`; the worker's maintenance pass un-parks whatever is left.
   */
  async unparkPending(
    tx: Tx,
    scope: TenantScope,
    subscriptionId: bigint,
    now: Date,
  ): Promise<number> {
    let total = 0;
    for (let batch = 0; batch < CANCEL_MAX_BATCHES; batch += 1) {
      const count = await tx.$executeRaw`
        UPDATE webhook_deliveries
        SET next_attempt_at = ${now}, updated_at = ${now}
        WHERE status = 'pending' AND organization_id = ${scope.organizationId}
          AND subscription_id = ${subscriptionId} AND next_attempt_at IS NULL
        LIMIT ${CANCEL_BATCH}`;
      total += count;
      if (count < CANCEL_BATCH) break;
    }
    return total;
  }

  /** A delivery of the subscription by public id on the writer, or null. */
  async findDeliveryTx(
    tx: Tx,
    scope: TenantScope,
    subscriptionId: bigint,
    publicId: string,
  ): Promise<DeliveryRow | null> {
    const row = await tx.webhookDelivery.findFirst({
      where: tenantWhere(scope, { subscriptionId, publicId }),
      select: deliverySelect,
    });
    if (!row) return null;
    assertEcho('webhookDeliveries.findTx', [row], {
      organizationId: scope.organizationId,
      subscriptionId,
      publicId,
    });
    return row;
  }

  /** True while the stored event (partition) still exists. */
  async eventExists(tx: Tx, scope: TenantScope, eventId: string, occurredAt: Date) {
    const row = await tx.webhookEvent.findFirst({
      where: tenantWhere(scope, { eventId, occurredAt }),
      select: { organizationId: true, eventId: true },
    });
    if (row) assertEcho('webhookEvents.exists', [row], { organizationId: scope.organizationId });
    return row !== null;
  }

  /** `max(delivery_seq)` and the number of replays (seq ≥ 1) of an event for a subscription. */
  async sequence(
    tx: Tx,
    scope: TenantScope,
    key: { subscriptionId: bigint; eventId: string; eventOccurredAt: Date },
  ): Promise<{ maxSeq: number; replays: number }> {
    const rows = await tx.$queryRaw<Array<{ max_seq: number | null; replays: bigint | number }>>`
      SELECT MAX(delivery_seq) AS max_seq, SUM(delivery_seq > 0) AS replays
      FROM webhook_deliveries
      WHERE organization_id = ${scope.organizationId} AND subscription_id = ${key.subscriptionId}
        AND event_id = ${key.eventId} AND event_occurred_at = ${key.eventOccurredAt}
      FOR UPDATE`;
    const row = rows[0];
    return {
      maxSeq: row?.max_seq === null || row?.max_seq === undefined ? 0 : Number(row.max_seq),
      replays: row?.replays === null || row?.replays === undefined ? 0 : Number(row.replays),
    };
  }

  async insertDelivery(tx: Tx, scope: TenantScope, data: NewDelivery): Promise<DeliveryRow> {
    const row = await tx.webhookDelivery.create({
      data: {
        organizationId: scope.organizationId,
        publicId: data.publicId,
        subscriptionId: data.subscriptionId,
        eventId: data.eventId,
        eventType: data.eventType,
        eventOccurredAt: data.eventOccurredAt,
        deliverySeq: data.deliverySeq,
        trigger: data.trigger,
        status: 'pending',
        nextAttemptAt: data.now,
      },
      select: deliverySelect,
    });
    assertEcho('webhookDeliveries.insert', [row], {
      organizationId: scope.organizationId,
      publicId: data.publicId,
    });
    return row;
  }

  async insertEvent(tx: Tx, scope: TenantScope, data: NewWebhookEvent): Promise<void> {
    await tx.webhookEvent.create({
      data: { organizationId: scope.organizationId, ...data },
      select: { id: true },
    });
  }

  /** The subscription's queued or running range replay, if any (one at a time, W12). */
  async activeReplay(
    tx: Tx,
    scope: TenantScope,
    subscriptionId: bigint,
  ): Promise<{ publicId: string } | null> {
    const row = await tx.webhookReplay.findFirst({
      where: tenantWhere(scope, {
        subscriptionId,
        status: { in: ['queued' as const, 'running' as const] },
      }),
      select: { publicId: true, organizationId: true, subscriptionId: true },
    });
    if (!row) return null;
    assertEcho('webhookReplays.active', [row], {
      organizationId: scope.organizationId,
      subscriptionId,
    });
    return row;
  }

  async insertReplay(tx: Tx, scope: TenantScope, data: NewReplay): Promise<ReplayRow> {
    const row = await tx.webhookReplay.create({
      data: {
        organizationId: scope.organizationId,
        publicId: data.publicId,
        subscriptionId: data.subscriptionId,
        requestedByType: data.requestedByType,
        requestedById: data.requestedById,
        rangeFrom: data.rangeFrom,
        rangeTo: data.rangeTo,
        statuses: data.statuses,
        eventTypes: data.eventTypes ?? Prisma.DbNull,
        status: 'queued',
      },
      select: replaySelect,
    });
    assertEcho('webhookReplays.insert', [row], {
      organizationId: scope.organizationId,
      publicId: data.publicId,
    });
    return row;
  }
}
