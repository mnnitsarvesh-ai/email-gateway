import { uuidv7, withTransactionDefaults } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { isWebhookEventType } from '@email-gateway/webhooks';
import type { WebhookMetrics } from '../metrics/webhook-metrics';
import { WEBHOOKS_FEATURE } from '../fanout/subscription-index';
import { idOf, type InconsistencySink, wrongRead } from '../shared/errors';

/** Original deliveries examined per batch transaction (W12). */
export const REPLAY_BATCH_SIZE = 500;
/** Replays advanced per pass (one batch each). */
const REPLAYS_PER_PASS = 4;
const REPLAYABLE_STATUSES: readonly string[] = ['succeeded', 'failed', 'dead', 'cancelled'];
const MAX_DELIVERY_SEQ = 65_535;

export type ReplayStepResult = 'skipped' | 'continued' | 'completed' | 'truncated' | 'failed';

interface ReplayRow {
  id: bigint;
  organization_id: bigint;
  subscription_id: bigint;
  status: string;
  range_from: Date;
  range_to: Date;
  statuses: unknown;
  event_types: unknown;
  cursor_occurred_at: Date | null;
  cursor_id: bigint | null;
  matched_count: number | bigint;
}

interface OriginalRow {
  id: bigint;
  event_occurred_at: Date;
  organization_id: bigint;
  event_id: string;
  event_type: string;
}

const parseJson = (value: unknown): unknown =>
  typeof value === 'string' ? (JSON.parse(value) as unknown) : value;

/**
 * Range replays (step 6.2 W12), run by the `delivery` role. The api inserts a `webhook_replays`
 * row (`queued`); each pass advances up to four replays by one batch transaction each: the
 * replay row `FOR UPDATE SKIP LOCKED` (one replica per replay); the organization (must be
 * `active`, its `webhooks` feature enabled: otherwise `failed` with `organization_inactive` /
 * `webhooks_not_enabled`); the subscription **locked** `FOR UPDATE` (must still be `active`; the
 * same lock the api's single replay takes, so the two never compute the same `delivery_seq`);
 * then up to 500 of the subscription's **original** deliveries (`delivery_seq = 0`) in the range
 * with the requested statuses and types, in keyset order `(event_occurred_at, id)` over
 * `(subscription_id, event_occurred_at, id)`, whose stored event still exists. Each gets a new
 * delivery (`delivery_seq = max + 1` for its `(subscription, event, occurred_at)`, read `FOR
 * UPDATE`; `trigger = replay`, `replay_id`, `pending`, due now) unless the event already has
 * WEBHOOK_REPLAY_MAX_PER_DELIVERY replays (skipped: counted in `matched_count`, not in
 * `created_count`, and in `webhook_replay_events_skipped_total{reason="replay_limit"}`);
 * insert-ignore on the delivery unique key, and the cursor, `matched_count` and `created_count`
 * advance in the same transaction — a crash resumes at the cursor and a re-run batch creates
 * nothing twice. At most `WEBHOOK_REPLAY_MAX_EVENTS` matches (beyond → `completed`, `truncated =
 * true`).
 */
export class ReplayProcessor {
  private readonly tx: PrismaClient;
  private readonly logger: Logger;
  private readonly batchSize: number;
  private readonly now: () => Date;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      maxEvents: number;
      /** WEBHOOK_REPLAY_MAX_PER_DELIVERY: replays (seq ≥ 1) of one event per subscription. */
      maxPerDelivery: number;
      metrics: WebhookMetrics;
      sink: InconsistencySink;
      logger: Logger;
      txTimeoutMs?: number;
      batchSize?: number;
      organizationIds?: readonly bigint[];
      now?: () => Date;
    },
  ) {
    this.tx = withTransactionDefaults(prisma, { timeoutMs: options.txTimeoutMs ?? 60_000 });
    this.logger = options.logger.child({ component: 'webhook-replay' });
    this.batchSize = options.batchSize ?? REPLAY_BATCH_SIZE;
    this.now = options.now ?? (() => new Date());
  }

  /** One pass: the oldest queued/running replays, one batch each. */
  async runOnce(): Promise<Array<{ id: bigint; result: ReplayStepResult }>> {
    const ids = this.options.organizationIds;
    const pending = await this.prisma.webhookReplay.findMany({
      where: {
        status: { in: ['queued', 'running'] },
        ...(ids !== undefined ? { organizationId: { in: [...ids] } } : {}),
      },
      select: { id: true },
      orderBy: { createdAt: 'asc' },
      take: REPLAYS_PER_PASS,
    });
    const out: Array<{ id: bigint; result: ReplayStepResult }> = [];
    for (const { id } of pending) {
      try {
        out.push({ id, result: await this.step(id) });
      } catch (error) {
        this.logger.warn(
          { errName: (error as Error).name, errCode: (error as { code?: string }).code },
          'webhook replay batch failed; resumed next pass',
        );
      }
    }
    return out;
  }

  /** One batch of one replay (exported for tests). */
  async step(replayId: bigint): Promise<ReplayStepResult> {
    const created: string[] = [];
    const skipped = { replay_limit: 0, sequence_exhausted: 0 };
    const result = await this.tx.$transaction(async (tx): Promise<ReplayStepResult> => {
      const [replay] = await tx.$queryRaw<ReplayRow[]>`
        SELECT id, organization_id, subscription_id, status, range_from, range_to, statuses,
               event_types, cursor_occurred_at, cursor_id, matched_count
        FROM webhook_replays WHERE id = ${replayId} FOR UPDATE SKIP LOCKED`;
      if (replay === undefined) return 'skipped';
      if (idOf(replay.id) !== replayId) wrongRead(this.options.sink, 'replay', 'id');
      if (replay.status !== 'queued' && replay.status !== 'running') return 'skipped';
      const organizationId = idOf(replay.organization_id);
      const subscriptionId = idOf(replay.subscription_id);
      const now = this.now();
      const finish = async (
        status: 'completed' | 'failed',
        extra: { truncated?: boolean; errorCode?: string | null } = {},
      ): Promise<void> => {
        await tx.$executeRaw`
          UPDATE webhook_replays
          SET status = ${status}, completed_at = ${now}, started_at = COALESCE(started_at, ${now}),
              truncated = ${extra.truncated ?? false}, error_code = ${extra.errorCode ?? null}
          WHERE id = ${replayId}`;
      };

      // A suspended / deleted organization or a revoked feature: nothing is re-sent.
      const organization = await tx.organization.findUnique({
        where: { id: organizationId },
        select: { id: true, status: true },
      });
      if (organization !== null && organization.id !== organizationId) {
        wrongRead(this.options.sink, 'organization', 'organization id');
      }
      if (organization === null || organization.status !== 'active') {
        await finish('failed', { errorCode: 'organization_inactive' });
        return 'failed';
      }
      const feature = await tx.organizationFeature.findUnique({
        where: {
          organizationId_featureKey: { organizationId, featureKey: WEBHOOKS_FEATURE },
        },
        select: { organizationId: true, featureKey: true, enabled: true },
      });
      if (feature !== null && feature.organizationId !== organizationId) {
        wrongRead(this.options.sink, 'organization', 'feature row');
      }
      if (feature?.enabled !== true) {
        await finish('failed', { errorCode: 'webhooks_not_enabled' });
        return 'failed';
      }

      // The subscription lock serializes this batch with the api's single replay (W12).
      const [subscription] = await tx.$queryRaw<
        Array<{ id: bigint; organization_id: bigint; status: string }>
      >`
        SELECT id, organization_id, status FROM webhook_subscriptions
        WHERE id = ${subscriptionId} FOR UPDATE`;
      if (
        subscription !== undefined &&
        (idOf(subscription.organization_id) !== organizationId ||
          idOf(subscription.id) !== subscriptionId)
      ) {
        wrongRead(this.options.sink, 'subscriptions', 'organization');
      }
      if (subscription === undefined || subscription.status !== 'active') {
        await finish('failed', { errorCode: 'webhook_not_active' });
        return 'failed';
      }
      const statuses = parseJson(replay.statuses);
      const types = replay.event_types === null ? null : parseJson(replay.event_types);
      if (
        !Array.isArray(statuses) ||
        statuses.length === 0 ||
        !statuses.every((s) => typeof s === 'string' && REPLAYABLE_STATUSES.includes(s)) ||
        (types !== null &&
          (!Array.isArray(types) ||
            !types.every((t) => typeof t === 'string' && isWebhookEventType(t))))
      ) {
        await finish('failed', { errorCode: 'replay_invalid' });
        return 'failed';
      }

      const matched = Number(replay.matched_count);
      const remaining = Math.max(0, this.options.maxEvents - matched);
      const limit = remaining === 0 ? 1 : Math.min(this.batchSize, remaining);
      const cursor =
        replay.cursor_occurred_at !== null && replay.cursor_id !== null
          ? Prisma.sql`AND (d.event_occurred_at > ${replay.cursor_occurred_at}
              OR (d.event_occurred_at = ${replay.cursor_occurred_at} AND d.id > ${idOf(replay.cursor_id)}))`
          : Prisma.empty;
      const typeFilter =
        types === null || (types as string[]).length === 0
          ? Prisma.empty
          : Prisma.sql`AND d.event_type IN (${Prisma.join(types)})`;
      const rows = await tx.$queryRaw<OriginalRow[]>`
        SELECT d.id, d.event_occurred_at, d.organization_id, d.event_id, d.event_type
        FROM webhook_deliveries d
        JOIN webhook_events e ON e.event_id = d.event_id AND e.occurred_at = d.event_occurred_at
        WHERE d.subscription_id = ${subscriptionId}
          AND d.event_occurred_at >= ${replay.range_from} AND d.event_occurred_at <= ${replay.range_to}
          AND d.delivery_seq = 0
          AND d.status IN (${Prisma.join(statuses as string[])})
          ${typeFilter}
          ${cursor}
        ORDER BY d.event_occurred_at, d.id
        LIMIT ${limit}`;
      for (const r of rows) {
        if (idOf(r.organization_id) !== organizationId) {
          wrongRead(this.options.sink, 'deliveries', 'organization');
        }
      }
      if (remaining === 0) {
        // The bound was reached exactly at the end of the previous batch.
        await finish('completed', { truncated: rows.length > 0 });
        return rows.length > 0 ? 'truncated' : 'completed';
      }

      let inserted = 0;
      if (rows.length > 0) {
        // Current read (FOR UPDATE), as the api's single replay: never a stale snapshot.
        const maxSeq = await tx.$queryRaw<
          Array<{
            event_id: string;
            event_occurred_at: Date;
            seq: number | bigint;
            replays: number | bigint | string | null;
          }>
        >`
          SELECT event_id, event_occurred_at, MAX(delivery_seq) AS seq,
                 SUM(delivery_seq > 0) AS replays
          FROM webhook_deliveries
          WHERE subscription_id = ${subscriptionId}
            AND event_id IN (${Prisma.join(rows.map((r) => r.event_id))})
          GROUP BY event_id, event_occurred_at
          FOR UPDATE`;
        const seqOf = new Map(
          maxSeq.map((s) => [
            `${s.event_id}|${s.event_occurred_at.getTime()}`,
            { seq: Number(s.seq), replays: Number(s.replays ?? 0) },
          ]),
        );
        const values: Prisma.Sql[] = [];
        for (const r of rows) {
          const known = seqOf.get(`${r.event_id}|${r.event_occurred_at.getTime()}`);
          if ((known?.replays ?? 0) >= this.options.maxPerDelivery) {
            skipped.replay_limit += 1;
            continue;
          }
          const next = (known?.seq ?? 0) + 1;
          if (next > MAX_DELIVERY_SEQ) {
            skipped.sequence_exhausted += 1;
            continue;
          }
          values.push(
            Prisma.sql`(${r.event_occurred_at}, ${uuidv7(now.getTime())}, ${subscriptionId},
              ${organizationId}, ${r.event_id}, ${r.event_type}, ${next}, 'replay', ${replayId},
              'pending', 0, ${now}, NOW(3), NOW(3))`,
          );
          created.push(r.event_type);
        }
        if (values.length > 0) {
          inserted = await tx.$executeRaw`
            INSERT INTO webhook_deliveries
              (event_occurred_at, public_id, subscription_id, organization_id, event_id,
               event_type, delivery_seq, \`trigger\`, replay_id, status, attempt_count,
               next_attempt_at, created_at, updated_at)
            VALUES ${Prisma.join(values)}
            ON DUPLICATE KEY UPDATE id = id`;
        }
      }
      if (inserted !== created.length) created.length = Math.min(created.length, inserted);
      const last = rows.at(-1);
      // Fewer rows than asked: the range is exhausted. A full batch that reached the bound
      // exactly continues: the next pass finds out whether more matches exist (truncated).
      const done = rows.length < limit;
      await tx.$executeRaw`
        UPDATE webhook_replays
        SET status = ${done ? 'completed' : 'running'},
            started_at = COALESCE(started_at, ${now}),
            completed_at = ${done ? now : null},
            cursor_occurred_at = ${last?.event_occurred_at ?? replay.cursor_occurred_at},
            cursor_id = ${last !== undefined ? idOf(last.id) : replay.cursor_id},
            matched_count = matched_count + ${rows.length},
            created_count = created_count + ${inserted}
        WHERE id = ${replayId}`;
      return done ? 'completed' : 'continued';
    });
    const m = this.options.metrics;
    for (const type of created) m.deliveriesCreated.inc({ type, trigger: 'replay' });
    for (const [reason, n] of Object.entries(skipped)) {
      if (n > 0) m.replayEventsSkipped.inc({ reason }, n);
    }
    if (result === 'completed' || result === 'truncated' || result === 'failed') {
      m.replays.inc({ result });
    }
    return result;
  }
}
