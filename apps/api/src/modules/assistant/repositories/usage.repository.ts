import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';

type Tx = Prisma.TransactionClient;

export interface UsageDelta {
  day: Date;
  provider: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  costMicros: number;
  /**
   * Step AI-6 D1: the user row of `ai_chat_usage_user_daily` upserted with the organization row
   * (`costMicros` NULL there when the model has no price), with the key that paid for the turn.
   */
  user?: { userId: bigint; keySource: 'platform' | 'tenant'; priced: boolean };
}

export interface UsageDayRow {
  day: Date;
  provider: string;
  model: string;
  turns: number;
  inputTokens: bigint;
  outputTokens: bigint;
  cacheReadTokens: bigint;
  cacheWriteTokens: bigint;
  costMicros: bigint;
}

/** Tokens counted against the daily budgets: everything the provider processed for the turn. */
export const budgetTokens = (u: {
  inputTokens: number | bigint;
  outputTokens: number | bigint;
  cacheReadTokens: number | bigint;
  cacheWriteTokens: number | bigint;
}): number =>
  Number(u.inputTokens) +
  Number(u.outputTokens) +
  Number(u.cacheReadTokens) +
  Number(u.cacheWriteTokens);

/**
 * `ai_chat_usage_daily` (step AI-1 §3, D11): per organization, UTC day, provider and model, and
 * `ai_chat_usage_user_daily` (step AI-6 D1): per organization, UTC day, user, provider, model and
 * key source. Both upserted in the turn's closing transaction; read by the usage routes (replica)
 * and on a Redis miss of the daily token counters (writer). The platform cap is seeded from the
 * user table's `key_source = 'platform'` rows (D6: tenant-key turns do not count).
 */
@Injectable()
export class UsageRepository {
  constructor(
    private readonly writer: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  /** One turn's usage (`turns + 1`), atomically. */
  async add(scope: TenantScope, delta: UsageDelta, tx: Tx): Promise<void> {
    const day = delta.day.toISOString().slice(0, 10);
    await tx.$executeRaw`INSERT INTO ai_chat_usage_daily
        (organization_id, day, provider, model, turns, input_tokens, output_tokens,
         cache_read_tokens, cache_write_tokens, cost_micros, updated_at)
      VALUES (${scope.organizationId}, ${day}, ${delta.provider}, ${delta.model}, 1,
        ${delta.inputTokens}, ${delta.outputTokens}, ${delta.cacheReadTokens},
        ${delta.cacheWriteTokens}, ${delta.costMicros}, NOW(3))
      ON DUPLICATE KEY UPDATE
        turns = turns + 1,
        input_tokens = input_tokens + VALUES(input_tokens),
        output_tokens = output_tokens + VALUES(output_tokens),
        cache_read_tokens = cache_read_tokens + VALUES(cache_read_tokens),
        cache_write_tokens = cache_write_tokens + VALUES(cache_write_tokens),
        cost_micros = cost_micros + VALUES(cost_micros),
        updated_at = NOW(3)`;
    if (delta.user) {
      const cost = delta.user.priced ? delta.costMicros : null;
      await tx.$executeRaw`INSERT INTO ai_chat_usage_user_daily
          (organization_id, day, user_id, provider, model, key_source, turns, input_tokens,
           output_tokens, cache_read_tokens, cache_write_tokens, cost_micros, updated_at)
        VALUES (${scope.organizationId}, ${day}, ${delta.user.userId}, ${delta.provider},
          ${delta.model}, ${delta.user.keySource}, 1, ${delta.inputTokens}, ${delta.outputTokens},
          ${delta.cacheReadTokens}, ${delta.cacheWriteTokens}, ${cost}, NOW(3))
        ON DUPLICATE KEY UPDATE
          turns = turns + 1,
          input_tokens = input_tokens + VALUES(input_tokens),
          output_tokens = output_tokens + VALUES(output_tokens),
          cache_read_tokens = cache_read_tokens + VALUES(cache_read_tokens),
          cache_write_tokens = cache_write_tokens + VALUES(cache_write_tokens),
          cost_micros = CASE WHEN VALUES(cost_micros) IS NULL THEN cost_micros
            ELSE COALESCE(cost_micros, 0) + VALUES(cost_micros) END,
          updated_at = NOW(3)`;
    }
  }

  /** Budget tokens of one user of an organization on a UTC day (writer; step AI-6 D1). */
  async userDayTokens(organizationId: bigint, userId: bigint, day: Date): Promise<number> {
    const sums = await this.writer.aiChatUsageUserDaily.aggregate({
      where: { organizationId, userId, day },
      _sum: {
        inputTokens: true,
        outputTokens: true,
        cacheReadTokens: true,
        cacheWriteTokens: true,
      },
    });
    return budgetTokens({
      inputTokens: sums._sum.inputTokens ?? 0n,
      outputTokens: sums._sum.outputTokens ?? 0n,
      cacheReadTokens: sums._sum.cacheReadTokens ?? 0n,
      cacheWriteTokens: sums._sum.cacheWriteTokens ?? 0n,
    });
  }

  /** Budget tokens of an organization on a UTC day (writer). */
  async tenantDayTokens(organizationId: bigint, day: Date): Promise<number> {
    const rows = await this.writer.aiChatUsageDaily.findMany({
      where: { organizationId, day },
      select: {
        inputTokens: true,
        outputTokens: true,
        cacheReadTokens: true,
        cacheWriteTokens: true,
      },
    });
    return rows.reduce((sum, r) => sum + budgetTokens(r), 0);
  }

  /**
   * Budget tokens of the whole platform on a UTC day (writer): step AI-6 D6, A6-7, turns on the
   * platform's keys only (`ai_chat_usage_user_daily.key_source = 'platform'`, backfilled from the
   * turns by the migration).
   */
  async platformDayTokens(day: Date): Promise<number> {
    const sums = await this.writer.aiChatUsageUserDaily.aggregate({
      where: { day, keySource: 'platform' },
      _sum: {
        inputTokens: true,
        outputTokens: true,
        cacheReadTokens: true,
        cacheWriteTokens: true,
      },
    });
    return budgetTokens({
      inputTokens: sums._sum.inputTokens ?? 0n,
      outputTokens: sums._sum.outputTokens ?? 0n,
      cacheReadTokens: sums._sum.cacheReadTokens ?? 0n,
      cacheWriteTokens: sums._sum.cacheWriteTokens ?? 0n,
    });
  }

  /** Rows of the organization between two UTC days, inclusive (replica). */
  range(scope: TenantScope, from: Date, to: Date): Promise<UsageDayRow[]> {
    return this.reader.client.aiChatUsageDaily.findMany({
      where: { organizationId: scope.organizationId, day: { gte: from, lte: to } },
      orderBy: [{ day: 'asc' }, { provider: 'asc' }, { model: 'asc' }],
      select: {
        day: true,
        provider: true,
        model: true,
        turns: true,
        inputTokens: true,
        outputTokens: true,
        cacheReadTokens: true,
        cacheWriteTokens: true,
        costMicros: true,
      },
    });
  }

  /**
   * Hard delete (execution retention): usage rows before `before`, one batch of each table
   * (`ai_chat_usage_daily`, then `ai_chat_usage_user_daily`, step AI-6).
   */
  async deleteBefore(before: Date, batch: number): Promise<number> {
    const day = before.toISOString().slice(0, 10);
    const tenant = await this.writer.$executeRaw`DELETE FROM ai_chat_usage_daily
      WHERE day < ${day} ORDER BY day LIMIT ${batch}`;
    const users = await this.writer.$executeRaw`DELETE FROM ai_chat_usage_user_daily
      WHERE day < ${day} ORDER BY day LIMIT ${batch}`;
    return Math.max(tenant, users);
  }
}
