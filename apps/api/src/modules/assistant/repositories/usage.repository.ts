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
 * `ai_chat_usage_daily` (step AI-1 §3, D11): per organization, UTC day, provider and model.
 * Upserted in the turn's closing transaction; read by the usage route (replica) and on a Redis
 * miss of the daily token counters (writer).
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

  /** Budget tokens of the whole platform on a UTC day (writer). */
  async platformDayTokens(day: Date): Promise<number> {
    const sums = await this.writer.aiChatUsageDaily.aggregate({
      where: { day },
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

  /** Hard delete (execution retention): usage rows before `before`, one batch. */
  deleteBefore(before: Date, batch: number): Promise<number> {
    const day = before.toISOString().slice(0, 10);
    return this.writer.$executeRaw`DELETE FROM ai_chat_usage_daily
      WHERE day < ${day} ORDER BY day LIMIT ${batch}`;
  }
}
