import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho, InconsistentReadError } from '../../../http/listing/echo-check';
import type { DayWindow } from '../domain/window';

export type KeySource = 'platform' | 'tenant';
export const KEY_SOURCES: readonly KeySource[] = ['platform', 'tenant'];

/** Sums of usage rows (any grouping); `pricedRows` counts the rows with a known cost. */
export interface UsageSums {
  turns: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  costMicros: number;
  pricedRows: number;
}

export interface UserDayUsageRow extends UsageSums {
  organizationId: bigint;
  day: Date;
  userId: bigint;
  keySource: KeySource;
}

export interface UserUsageTotalRow extends UsageSums {
  organizationId: bigint;
  userId: bigint;
}

export interface UserUsageFilter {
  window: DayWindow;
  userId?: bigint;
}

export interface UserUsageCursor {
  day: Date;
  userId: bigint;
  keySource: KeySource;
}

type RawSums = {
  turns: unknown;
  inputTokens: unknown;
  outputTokens: unknown;
  cacheReadTokens: unknown;
  cacheWriteTokens: unknown;
  costMicros: unknown;
  pricedRows: unknown;
};

/** A non-negative integer from a SUM/COUNT column (DECIMAL, BIGINT or null for an empty SUM). */
function integer(value: unknown, read: string): number {
  if (value === null || value === undefined) return 0;
  let n = Number.NaN;
  if (typeof value === 'bigint' || typeof value === 'number') n = Number(value);
  else if (typeof value === 'string') n = Number(value);
  // SUM over BIGINT columns is a DECIMAL (Prisma.Decimal).
  else if (Prisma.Decimal.isDecimal(value)) n = value.toNumber();
  if (!Number.isSafeInteger(n) || n < 0) throw new InconsistentReadError(read);
  return n;
}

function sumsOf(raw: RawSums, read: string): UsageSums {
  return {
    turns: integer(raw.turns, read),
    inputTokens: integer(raw.inputTokens, read),
    outputTokens: integer(raw.outputTokens, read),
    cacheReadTokens: integer(raw.cacheReadTokens, read),
    cacheWriteTokens: integer(raw.cacheWriteTokens, read),
    costMicros: integer(raw.costMicros, read),
    pricedRows: integer(raw.pricedRows, read),
  };
}

const SUMS = Prisma.sql`SUM(turns) AS turns, SUM(input_tokens) AS inputTokens,
  SUM(output_tokens) AS outputTokens, SUM(cache_read_tokens) AS cacheReadTokens,
  SUM(cache_write_tokens) AS cacheWriteTokens, SUM(cost_micros) AS costMicros,
  COUNT(cost_micros) AS pricedRows`;

const dayParam = (date: Date): string => date.toISOString().slice(0, 10);

/**
 * `ai_chat_usage_user_daily` (step AI-6 §3, D1) for the administration page, on the replica. Rows
 * are summed per UTC day, user and key source (over providers and models); the window is a
 * range of the primary key `(organization_id, day, …)`, with a user the index
 * `(organization_id, user_id, day)`. Organization from the scope only; every row is echo-checked.
 */
@Injectable()
export class UserUsageRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private where(scope: TenantScope, filter: UserUsageFilter): Prisma.Sql {
    return Prisma.sql`organization_id = ${scope.organizationId}
      AND day >= ${dayParam(filter.window.from)} AND day <= ${dayParam(filter.window.to)}
      ${filter.userId === undefined ? Prisma.empty : Prisma.sql`AND user_id = ${filter.userId}`}`;
  }

  /** Newest day first, then user id and key source ascending; keyset after `after`. */
  async page(
    scope: TenantScope,
    filter: UserUsageFilter,
    after: UserUsageCursor | undefined,
    take: number,
  ): Promise<UserDayUsageRow[]> {
    const keyset = after
      ? Prisma.sql`AND (day < ${dayParam(after.day)}
          OR (day = ${dayParam(after.day)} AND user_id > ${after.userId})
          OR (day = ${dayParam(after.day)} AND user_id = ${after.userId}
            AND CAST(key_source AS CHAR) > ${after.keySource}))`
      : Prisma.empty;
    const raw = await this.reader.client.$queryRaw<
      Array<RawSums & { organizationId: unknown; day: Date; userId: unknown; keySource: string }>
    >(Prisma.sql`SELECT organization_id AS organizationId, day, user_id AS userId,
        CAST(key_source AS CHAR) AS keySource, ${SUMS}
      FROM ai_chat_usage_user_daily
      WHERE ${this.where(scope, filter)} ${keyset}
      GROUP BY organization_id, day, user_id, key_source
      ORDER BY day DESC, user_id ASC, CAST(key_source AS CHAR) ASC
      LIMIT ${take}`);
    const rows = raw.map((r): UserDayUsageRow => {
      if (!(KEY_SOURCES as readonly string[]).includes(r.keySource)) {
        throw new InconsistentReadError('assistant.usage_users');
      }
      const day = new Date(r.day);
      if (
        day.getTime() < filter.window.from.getTime() ||
        day.getTime() > filter.window.to.getTime()
      ) {
        throw new InconsistentReadError('assistant.usage_users');
      }
      return {
        organizationId: BigInt(String(r.organizationId)),
        day,
        userId: BigInt(String(r.userId)),
        keySource: r.keySource as KeySource,
        ...sumsOf(r, 'assistant.usage_users'),
      };
    });
    assertEcho('assistant.usage_users', rows, {
      organizationId: scope.organizationId,
      ...(filter.userId !== undefined && { userId: filter.userId }),
    });
    return rows;
  }

  /** Totals over the whole window of the given users. */
  async totalsOfUsers(
    scope: TenantScope,
    filter: UserUsageFilter,
    userIds: readonly bigint[],
  ): Promise<UserUsageTotalRow[]> {
    const ids = [...new Set(userIds)];
    if (ids.length === 0) return [];
    const raw = await this.reader.client.$queryRaw<
      Array<RawSums & { organizationId: unknown; userId: unknown }>
    >(Prisma.sql`SELECT organization_id AS organizationId, user_id AS userId, ${SUMS}
      FROM ai_chat_usage_user_daily
      WHERE ${this.where(scope, filter)} AND user_id IN (${Prisma.join(ids)})
      GROUP BY organization_id, user_id
      ORDER BY user_id ASC`);
    const rows = raw.map((r): UserUsageTotalRow => ({
      organizationId: BigInt(String(r.organizationId)),
      userId: BigInt(String(r.userId)),
      ...sumsOf(r, 'assistant.usage_users_totals'),
    }));
    assertEcho('assistant.usage_users_totals', rows, {
      organizationId: scope.organizationId,
      userId: ids,
    });
    return rows;
  }

  /** Totals over the whole window (and the user filter). */
  async overall(scope: TenantScope, filter: UserUsageFilter): Promise<UsageSums> {
    const raw = await this.reader.client.$queryRaw<RawSums[]>(Prisma.sql`SELECT ${SUMS}
      FROM ai_chat_usage_user_daily WHERE ${this.where(scope, filter)}`);
    return sumsOf(
      raw[0] ?? {
        turns: 0,
        inputTokens: 0,
        outputTokens: 0,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        costMicros: 0,
        pricedRows: 0,
      },
      'assistant.usage_users_overall',
    );
  }
}
