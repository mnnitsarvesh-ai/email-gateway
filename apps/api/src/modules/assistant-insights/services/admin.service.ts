import { Injectable } from '@nestjs/common';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CursorCodec, cursorInvalid } from '../../../http/cursor/cursor-codec';
import { rangeWindow } from '../../../http/listing/range';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  instantKey,
  listBinding,
} from '../../messages/domain/v1-list';
import { identityOf, usageFigures } from '../domain/views';
import { dayString, resolveDayWindow, resolveInstantWindow } from '../domain/window';
import type {
  AdminFeedbackPage,
  FeedbackListQuery,
  UsageByUserQuery,
  UserUsagePage,
} from '../dto/insights.schemas';
import { CURSOR_RESOURCES } from '../insights.constants';
import { type AdminFeedbackRow, FeedbackRepository } from '../repositories/feedback.repository';
import { IdentityRepository } from '../repositories/identity.repository';
import {
  KEY_SOURCES,
  type KeySource,
  type UserDayUsageRow,
  UserUsageRepository,
} from '../repositories/user-usage.repository';

const DAY_KEY = /^\d{4}-\d{2}-\d{2}$/;
const EMPTY_SUMS = {
  turns: 0,
  inputTokens: 0,
  outputTokens: 0,
  cacheReadTokens: 0,
  cacheWriteTokens: 0,
  costMicros: 0,
  pricedRows: 0,
};

/** A `YYYY-MM-DD` keyset value of a verified cursor. */
function dayKey(value: string | undefined): Date {
  if (value === undefined || !DAY_KEY.test(value)) throw cursorInvalid();
  const date = new Date(`${value}T00:00:00.000Z`);
  if (Number.isNaN(date.getTime()) || dayString(date) !== value) throw cursorInvalid();
  return date;
}

function keySourceKey(value: string | undefined): KeySource {
  if (value === undefined || !(KEY_SOURCES as readonly string[]).includes(value)) {
    throw cursorInvalid();
  }
  return value as KeySource;
}

/**
 * The tenant AI administration reads (step AI-6 D1, D2; `assistant:configure`): usage and
 * estimated cost per user and UTC day, and the users' feedback with the answered turn's metadata.
 * Organization from the scope only (never from input); the `userId` filter is a public id that is
 * resolved and then combined with the organization filter, so it never widens a read. Replica
 * reads; v1 cursors.
 */
@Injectable()
export class AssistantAdminService {
  constructor(
    private readonly usage: UserUsageRepository,
    private readonly feedback: FeedbackRepository,
    private readonly identities: IdentityRepository,
    private readonly codec: CursorCodec,
  ) {}

  now(): Date {
    return new Date();
  }

  async usageByUser(
    principal: UserPrincipal,
    scope: TenantScope,
    query: UsageByUserQuery,
  ): Promise<UserUsagePage> {
    const window = resolveDayWindow(query, this.now());
    const binding = listBinding({
      resource: CURSOR_RESOURCES.usageByUser,
      principal,
      filters: {
        from: { values: [dayString(window.from)] },
        to: { values: [dayString(window.to)] },
        ...(query.userId !== undefined && { userId: { values: [query.userId] } }),
      },
      sort: '-day',
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 3);
    const empty: UserUsagePage = {
      from: dayString(window.from),
      to: dayString(window.to),
      data: [],
      totals: { users: [], overall: usageFigures(EMPTY_SUMS) },
      nextCursor: null,
    };
    let userId: bigint | undefined;
    if (query.userId !== undefined) {
      const resolved = await this.identities.idOfFilter(scope, query.userId);
      if (resolved === null) return empty;
      userId = resolved;
    }
    const filter = { window, ...(userId !== undefined && { userId }) };
    const fetched = await this.usage.page(
      scope,
      filter,
      decoded && {
        day: dayKey(decoded.keys[0]),
        userId: decimalKey(decoded.keys[1]),
        keySource: keySourceKey(decoded.keys[2]),
      },
      query.limit + 1,
    );
    const decision = decideKeysetPage({
      fetched,
      limit: query.limit,
      keyOf: (row: UserDayUsageRow) => [dayString(row.day), row.userId.toString(), row.keySource],
    });
    const rows = fetched.slice(0, decision.rows);
    const userIds = [...new Set(rows.map((r) => r.userId))];
    const [totals, overall, users] = await Promise.all([
      this.usage.totalsOfUsers(scope, filter, userIds),
      this.usage.overall(scope, filter),
      this.identities.byIds(userIds),
    ]);
    const org = scope.organizationId;
    return {
      ...empty,
      data: rows.map((r) => ({
        day: dayString(r.day),
        user: identityOf(r.userId, users, org),
        keySource: r.keySource,
        ...usageFigures(r),
      })),
      totals: {
        users: totals.map((t) => ({ user: identityOf(t.userId, users, org), ...usageFigures(t) })),
        overall: usageFigures(overall),
      },
      nextCursor:
        decision.next === null ? null : encodeListCursor(this.codec, binding, decision.next),
    };
  }

  async feedbackList(
    principal: UserPrincipal,
    scope: TenantScope,
    query: FeedbackListQuery,
  ): Promise<AdminFeedbackPage> {
    const binding = listBinding({
      resource: CURSOR_RESOURCES.feedback,
      principal,
      filters: {
        ...query.filters,
        ...(query.from !== undefined && { from: { values: [query.from] } }),
        ...(query.to !== undefined && { to: { values: [query.to] } }),
      },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const range = resolveInstantWindow(query, this.now(), decoded?.window);
    const userPublicId = query.filters.userId?.values?.[0];
    let userId: bigint | undefined;
    if (userPublicId !== undefined) {
      const resolved = await this.identities.idOfFilter(scope, userPublicId);
      if (resolved === null) return { data: [], nextCursor: null };
      userId = resolved;
    }
    const fetched = await this.feedback.adminList(scope, {
      from: range.from,
      to: range.to,
      ...(query.filters.rating?.values?.[0] !== undefined && {
        rating: query.filters.rating.values[0],
      }),
      ...(query.filters.reason?.values !== undefined && { reasons: query.filters.reason.values }),
      ...(userId !== undefined && { userId }),
      ...(decoded && {
        after: { createdAt: instantKey(decoded.keys[0]), id: decimalKey(decoded.keys[1]) },
      }),
      take: query.limit + 1,
    });
    const decision = decideKeysetPage({
      fetched,
      limit: query.limit,
      keyOf: (row: AdminFeedbackRow) => [row.createdAt.toISOString(), row.id.toString()],
    });
    const rows = fetched.slice(0, decision.rows);
    const turnIds = rows.map((r) => r.turnId);
    const [turns, tools, users] = await Promise.all([
      this.feedback.turnsMeta(scope, turnIds),
      this.feedback.toolsOfTurns(scope, turnIds),
      this.identities.byIds(rows.map((r) => r.userId)),
    ]);
    return {
      data: rows.map((row) => {
        const turn = turns.get(row.turnId);
        return {
          id: row.publicId,
          conversationId: row.conversationPublicId,
          messageId: row.messagePublicId,
          user: identityOf(row.userId, users, scope.organizationId),
          rating: row.rating,
          reason: row.reason,
          comment: row.comment,
          createdAt: row.createdAt.toISOString(),
          updatedAt: row.updatedAt.toISOString(),
          turn: turn
            ? {
                provider: turn.provider,
                model: turn.model,
                promptVersion: turn.promptVersion,
                dataSharing: turn.dataSharing,
              }
            : null,
          tools: tools.get(row.turnId) ?? [],
        };
      }),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, decision.next, rangeWindow(range)),
    };
  }
}
