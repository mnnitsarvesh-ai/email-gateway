import { BadRequestException, Injectable } from '@nestjs/common';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { type Page, pageWindow, toPage } from '../../http/pagination';
import { formatId } from '../../http/serialization';
import { UsersRepository } from '../users/users.repository';
import { type LoginEventRecord, LoginEventsRepository } from './login-events.repository';
import type { LoginEventsQuery, LoginEventView } from './login-events.schemas';

const DAY_MS = 24 * 60 * 60 * 1000;
export const LOGIN_EVENTS_DEFAULT_DAYS = 7;
export const LOGIN_EVENTS_MAX_DAYS = 90;

/** The `[from, to)` window: defaults to the last 7 days, at most 90 days, `from < to`. */
export function loginEventsWindow(
  query: Pick<LoginEventsQuery, 'from' | 'to'>,
  now: Date,
): { from: Date; to: Date } {
  const to = query.to !== undefined ? new Date(query.to) : now;
  const from =
    query.from !== undefined
      ? new Date(query.from)
      : new Date(to.getTime() - LOGIN_EVENTS_DEFAULT_DAYS * DAY_MS);
  if (from.getTime() >= to.getTime()) throw new BadRequestException(['from: must be before to']);
  if (to.getTime() - from.getTime() > LOGIN_EVENTS_MAX_DAYS * DAY_MS) {
    throw new BadRequestException([`from: the window is at most ${LOGIN_EVENTS_MAX_DAYS} days`]);
  }
  return { from, to };
}

export function toLoginEventView(
  row: LoginEventRecord,
  userPublicIds: ReadonlyMap<bigint, string>,
): LoginEventView {
  return {
    id: formatId(row.id),
    occurredAt: row.createdAt.toISOString(),
    email: row.emailAttempted,
    outcome: row.outcome,
    failureReason: row.failureReason,
    ipAddress: row.ipAddress,
    userAgent: row.userAgent,
    userId: row.userId === null ? null : (userPublicIds.get(row.userId) ?? null),
  };
}

/** Login attempts of the scope organization (D6 rows, §4.2), from the replica. */
@Injectable()
export class LoginEventsService {
  constructor(
    private readonly events: LoginEventsRepository,
    private readonly users: UsersRepository,
  ) {}

  async list(
    scope: TenantScope,
    query: LoginEventsQuery,
    now: Date = new Date(),
  ): Promise<Page<LoginEventView>> {
    const window = loginEventsWindow(query, now);
    let userId: bigint | undefined;
    if (query.userId !== undefined) {
      const id = await this.users.findIdByPublicId(scope, query.userId);
      // A user of another organization (or none) matches nothing in this organization.
      if (id === null) return { data: [], nextCursor: null };
      userId = id;
    }
    const rows = await this.events.list(
      scope,
      {
        ...window,
        ...(query.outcome && { outcome: query.outcome }),
        ...(userId !== undefined && { userId }),
      },
      pageWindow(query),
    );
    const userIds = [...new Set(rows.flatMap((r) => (r.userId === null ? [] : [r.userId])))];
    const publicIds = await this.users.publicIds(scope, userIds);
    return toPage(rows, query.limit, (row) => toLoginEventView(row, publicIds));
  }
}
