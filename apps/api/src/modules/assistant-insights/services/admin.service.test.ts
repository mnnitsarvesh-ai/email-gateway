import { randomBytes } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { scopeFromPrincipal, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import { FeedbackListQuerySchema, UsageByUserQuerySchema } from '../dto/insights.schemas';
import type {
  AdminFeedbackRow,
  FeedbackListFilter,
  FeedbackRepository,
} from '../repositories/feedback.repository';
import type { IdentityRepository, IdentityRow } from '../repositories/identity.repository';
import type {
  UserDayUsageRow,
  UserUsageCursor,
  UserUsageFilter,
  UserUsageRepository,
} from '../repositories/user-usage.repository';
import { AssistantAdminService } from './admin.service';

const ORG = 7001n;
const admin: UserPrincipal = {
  kind: 'user',
  userId: 500n,
  userPublicId: '0193b000-0000-7000-8000-000000000500',
  organizationId: ORG,
  organizationPublicId: '0193b000-0000-7000-8000-000000007001',
  organizationKind: 'customer',
  sessionId: '0193b000-0000-7000-8000-0000000000aa',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['assistant:configure']),
};
const scope = scopeFromPrincipal(admin);
const NOW = new Date('2026-11-26T12:00:00.000Z');
const DANA = '0193b000-0000-7000-8000-000000000501';

const sums = (turns: number, priced = true) => ({
  turns,
  inputTokens: turns * 100,
  outputTokens: turns * 10,
  cacheReadTokens: 0,
  cacheWriteTokens: 0,
  costMicros: priced ? turns * 7 : 0,
  pricedRows: priced ? 1 : 0,
});

function usageRow(day: string, userId: bigint, keySource: 'platform' | 'tenant', turns: number) {
  return {
    organizationId: ORG,
    day: new Date(`${day}T00:00:00.000Z`),
    userId,
    keySource,
    ...sums(turns, keySource === 'platform'),
  } satisfies UserDayUsageRow;
}

const order = (a: UserDayUsageRow, b: UserDayUsageRow) =>
  b.day.getTime() - a.day.getTime() ||
  Number(a.userId - b.userId) ||
  a.keySource.localeCompare(b.keySource);

function harness() {
  const rows: UserDayUsageRow[] = [
    usageRow('2026-11-25', 501n, 'platform', 3),
    usageRow('2026-11-25', 501n, 'tenant', 1),
    usageRow('2026-11-25', 502n, 'platform', 2),
    usageRow('2026-11-24', 501n, 'platform', 4),
    usageRow('2026-11-20', 9n, 'platform', 1),
  ].sort(order);
  const usageCalls: Array<{ scope: TenantScope; filter: UserUsageFilter }> = [];
  const usage = {
    page: vi.fn(
      (
        s: TenantScope,
        filter: UserUsageFilter,
        after: UserUsageCursor | undefined,
        take: number,
      ) => {
        usageCalls.push({ scope: s, filter });
        const cursor = after
          ? { ...usageRow('2000-01-01', after.userId, after.keySource, 0), day: after.day }
          : null;
        return Promise.resolve(
          rows
            .filter((r) => filter.userId === undefined || r.userId === filter.userId)
            .filter((r) => cursor === null || order(cursor, r) < 0)
            .slice(0, take),
        );
      },
    ),
    totalsOfUsers: vi.fn((_s: TenantScope, _f: UserUsageFilter, ids: readonly bigint[]) =>
      Promise.resolve(ids.map((userId) => ({ organizationId: ORG, userId, ...sums(5) }))),
    ),
    overall: vi.fn(() => Promise.resolve(sums(11))),
  };
  const users = new Map<bigint, IdentityRow>([
    [
      501n,
      {
        id: 501n,
        publicId: DANA,
        organizationId: ORG,
        displayName: 'Dana',
        email: 'dana@example.com',
      },
    ],
    [
      502n,
      {
        id: 502n,
        publicId: 'u-502',
        organizationId: ORG,
        displayName: 'Lee',
        email: 'lee@example.com',
      },
    ],
    [
      9n,
      { id: 9n, publicId: 'u-ops', organizationId: 1n, displayName: 'Op', email: 'op@example.com' },
    ],
  ]);
  const identities = {
    byIds: vi.fn((ids: readonly bigint[]) =>
      Promise.resolve(new Map(ids.flatMap((id) => (users.has(id) ? [[id, users.get(id)!]] : [])))),
    ),
    idOfFilter: vi.fn((_s: TenantScope, publicId: string) =>
      Promise.resolve(publicId === DANA ? 501n : null),
    ),
  };
  const feedbackRows: AdminFeedbackRow[] = [1, 2, 3].map((i) => ({
    id: BigInt(i),
    publicId: `f-${i}`,
    organizationId: ORG,
    userId: 501n,
    conversationId: 10n,
    turnId: BigInt(20 + i),
    messageId: BigInt(30 + i),
    rating: i === 2 ? 'down' : 'up',
    reason: i === 2 ? 'incorrect' : null,
    comment: i === 2 ? 'Wrong count' : null,
    createdAt: new Date(NOW.getTime() - i * 60_000),
    updatedAt: new Date(NOW.getTime() - i * 60_000),
    messagePublicId: `m-${i}`,
    conversationPublicId: 'c-10',
  }));
  const feedbackCalls: FeedbackListFilter[] = [];
  const feedback = {
    adminList: vi.fn((_s: TenantScope, f: FeedbackListFilter) => {
      feedbackCalls.push(f);
      return Promise.resolve(
        feedbackRows.filter((r) => !f.after || r.createdAt < f.after.createdAt).slice(0, f.take),
      );
    }),
    turnsMeta: vi.fn(() =>
      Promise.resolve(
        new Map([
          [
            22n,
            {
              id: 22n,
              organizationId: ORG,
              provider: 'fake',
              model: 'fake-1',
              promptVersion: 'assistant-system/7',
              dataSharing: 'pseudonymized' as const,
            },
          ],
        ]),
      ),
    ),
    toolsOfTurns: vi.fn(() => Promise.resolve(new Map([[22n, ['policy_management_list']]]))),
  };
  const service = new AssistantAdminService(
    usage as unknown as UserUsageRepository,
    feedback as unknown as FeedbackRepository,
    identities as unknown as IdentityRepository,
    new CursorCodec({
      API_CURSOR_KEY: randomBytes(32).toString('hex'),
      API_CURSOR_KEY_PREVIOUS: undefined,
      API_CURSOR_TTL_SECONDS: 86_400,
    }),
  );
  service.now = () => NOW;
  return { service, usage, usageCalls, identities, feedback, feedbackCalls };
}

const uq = (raw: Record<string, string>) => UsageByUserQuerySchema.parse(raw);
const fq = (raw: Record<string, string>) => FeedbackListQuerySchema.parse(raw);

describe('AssistantAdminService.usageByUser (D1)', () => {
  it('pages rows per day, user and key source with a cursor round trip', async () => {
    const h = harness();
    const first = await h.service.usageByUser(admin, scope, uq({ limit: '2' }));
    expect(first.from).toBe('2026-10-28');
    expect(first.to).toBe('2026-11-26');
    expect(first.data.map((r) => [r.day, r.user.id, r.keySource])).toEqual([
      ['2026-11-25', DANA, 'platform'],
      ['2026-11-25', DANA, 'tenant'],
    ]);
    expect(first.data[1]).toMatchObject({ turns: 1, totalTokens: 110, estimatedCostMicros: null });
    expect(first.totals.users).toEqual([
      expect.objectContaining({ user: expect.objectContaining({ id: DANA }), turns: 5 }),
    ]);
    expect(first.totals.overall).toMatchObject({ turns: 11, estimatedCostMicros: 77 });
    const second = await h.service.usageByUser(
      admin,
      scope,
      uq({ limit: '2', cursor: first.nextCursor! }),
    );
    expect(second.data.map((r) => [r.day, r.user.id])).toEqual([
      ['2026-11-25', 'u-502'],
      ['2026-11-24', DANA],
    ]);
    const third = await h.service.usageByUser(
      admin,
      scope,
      uq({ limit: '2', cursor: second.nextCursor! }),
    );
    // A platform operator's override use: public id only.
    expect(third.data).toEqual([
      expect.objectContaining({ user: { id: 'u-ops', displayName: null, email: null } }),
    ]);
    expect(third.nextCursor).toBeNull();
    // The cursor is bound to the window and filters.
    await expect(
      h.service.usageByUser(admin, scope, uq({ from: '2026-11-01', cursor: first.nextCursor! })),
    ).rejects.toMatchObject({ code: 'cursor_invalid' });
  });

  it('reads the scope’s organization only and resolves the user filter', async () => {
    const h = harness();
    const page = await h.service.usageByUser(admin, scope, uq({ userId: DANA }));
    expect(page.data.every((r) => r.user.id === DANA)).toBe(true);
    expect(h.usageCalls[0]!.scope.organizationId).toBe(ORG);
    expect(h.usageCalls[0]!.filter.userId).toBe(501n);
    const unknown = await h.service.usageByUser(
      admin,
      scope,
      uq({ userId: '0193b000-0000-7000-8000-000000009999' }),
    );
    expect(unknown).toMatchObject({ data: [], nextCursor: null, totals: { users: [] } });
    expect(h.usage.page).toHaveBeenCalledTimes(1);
  });

  it('refuses a window longer than 92 days and unknown parameters', async () => {
    const h = harness();
    await expect(
      h.service.usageByUser(admin, scope, uq({ from: '2026-01-01', to: '2026-11-26' })),
    ).rejects.toMatchObject({ status: 400 });
    expect(UsageByUserQuerySchema.safeParse({ organizationId: '1' }).success).toBe(false);
    expect(UsageByUserQuerySchema.safeParse({ from: '2026-13-01' }).success).toBe(false);
  });
});

describe('AssistantAdminService.feedbackList (D2)', () => {
  it('lists newest first with the turn metadata, tools and comment, cursor round trip', async () => {
    const h = harness();
    const first = await h.service.feedbackList(admin, scope, fq({ limit: '2' }));
    expect(first.data.map((d) => d.id)).toEqual(['f-1', 'f-2']);
    expect(first.data[1]).toMatchObject({
      rating: 'down',
      reason: 'incorrect',
      comment: 'Wrong count',
      messageId: 'm-2',
      conversationId: 'c-10',
      user: { id: DANA, displayName: 'Dana', email: 'dana@example.com' },
      turn: {
        provider: 'fake',
        model: 'fake-1',
        promptVersion: 'assistant-system/7',
        dataSharing: 'pseudonymized',
      },
      tools: ['policy_management_list'],
    });
    expect(first.data[0]).toMatchObject({ turn: null, tools: [] });
    expect(h.feedbackCalls[0]!.to).toEqual(NOW);
    expect(NOW.getTime() - h.feedbackCalls[0]!.from.getTime()).toBe(30 * 86_400_000);
    const second = await h.service.feedbackList(
      admin,
      scope,
      fq({ limit: '2', cursor: first.nextCursor! }),
    );
    expect(second.data.map((d) => d.id)).toEqual(['f-3']);
    // Later pages keep the first page's window.
    expect(h.feedbackCalls[1]!.to).toEqual(NOW);
    await expect(
      h.service.feedbackList(admin, scope, fq({ rating: 'up', cursor: first.nextCursor! })),
    ).rejects.toMatchObject({ code: 'cursor_invalid' });
  });

  it('passes the filters through and refuses more than 92 days', async () => {
    const h = harness();
    await h.service.feedbackList(
      admin,
      scope,
      fq({ rating: 'down', reason: 'unsafe,other', userId: DANA }),
    );
    expect(h.feedbackCalls[0]).toMatchObject({
      rating: 'down',
      reasons: ['unsafe', 'other'],
      userId: 501n,
    });
    await expect(
      h.service.feedbackList(admin, scope, fq({ from: '2026-01-01T00:00:00Z' })),
    ).rejects.toMatchObject({ status: 400 });
  });
});
