import { describe, expect, it, vi } from 'vitest';
import { InconsistentNotificationReadError, type NoticeUser } from './notification-reads';
import { PreferenceFilter } from './preference-filter';

type Row = { organizationId: bigint; userId: bigint; preferences: unknown };

function fixture(rows: Row[]) {
  const findMany = vi.fn((args: { where: { organizationId: bigint; userId: { in: bigint[] } } }) =>
    Promise.resolve(
      rows.filter(
        (r) =>
          r.organizationId === args.where.organizationId && args.where.userId.in.includes(r.userId),
      ),
    ),
  );
  const tx = { notificationUserPreference: { findMany } } as never;
  const suppressed: Array<[Record<string, string>, number]> = [];
  const warn = vi.fn();
  const filter = new PreferenceFilter(
    {
      alertsSuppressed: {
        inc: (labels: Record<string, string>, n: number) => suppressed.push([labels, n]),
      },
    } as never,
    { warn } as never,
  );
  return { tx, findMany, filter, suppressed, warn };
}

const users: NoticeUser[] = Array.from({ length: 7 }, (_, i) => ({
  id: BigInt(i + 1),
  email: `u${String(i + 1)}@acme.example`,
}));
const pages = vi.fn((afterId: bigint | null, take: number) =>
  Promise.resolve(users.filter((u) => afterId === null || u.id > afterId).slice(0, take)),
);

describe('PreferenceFilter (step 6.2 N4)', () => {
  it('drops opted-out users before the cap, paging by user id, and counts them', async () => {
    const f = fixture([
      { organizationId: 7n, userId: 1n, preferences: { optOut: ['policy_alert'] } },
      {
        organizationId: 7n,
        userId: 2n,
        preferences: { optOut: ['policy_alert', 'threat_detected'] },
      },
      { organizationId: 7n, userId: 3n, preferences: { optOut: ['threat_detected'] } },
      { organizationId: 7n, userId: 5n, preferences: { optOut: ['policy_alert'] } },
    ]);
    pages.mockClear();
    const result = await f.filter.collect(f.tx, 7n, 'policy_alert', pages, 3);
    expect(result).toEqual({
      emails: ['u3@acme.example', 'u4@acme.example', 'u6@acme.example'],
      optedOut: 3,
    });
    expect(pages.mock.calls).toEqual([
      [null, 3],
      [3n, 3],
    ]);
    expect(f.suppressed).toEqual([[{ kind: 'policy_alert', reason: 'opt_out' }, 3]]);
  });

  it('stops at the end of the candidates; counts nothing when nobody opted out', async () => {
    const f = fixture([]);
    const result = await f.filter.collect(f.tx, 7n, 'quarantine_admin_alert', pages, 50);
    expect(result.emails).toHaveLength(7);
    expect(result.optedOut).toBe(0);
    expect(f.suppressed).toEqual([]);
    const empty = await f.filter.collect(f.tx, 7n, 'policy_alert', () => Promise.resolve([]), 5);
    expect(empty).toEqual({ emails: [], optedOut: 0 });
  });

  it('an invalid stored document opts out of nothing (logged without values)', async () => {
    const f = fixture([{ organizationId: 7n, userId: 1n, preferences: { optOut: ['bogus'] } }]);
    const out = await f.filter.optedOut(f.tx, 7n, [1n], 'policy_alert');
    expect(out.size).toBe(0);
    expect(f.warn).toHaveBeenCalledOnce();
    expect(JSON.stringify(f.warn.mock.calls)).not.toContain('bogus');
  });

  it('reads only the organization’s rows and rejects an inconsistent row', async () => {
    const f = fixture([
      { organizationId: 8n, userId: 1n, preferences: { optOut: ['policy_alert'] } },
    ]);
    expect((await f.filter.optedOut(f.tx, 7n, [1n], 'policy_alert')).size).toBe(0);
    expect(f.findMany.mock.calls[0]![0].where.organizationId).toBe(7n);
    const lying = {
      notificationUserPreference: {
        findMany: () =>
          Promise.resolve([{ organizationId: 8n, userId: 1n, preferences: { optOut: [] } }]),
      },
    } as never;
    await expect(f.filter.optedOut(lying, 7n, [1n], 'policy_alert')).rejects.toBeInstanceOf(
      InconsistentNotificationReadError,
    );
    expect((await f.filter.optedOut(f.tx, 7n, [], 'policy_alert')).size).toBe(0);
  });
});
