import { http, HttpResponse } from 'msw';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { TEST_ORIGIN, server } from '@/test';
import {
  PROACTIVE_LEAD_MS,
  PROACTIVE_MIN_DELAY_MS,
  proactiveDelay,
  refreshSession,
  resetRefreshCoordinatorForTests,
  scheduleProactiveRefresh,
} from './refresh';
import { onSessionEvent } from './events';
import {
  REFRESH_LOCK,
  endOverride,
  logout,
  startOverride,
  withSessionLock,
} from './session-client';

const NOW = Date.UTC(2026, 10, 13, 12, 0, 0);
const state = (accessExpiresAt: string) => ({
  authenticated: true,
  accessExpiresAt,
  refreshExpiresAt: new Date(NOW + 7 * 86_400_000).toISOString(),
  mfaEnrollmentRequired: false,
  override: null,
  devFixtures: false,
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  resetRefreshCoordinatorForTests();
});

describe('proactive refresh delay (design P4; step 7.1 WP6 fix)', () => {
  it('refreshes PROACTIVE_LEAD_MS before expiry for the default 600 s token', () => {
    expect(proactiveDelay(NOW + 600_000, NOW)).toBe(600_000 - PROACTIVE_LEAD_MS);
  });

  it('waits half the lifetime for short tokens instead of refreshing at once (no loop at TTL 60 s)', () => {
    expect(proactiveDelay(NOW + 60_000, NOW)).toBe(30_000);
    expect(proactiveDelay(NOW + 90_000, NOW)).toBe(45_000);
  });

  it('never schedules sooner than the minimum, even for an expired token', () => {
    expect(proactiveDelay(NOW + 1_000, NOW)).toBe(PROACTIVE_MIN_DELAY_MS);
    expect(proactiveDelay(NOW - 5_000, NOW)).toBe(PROACTIVE_MIN_DELAY_MS);
  });

  it('with a 60 s token, refreshes about twice a minute, not continuously', async () => {
    vi.useFakeTimers({ now: NOW, toFake: ['setTimeout', 'clearTimeout', 'Date'] });
    let calls = 0;
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/refresh`, () => {
        calls += 1;
        return HttpResponse.json(state(new Date(Date.now() + 60_000).toISOString()));
      }),
    );
    const refreshed: string[] = [];
    const stop = scheduleProactiveRefresh(
      () => new Date(NOW + 60_000).toISOString(),
      (s) => refreshed.push(s.accessExpiresAt!),
    );
    for (let i = 0; i < 12; i++) await vi.advanceTimersByTimeAsync(5_000);
    stop();
    // 60 s of wall time: refreshes at ~30 s and ~60 s.
    expect(calls).toBeGreaterThanOrEqual(1);
    expect(calls).toBeLessThanOrEqual(2);
    expect(refreshed).toHaveLength(calls);
  });
});

/** A Web Locks stand-in that runs callbacks of one name strictly one after the other. */
function stubLocks() {
  const held = new Map<string, Promise<unknown>>();
  vi.stubGlobal('navigator', {
    locks: {
      request<T>(name: string, fn: () => Promise<T>): Promise<T> {
        const previous = held.get(name) ?? Promise.resolve();
        const next = previous.then(fn);
        held.set(
          name,
          next.catch(() => undefined),
        );
        return next;
      },
    },
  });
}

/** Holds the session lock (as a refresh in another tab would) until `release` is called. */
function holdLock(order: string[]) {
  let release: () => void = () => undefined;
  const done = withSessionLock(
    () =>
      new Promise<void>((resolve) => {
        order.push('refresh-start');
        release = () => {
          order.push('refresh-end');
          resolve();
        };
      }),
  );
  return { done, release: () => release() };
}

describe('sign-out and refresh share one lock', () => {
  it('logout waits for the lock held by a refresh in another tab', async () => {
    const order: string[] = [];
    stubLocks();
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/logout`, () => {
        order.push('logout');
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const lock = holdLock(order);
    const out = logout();
    await new Promise((r) => setTimeout(r, 20));
    expect(order).toEqual(['refresh-start']);
    lock.release();
    await Promise.all([lock.done, out]);
    expect(order).toEqual(['refresh-start', 'refresh-end', 'logout']);
    expect(REFRESH_LOCK).toBe('eg-session-refresh');
  });

  it('starting and ending an override wait for the lock too (the BFF may refresh server-side)', async () => {
    const order: string[] = [];
    stubLocks();
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/override`, () => {
        order.push('start');
        return HttpResponse.json(
          {
            id: 'o',
            organizationId: 'org',
            organizationName: 'Beta',
            expiresAt: new Date(NOW).toISOString(),
          },
          { status: 201 },
        );
      }),
      http.delete(`${TEST_ORIGIN}/bff/session/override`, () => {
        order.push('end');
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const first = holdLock(order);
    const started = startOverride({
      organizationId: 'org',
      reason: 'r'.repeat(10),
      durationMinutes: 5,
    });
    await new Promise((r) => setTimeout(r, 20));
    expect(order).toEqual(['refresh-start']);
    first.release();
    await Promise.all([first.done, started]);
    const second = holdLock(order);
    const ended = endOverride();
    await new Promise((r) => setTimeout(r, 20));
    expect(order.at(-1)).toBe('refresh-start');
    second.release();
    await Promise.all([second.done, ended]);
    expect(order).toEqual([
      'refresh-start',
      'refresh-end',
      'start',
      'refresh-start',
      'refresh-end',
      'end',
    ]);
  });
});

describe('refreshSession coalescing', () => {
  it('a forced refresh does not join an unforced one in flight; it runs after it', async () => {
    const bodies: unknown[] = [];
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/refresh`, async ({ request }) => {
        bodies.push(await request.json());
        await new Promise((r) => setTimeout(r, 10));
        return HttpResponse.json(state(new Date(NOW + 600_000).toISOString()));
      }),
    );
    const plain = refreshSession();
    const joined = refreshSession();
    const forced = refreshSession({ force: true });
    const forcedJoined = refreshSession({ force: true });
    expect(joined).toBe(plain);
    expect(forcedJoined).toBe(forced);
    await Promise.all([plain, forced]);
    expect(bodies).toEqual([{}, { force: true }]);
  });

  it('emits session-expired when a forced refresh is refused', async () => {
    const events: string[] = [];
    const off = onSessionEvent((e) => events.push(e.type));
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/refresh`, () =>
        HttpResponse.json(
          { statusCode: 401, code: 'session_expired', message: 'x' },
          { status: 401 },
        ),
      ),
    );
    await expect(refreshSession({ force: true })).rejects.toMatchObject({ status: 401 });
    expect(events).toEqual(['session-expired']);
    off();
  });
});
