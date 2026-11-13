import { ApiError } from '@/lib/api/errors';
import { emitSessionEvent } from './events';
import { REFRESH_LOCK, bffSessionCall, sessionLocks, type SessionState } from './session-client';

/**
 * The browser's single refresh coordinator (design P4). The api's refresh tokens are single
 * use; two concurrent refreshes look like reuse and end the session. So: one in-memory promise
 * per tab, and `navigator.locks` across tabs (in-memory only without Web Locks). The BFF answers
 * "fresh enough" without calling the api when another tab refreshed in the last minute.
 */
export { REFRESH_LOCK };
/** Proactive refresh this long before the access token expires. */
export const PROACTIVE_LEAD_MS = 60_000;
/** Never schedule two proactive refreshes closer than this. */
export const PROACTIVE_MIN_DELAY_MS = 5_000;

let inflight: Promise<SessionState> | null = null;
let inflightForced = false;

/**
 * Delay of the next proactive refresh: `PROACTIVE_LEAD_MS` before expiry, but never earlier than
 * half of the remaining lifetime (an access-token TTL of 60 s, the api minimum, would otherwise
 * mean "refresh now" after every refresh: a refresh loop) and never sooner than
 * `PROACTIVE_MIN_DELAY_MS`.
 */
export function proactiveDelay(expiresAtMs: number, nowMs: number): number {
  const remaining = expiresAtMs - nowMs;
  return Math.max(PROACTIVE_MIN_DELAY_MS, remaining - PROACTIVE_LEAD_MS, remaining / 2);
}

async function runRefresh(force: boolean): Promise<SessionState> {
  const call = () =>
    bffSessionCall<SessionState>('/bff/session/refresh', {
      method: 'POST',
      body: force ? { force: true } : {},
    });
  const locks = sessionLocks();
  try {
    const state = locks ? await locks.request(REFRESH_LOCK, call) : await call();
    emitSessionEvent({ type: 'session-refreshed' });
    return state;
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      emitSessionEvent({ type: 'session-expired' });
    }
    throw error;
  }
}

/**
 * Refreshes once for all concurrent callers in this tab. A forced caller never joins an unforced
 * refresh (which the BFF may answer from its "fresh enough" short-circuit without asking the api):
 * it chains a forced refresh after it.
 */
export function refreshSession(options: { force?: boolean } = {}): Promise<SessionState> {
  const force = options.force === true;
  if (inflight && (inflightForced || !force)) return inflight;
  const run = inflight ? inflight.then(() => runRefresh(true)) : runRefresh(force);
  inflightForced = force;
  const current: Promise<SessionState> = run.finally(() => {
    if (inflight === current) {
      inflight = null;
      inflightForced = false;
    }
  });
  inflight = current;
  return current;
}

/**
 * Schedules a proactive refresh `PROACTIVE_LEAD_MS` before `accessExpiresAt` while the tab is
 * visible; re-arms on visibility change. Returns a disposer.
 */
export function scheduleProactiveRefresh(
  getAccessExpiresAt: () => string | null,
  onRefreshed: (state: SessionState) => void,
): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let known: string | null = null;
  const arm = (latest?: string | null) => {
    if (timer) clearTimeout(timer);
    const current = getAccessExpiresAt();
    const expiresAt =
      latest !== undefined
        ? latest
        : current && known
          ? Date.parse(current) >= Date.parse(known)
            ? current
            : known
          : (current ?? known);
    known = expiresAt;
    if (!expiresAt || (typeof document !== 'undefined' && document.visibilityState === 'hidden')) {
      return;
    }
    const delay = proactiveDelay(Date.parse(expiresAt), Date.now());
    timer = setTimeout(() => {
      refreshSession()
        .then((state) => {
          onRefreshed(state);
          arm(state.accessExpiresAt);
        })
        .catch(() => undefined);
    }, delay);
  };
  arm();
  const onVisibility = () => arm();
  if (typeof document !== 'undefined') document.addEventListener('visibilitychange', onVisibility);
  return () => {
    if (timer) clearTimeout(timer);
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', onVisibility);
    }
  };
}

/** Tests only. */
export function resetRefreshCoordinatorForTests(): void {
  inflight = null;
  inflightForced = false;
}
