/**
 * Per-tenant call budgets and the shared throttle pause of the mailbox clients (design D9, D10.6,
 * invariant N7).
 *
 * - Budget: every call first takes one unit of the per-second budget of its API connection and
 *   family through 8.5's `takeBudget` with `integrationId = 'mbx:<apiConnectionPublicId>'` (the
 *   worker's `RateBudget` over Redis keys `mbx:rb:<apiConnectionPublicId>:<family>:s<epoch>`).
 * - Throttle gate: every call consults the gate before calling; a `429`, a Google rate-limit
 *   `403` or a `503` with `Retry-After` pauses the connection-family for `Retry-After` (capped at
 *   600 s) for every worker (the worker implements the port over Redis
 *   `mbx:throttle:<apiConnectionPublicId>:<family>`).
 */
import {
  takeBudget,
  type IdpMetricsSink,
  type RateBudget,
  type Sleep,
} from '@email-gateway/idp-adapters';

export const MAILBOX_API_FAMILIES = ['graph', 'gmail', 'google_directory'] as const;
export type MailboxApiFamily = (typeof MAILBOX_API_FAMILIES)[number];

/** Upper bound of a provider-requested pause (D10.6). */
export const MAX_THROTTLE_PAUSE_MS = 600_000;

export const MAILBOX_BUDGET_PREFIX = 'mbx:';

/** The 8.5 `integrationId` of an API connection's budgets: `mbx:<apiConnectionPublicId>`. */
export function mailboxBudgetId(apiConnectionPublicId: string): string {
  return `${MAILBOX_BUDGET_PREFIX}${apiConnectionPublicId}`;
}

/** The API connection public id of a `mbx:` budget id, or null for other integrations. */
export function parseMailboxBudgetId(integrationId: string): string | null {
  return integrationId.startsWith(MAILBOX_BUDGET_PREFIX)
    ? integrationId.slice(MAILBOX_BUDGET_PREFIX.length) || null
    : null;
}

/** Takes one unit of the connection-family budget (waits ≤ 1 s, else `rate_budget`). */
export function takeMailboxBudget(input: {
  budget: RateBudget;
  apiConnectionPublicId: string;
  family: MailboxApiFamily;
  signal: AbortSignal;
  sleep?: Sleep;
  metrics?: IdpMetricsSink;
  maxWaitMs?: number;
}): Promise<void> {
  return takeBudget({
    budget: input.budget,
    integrationId: mailboxBudgetId(input.apiConnectionPublicId),
    family: input.family,
    signal: input.signal,
    ...(input.sleep ? { sleep: input.sleep } : {}),
    ...(input.metrics ? { metrics: input.metrics } : {}),
    ...(input.maxWaitMs !== undefined ? { maxWaitMs: input.maxWaitMs } : {}),
  });
}

/** One provider throttle answer that paused a connection-family. */
export interface ThrottleEvent {
  apiConnectionPublicId: string;
  family: MailboxApiFamily;
  /** The pause, already capped at `MAX_THROTTLE_PAUSE_MS`. */
  retryAfterMs: number;
  /** HTTP status of the answer (`429`, `503`, `403` for Google rate-limit reasons). */
  status: number;
  /** `throttled` (429 / rate limit), `quota_exhausted` or `provider_unavailable` (503). */
  code: 'throttled' | 'quota_exhausted' | 'provider_unavailable';
}

/**
 * Shared pause of a connection-family (port; the mailbox-worker implements it over Redis and
 * also records `throttled_until`, the counters and the metrics from `pause`).
 */
export interface ThrottleGate {
  /** Milliseconds the connection-family stays paused; 0 when calls may proceed. */
  remainingMs(apiConnectionPublicId: string, family: MailboxApiFamily): Promise<number>;
  /** Pauses the connection-family for `event.retryAfterMs` (keeps a longer existing pause). */
  pause(event: ThrottleEvent): Promise<void>;
}

/** A gate that never pauses (tools and tests that do not exercise throttling). */
export const OPEN_THROTTLE_GATE: ThrottleGate = {
  remainingMs: () => Promise.resolve(0),
  pause: () => Promise.resolve(),
};

/**
 * In-process gate (tests, single-process tools): pauses kept in memory with an injectable clock.
 * Production uses the worker's Redis implementation so every worker honours the pause.
 */
export class InMemoryThrottleGate implements ThrottleGate {
  private readonly until = new Map<string, number>();
  readonly events: ThrottleEvent[] = [];

  constructor(private readonly now: () => number = Date.now) {}

  remainingMs(apiConnectionPublicId: string, family: MailboxApiFamily): Promise<number> {
    const until = this.until.get(`${apiConnectionPublicId}|${family}`) ?? 0;
    return Promise.resolve(Math.max(0, until - this.now()));
  }

  pause(event: ThrottleEvent): Promise<void> {
    this.events.push(event);
    const key = `${event.apiConnectionPublicId}|${event.family}`;
    const until = this.now() + Math.min(event.retryAfterMs, MAX_THROTTLE_PAUSE_MS);
    this.until.set(key, Math.max(this.until.get(key) ?? 0, until));
    return Promise.resolve();
  }
}
