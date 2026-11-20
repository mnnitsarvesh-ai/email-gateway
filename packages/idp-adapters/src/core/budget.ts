/**
 * Rate budgets (design note D7.5): per integration and API family, a request over budget waits
 * ≤ 1 s, then the page ends early (`retryAfterMs = 1000`, ingestion) or the action fails
 * `rate_budget` (retryable). WP4 implements `RateBudget` over Redis
 * (`ato:idp:rb:{integrationId}:{family}:s{epochSecond}`, INCR + EXPIRE 5).
 */
import type { ApiFamily, RateBudget } from '../port/state-ports';
import { ProviderCallError } from './errors';
import type { IdpMetricsSink } from './http';

export const RATE_BUDGET_MAX_WAIT_MS = 1_000;
export const RATE_BUDGET_RETRY_AFTER_MS = 1_000;
const POLL_STEP_MS = 100;

export type Sleep = (ms: number, signal: AbortSignal) => Promise<void>;

export const defaultSleep: Sleep = (ms, signal) =>
  new Promise<void>((resolve, reject) => {
    if (signal.aborted) {
      reject(new ProviderCallError('aborted', { retryable: false }));
      return;
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new ProviderCallError('aborted', { retryable: false }));
    };
    signal.addEventListener('abort', onAbort, { once: true });
  });

/**
 * Takes one unit of the budget, waiting up to 1 s. Throws `rate_budget` (retryable,
 * `retryAfterMs = 1000`) when the budget stays exhausted.
 */
export async function takeBudget(input: {
  budget: RateBudget;
  integrationId: string;
  family: ApiFamily;
  signal: AbortSignal;
  sleep?: Sleep;
  metrics?: IdpMetricsSink;
  maxWaitMs?: number;
}): Promise<void> {
  const sleep = input.sleep ?? defaultSleep;
  const maxWait = input.maxWaitMs ?? RATE_BUDGET_MAX_WAIT_MS;
  let waited = 0;
  for (;;) {
    const result = await input.budget.take(input.integrationId, input.family, input.signal);
    if (result === 'ok') return;
    if (waited === 0) input.metrics?.rateBudgetWait?.({ family: input.family });
    if (waited >= maxWait) {
      throw new ProviderCallError('rate_budget', { retryAfterMs: RATE_BUDGET_RETRY_AFTER_MS });
    }
    await sleep(POLL_STEP_MS, input.signal);
    waited += POLL_STEP_MS;
  }
}
