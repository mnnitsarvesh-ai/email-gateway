/**
 * Shared call discipline of the mailbox clients (design D9, D10.6, D10.7): consult the throttle
 * gate, take the per-connection budget, call through 8.5's `ProviderHttpClient`, normalize every
 * failure into a `MailboxApiError`, and pause the connection-family on throttling answers.
 */
import type {
  IdpMetricsSink,
  ProviderHttpClient,
  RateBudget,
  Sleep,
  TokenSource,
} from '@email-gateway/idp-adapters';
import {
  MAX_THROTTLE_PAUSE_MS,
  takeMailboxBudget,
  type MailboxApiFamily,
  type ThrottleEvent,
  type ThrottleGate,
} from '../budget';
import { MailboxApiError, toMailboxApiError } from '../errors';

/** Dependencies of a mailbox client for one API connection. */
export interface MailboxClientContext {
  /** 8.5's HTTP client configured with the Graph / Gmail / Google Admin base URLs. */
  http: ProviderHttpClient;
  /** `api_mode_connections.public_id` (budget and throttle key; never a tenant from input). */
  apiConnectionPublicId: string;
  budget: RateBudget;
  throttle: ThrottleGate;
  sleep?: Sleep;
  metrics?: IdpMetricsSink;
  /** Cap of a provider-requested pause; at most (and by default) 600 s. */
  maxThrottlePauseMs?: number;
}

export type { TokenSource };

/** A streamed provider body (MIME bytes); iterate once. Failures are `MailboxApiError`s. */
export interface MailboxContentStream {
  /** Declared length of the provider response, when given (Graph `$value` only). */
  contentLength: number | undefined;
  body: AsyncIterable<Uint8Array>;
}

function throttleEventOf(
  context: MailboxClientContext,
  family: MailboxApiFamily,
  error: MailboxApiError,
): ThrottleEvent | null {
  const cap = Math.min(context.maxThrottlePauseMs ?? MAX_THROTTLE_PAUSE_MS, MAX_THROTTLE_PAUSE_MS);
  const base = { apiConnectionPublicId: context.apiConnectionPublicId, family };
  if ((error.code === 'throttled' || error.code === 'quota_exhausted') && error.status) {
    return {
      ...base,
      code: error.code,
      status: error.status,
      retryAfterMs: Math.min(error.retryAfterMs ?? cap, cap),
    };
  }
  // A 503 pauses only when the provider said how long (Retry-After); other 5xx back off per mailbox.
  if (
    error.code === 'provider_unavailable' &&
    error.status === 503 &&
    error.retryAfterMs !== undefined
  ) {
    return {
      ...base,
      code: 'provider_unavailable',
      status: 503,
      retryAfterMs: Math.min(error.retryAfterMs, cap),
    };
  }
  return null;
}

/** Normalizes the error and pauses the connection-family when the provider throttled. */
async function settle(
  context: MailboxClientContext,
  family: MailboxApiFamily,
  thrown: unknown,
): Promise<MailboxApiError> {
  const error = toMailboxApiError(thrown);
  const event = throttleEventOf(context, family, error);
  if (event) {
    try {
      await context.throttle.pause(event);
    } catch {
      // The provider error is what the caller must see; the gate's own failure is not.
    }
    return new MailboxApiError(error.code, {
      retryable: error.retryable,
      retryAfterMs: event.retryAfterMs,
      ...(error.status !== undefined ? { status: error.status } : {}),
      ...(error.providerCode !== undefined ? { providerCode: error.providerCode } : {}),
    });
  }
  return error;
}

/**
 * Runs one provider call: gate (`throttle_paused` while paused), budget (`rate_budget`), call,
 * normalized errors, pause on throttling. Every client method goes through here.
 */
export async function guardedCall<T>(
  context: MailboxClientContext,
  family: MailboxApiFamily,
  signal: AbortSignal,
  run: () => Promise<T>,
): Promise<T> {
  let remaining: number;
  try {
    remaining = await context.throttle.remainingMs(context.apiConnectionPublicId, family);
  } catch (error) {
    throw toMailboxApiError(error);
  }
  if (remaining > 0) {
    throw new MailboxApiError('throttle_paused', { retryable: true, retryAfterMs: remaining });
  }
  try {
    await takeMailboxBudget({
      budget: context.budget,
      apiConnectionPublicId: context.apiConnectionPublicId,
      family,
      signal,
      ...(context.sleep ? { sleep: context.sleep } : {}),
      ...(context.metrics ? { metrics: context.metrics } : {}),
    });
    return await run();
  } catch (error) {
    throw await settle(context, family, error);
  }
}

/** Wraps a streamed body so that iteration failures are `MailboxApiError`s too. */
export async function* normalizedStream(
  body: AsyncIterable<Uint8Array>,
): AsyncGenerator<Uint8Array, void, undefined> {
  try {
    for await (const chunk of body) yield chunk;
  } catch (error) {
    throw toMailboxApiError(error);
  }
}

export const enc = encodeURIComponent;
