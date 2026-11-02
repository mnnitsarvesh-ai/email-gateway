import type { DomainStatus } from '@email-gateway/database';
import type { ApiConfig } from '../../../config';

/** The D11 schedule settings (seconds). */
export interface ScheduleConfig {
  retryBaseSeconds: number;
  retryMaxSeconds: number;
  recheckIncompleteSeconds: number;
  recheckIntervalSeconds: number;
}

export function scheduleConfigFrom(
  config: Pick<
    ApiConfig,
    | 'DOMAIN_RETRY_BASE_SECONDS'
    | 'DOMAIN_RETRY_MAX_SECONDS'
    | 'DOMAIN_RECHECK_INCOMPLETE_SECONDS'
    | 'DOMAIN_RECHECK_INTERVAL_SECONDS'
  >,
): ScheduleConfig {
  return {
    retryBaseSeconds: config.DOMAIN_RETRY_BASE_SECONDS,
    retryMaxSeconds: config.DOMAIN_RETRY_MAX_SECONDS,
    recheckIncompleteSeconds: config.DOMAIN_RECHECK_INCOMPLETE_SECONDS,
    recheckIntervalSeconds: config.DOMAIN_RECHECK_INTERVAL_SECONDS,
  };
}

/** Turns a delay into the jittered delay actually used (seconds). */
export type Jitter = (seconds: number) => number;

/** Fraction of the delay the default jitter may add or remove (±10 %, D11). */
export const JITTER_FRACTION = 0.1;

/** ±10 % uniform jitter, so domains created together do not stay in lock-step. */
export const defaultJitter: Jitter = (seconds) =>
  seconds * (1 - JITTER_FRACTION + Math.random() * 2 * JITTER_FRACTION);

/** No jitter (tests, and callers that need exact times). */
export const noJitter: Jitter = (seconds) => seconds;

export interface ScheduleInput {
  /** Status after the check (and after any transition it caused). */
  status: DomainStatus;
  /** Consecutive indeterminate checks, including this one (0 when it was definitive). */
  checkFailures: number;
  /** `domain_verifications.attempts` after this check. */
  attempts: number;
  /** True when every DNS record of the domain is `valid`. */
  allRecordsValid: boolean;
  /** Expiry of the current verification; caps the next check of pending domains. */
  verificationExpiresAt: Date | null;
  now: Date;
}

function backoff(config: ScheduleConfig, exponent: number): number {
  // 2^exponent overflows to Infinity for huge exponents; Math.min keeps the cap.
  return Math.min(config.retryBaseSeconds * 2 ** Math.max(exponent, 0), config.retryMaxSeconds);
}

/**
 * When the background job checks the domain next (D11 table):
 *
 * - `failed`, `deleted` (and the deprecated `disabled`): never (`null`);
 * - an indeterminate result (`checkFailures = k ≥ 1`): `base × 2^(k−1)`, capped at the maximum;
 * - `pending_verification` (attempt `n`): `base × 2^n`, capped at the maximum;
 * - `verified` / `active` / `suspended`: the incomplete-configuration interval while any record
 *   is not `valid`, else the healthy recheck interval.
 *
 * The delay gets the jitter (±10 % by default) and pending domains are never scheduled after
 * their verification expiry, so expiry is detected on time.
 */
export function nextCheckAt(
  input: ScheduleInput,
  config: ScheduleConfig,
  jitter: Jitter = defaultJitter,
): Date | null {
  let seconds: number;
  switch (input.status) {
    case 'pending_verification':
      seconds =
        input.checkFailures > 0
          ? backoff(config, input.checkFailures - 1)
          : backoff(config, input.attempts);
      break;
    case 'verified':
    case 'active':
    case 'suspended':
      if (input.checkFailures > 0) seconds = backoff(config, input.checkFailures - 1);
      else if (input.allRecordsValid) seconds = config.recheckIntervalSeconds;
      else seconds = config.recheckIncompleteSeconds;
      break;
    default:
      return null;
  }
  const delayMs = Math.max(Math.round(jitter(seconds) * 1000), 1000);
  let at = input.now.getTime() + delayMs;
  if (input.status === 'pending_verification' && input.verificationExpiresAt) {
    at = Math.min(at, Math.max(input.verificationExpiresAt.getTime(), input.now.getTime()));
  }
  return new Date(at);
}
