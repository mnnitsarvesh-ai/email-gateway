import type { CheckSeverity, CheckStatus, ProviderHealthStatus } from '../types';

export interface HealthCheckResultInput {
  code: string;
  status: CheckStatus;
  severity: CheckSeverity;
  /** When the check first failed or errored in its current streak (null when passing). */
  firstFailedAt: Date | null;
}

/** `INTEGRATION_HEALTH_ERROR_GRACE_MINUTES` default (D15). */
export const DEFAULT_HEALTH_ERROR_GRACE_MINUTES = 60;

const RANK: Record<Exclude<ProviderHealthStatus, 'unknown'>, number> = {
  healthy: 0,
  warning: 1,
  critical: 2,
};

/**
 * The connection's health from its latest check results (D11, D15), pure:
 * - `fail` counts with its severity (`critical` → critical, `warning` → warning; `info` never
 *   degrades);
 * - `warn` degrades to `warning` (unless its severity is `info`);
 * - `error` (the provider was unavailable or throttled) counts with its severity only once it
 *   has persisted for `graceMinutes` since `firstFailedAt`; before that it is ignored, so a
 *   short provider outage never flips a healthy connection;
 * - `pass` and `skipped` do not degrade.
 * With no result at all, or only skipped / in-grace results, the status is `unknown` — unless
 * `previous` is given, which is then kept (an outage within the grace window changes nothing).
 */
export function evaluateHealth(
  results: readonly HealthCheckResultInput[],
  now: Date,
  graceMinutes: number,
  previous?: ProviderHealthStatus,
): ProviderHealthStatus {
  let worst: Exclude<ProviderHealthStatus, 'unknown'> | null = null;
  let evaluated = false;
  const degrade = (to: Exclude<ProviderHealthStatus, 'unknown'>) => {
    if (worst === null || RANK[to] > RANK[worst]) worst = to;
  };
  const graceMs = Math.max(0, graceMinutes) * 60_000;

  for (const result of results) {
    switch (result.status) {
      case 'pass':
        evaluated = true;
        degrade('healthy');
        break;
      case 'skipped':
        break;
      case 'warn':
        evaluated = true;
        degrade(result.severity === 'info' ? 'healthy' : 'warning');
        break;
      case 'fail':
        evaluated = true;
        degrade(
          result.severity === 'critical'
            ? 'critical'
            : result.severity === 'warning'
              ? 'warning'
              : 'healthy',
        );
        break;
      case 'error': {
        const since = result.firstFailedAt?.getTime() ?? now.getTime();
        if (now.getTime() - since >= graceMs) {
          evaluated = true;
          degrade(
            result.severity === 'critical'
              ? 'critical'
              : result.severity === 'warning'
                ? 'warning'
                : 'healthy',
          );
        }
        break;
      }
    }
  }
  if (!evaluated || worst === null) return previous ?? 'unknown';
  return worst;
}

/** Codes of the results that currently degrade health (≤ `max`, for events and alerts). */
export function failingCheckCodes(
  results: readonly HealthCheckResultInput[],
  now: Date,
  graceMinutes: number,
  max = 10,
): string[] {
  const graceMs = Math.max(0, graceMinutes) * 60_000;
  const codes = results
    .filter((r) => {
      if (r.severity === 'info') return false;
      if (r.status === 'fail' || r.status === 'warn') return true;
      if (r.status === 'error')
        return now.getTime() - (r.firstFailedAt?.getTime() ?? now.getTime()) >= graceMs;
      return false;
    })
    .sort((a, b) =>
      a.severity === b.severity ? a.code.localeCompare(b.code) : a.severity === 'critical' ? -1 : 1,
    )
    .map((r) => r.code);
  return [...new Set(codes)].slice(0, max);
}
