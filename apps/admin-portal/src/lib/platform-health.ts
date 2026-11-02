import type { DependencyHealth, HealthReport } from '@email-gateway/shared-types';

export interface PlatformHealth {
  reachable: boolean;
  status: 'ok' | 'degraded' | 'unreachable';
  checks: DependencyHealth[];
  version?: string;
}

/** Reduces the API readiness report to what the dashboard displays. */
export function summarizeHealth(report: HealthReport | null): PlatformHealth {
  if (!report) return { reachable: false, status: 'unreachable', checks: [] };
  return {
    reachable: true,
    status: report.status === 'ok' ? 'ok' : 'degraded',
    checks: report.checks,
    version: report.version,
  };
}

/**
 * Server-side only: queries the API over the internal network. The URL is never exposed to the
 * browser. Times out quickly so a down API cannot stall page rendering.
 *
 * `API_INTERNAL_URL` is the API **origin** (e.g. `http://api:3000`). Probes are unprefixed
 * (`/health/ready`); business calls use `${API_INTERNAL_URL}/api/v1/...` (ADR-0015).
 */
export async function fetchPlatformHealth(): Promise<PlatformHealth> {
  const baseUrl = process.env.API_INTERNAL_URL;
  if (!baseUrl) return summarizeHealth(null);
  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, '')}/health/ready`, {
      cache: 'no-store',
      signal: AbortSignal.timeout(2_000),
    });
    return summarizeHealth((await res.json()) as HealthReport);
  } catch {
    return summarizeHealth(null);
  }
}
