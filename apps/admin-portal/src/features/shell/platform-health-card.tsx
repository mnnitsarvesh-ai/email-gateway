'use client';

import { useQuery } from '@tanstack/react-query';
import { ServerIcon } from 'lucide-react';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import type { ApiError } from '@/lib/api/errors';
import { usePermissions } from '@/lib/auth/me';
import { bffSessionCall } from '@/lib/session/session-client';
import type { PlatformHealth } from '@/lib/platform-health';

const STATUS = {
  ok: { label: 'Operational', variant: 'success' },
  degraded: { label: 'Degraded', variant: 'destructive' },
  unreachable: { label: 'API unreachable', variant: 'destructive' },
} as const;

/**
 * Platform readiness (the former home page), only for `platform:operations` (design P11),
 * through `GET /bff/platform/health`. Exported for the dashboard (WP3).
 */
export function PlatformHealthCard() {
  const permissions = usePermissions();
  const allowed = permissions.has('platform:operations');
  const health = useQuery<PlatformHealth, ApiError>({
    queryKey: ['bff-platform-health'],
    queryFn: () => bffSessionCall<PlatformHealth>('/bff/platform/health'),
    enabled: allowed,
    staleTime: 30_000,
    retry: false,
  });
  if (!allowed) return null;
  const status = health.data ? STATUS[health.data.status] : null;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ServerIcon className="size-4" aria-hidden />
          Platform dependencies
          {status ? <Badge variant={status.variant}>{status.label}</Badge> : null}
        </CardTitle>
        <CardDescription>
          Readiness reported by the API
          {health.data?.version ? ` (version ${health.data.version})` : ''}.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {health.isLoading ? (
          <LoadingState label="Loading platform readiness" rows={3} />
        ) : health.error ? (
          <ErrorState error={health.error} onRetry={() => void health.refetch()} compact />
        ) : !health.data || health.data.checks.length === 0 ? (
          <p className="text-sm text-muted-foreground">No readiness data available.</p>
        ) : (
          <ul className="divide-y">
            {health.data.checks.map((check) => (
              <li key={check.name} className="flex items-center justify-between py-2">
                <span className="font-mono text-sm">{check.name}</span>
                <span className="flex items-center gap-3 text-sm text-muted-foreground">
                  <span className="tabular-nums">{check.latencyMs} ms</span>
                  <Badge variant={check.status === 'ok' ? 'success' : 'destructive'}>
                    {check.status}
                  </Badge>
                </span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
