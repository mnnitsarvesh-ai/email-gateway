'use client';

import { useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { cn } from '@/lib/utils';

/**
 * The account takeover attention badge of the shell (step 8.4 D16): active critical ATO incidents
 * plus responses waiting for approval, from `GET /ato/attention` (cached 30 s by the api), for
 * holders of `ato:read`. Nothing is rendered while the count is zero, loading or failing.
 */
export function AtoAttentionBadge({ collapsed = false }: { collapsed?: boolean }) {
  const can = useCan('AtoOverviewController_attention_v1');
  const attention = useApiQuery('AtoOverviewController_attention_v1', undefined, {
    enabled: can,
    staleTime: 30_000,
    refetchInterval: 60_000,
    retry: false,
  });
  const data = attention.data;
  if (!can || !data) return null;
  const total = data.criticalIncidents + data.pendingApprovals;
  if (total === 0) return null;
  const description = `${data.criticalIncidents} critical incident${data.criticalIncidents === 1 ? '' : 's'}, ${data.pendingApprovals} pending approval${data.pendingApprovals === 1 ? '' : 's'}`;
  return (
    <span
      data-testid="ato-attention-badge"
      title={description}
      className={cn(
        'inline-flex min-w-5 items-center justify-center rounded-full bg-tone-danger px-1.5 text-xs font-semibold text-tone-danger-foreground tabular-nums',
        collapsed ? 'absolute top-1 right-1 h-4 min-w-4 px-1 text-[10px]' : 'ml-auto h-5',
      )}
    >
      <span aria-hidden>{total > 99 ? '99+' : total}</span>
      <span className="sr-only">{`: ${description}`}</span>
    </span>
  );
}
