'use client';

import type { ReactNode } from 'react';
import { ForbiddenView } from '@/components/forbidden-view';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import type { Gate } from '@/lib/navigation';
import { useMe } from './me';
import { passesGate } from './permissions';

/**
 * Guards a page with a navigation gate (design P11): loading → skeleton, `me` error → error
 * state, gate not satisfied → the 403 view. UI only: the api stays authoritative.
 */
export function RouteGate({ gate, children }: { gate: Gate; children: ReactNode }) {
  const me = useMe();
  if (me.isLoading) return <LoadingState label="Checking access" rows={4} className="p-4" />;
  if (me.error) return <ErrorState error={me.error} onRetry={() => void me.refetch()} />;
  const permissions = me.data?.permissions ?? [];
  if (!passesGate(gate, permissions)) return <ForbiddenView gate={gate} />;
  return <>{children}</>;
}
