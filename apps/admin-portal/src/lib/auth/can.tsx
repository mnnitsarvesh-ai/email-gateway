'use client';

import type { ReactNode } from 'react';
import type { OperationId } from '@/lib/api/types';
import { useCan } from './me';

/** Renders children only when the user may perform `op` (hides actions; the api decides). */
export function Can({
  op,
  children,
  fallback = null,
}: {
  op: OperationId;
  children: ReactNode;
  fallback?: ReactNode;
}) {
  return useCan(op) ? <>{children}</> : <>{fallback}</>;
}
