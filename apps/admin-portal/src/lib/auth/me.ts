'use client';

import { type QueryClient, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useMemo } from 'react';
import { useApiQuery } from '@/lib/api/hooks';
import type { ApiError } from '@/lib/api/errors';
import type { OperationId } from '@/lib/api/types';
import {
  endOverride,
  getSessionState,
  startOverride,
  type OverrideStarted,
  type SessionState,
} from '@/lib/session/session-client';
import { canPerform } from './permissions';

export const ME_QUERY_KEY = ['AuthController_me_v1'] as const;
export const SESSION_QUERY_KEY = ['bff-session'] as const;

/** `GET /auth/me`: user, organization, permissions, override (design P11). */
export function useMe() {
  return useApiQuery('AuthController_me_v1', undefined, {
    staleTime: 60_000,
    refetchOnWindowFocus: true,
  });
}

/** `GET /bff/session` (no tokens). */
export function useSession() {
  return useQuery<SessionState, ApiError>({
    queryKey: SESSION_QUERY_KEY,
    queryFn: getSessionState,
    staleTime: 30_000,
    retry: false,
  });
}

export function usePermissions(): ReadonlySet<string> {
  const me = useMe();
  const list = me.data?.permissions;
  return useMemo(() => new Set(list ?? []), [list]);
}

/** Whether the current user may perform an operation (UI only; the api decides). */
export function useCan(operationId: OperationId): boolean {
  const permissions = usePermissions();
  const me = useMe();
  return me.isSuccess && canPerform(operationId, permissions);
}

/**
 * Whether the current user holds **every** given permission (UI only; the api decides). For
 * rules that are not one operation's `x-eg-permissions`, such as the filter-level permissions of
 * `GET /messages` (`subject` needs `message:reveal`, `deliveryStatus` needs `delivery:read`; step
 * 7.2 §2 E2). `false` while `GET /auth/me` loads.
 */
export function useHasPermission(...required: readonly string[]): boolean {
  const permissions = usePermissions();
  const me = useMe();
  return me.isSuccess && required.every((permission) => permissions.has(permission));
}

/**
 * Whether the acting organization is on the archive-only plan (step 8.6 D13, ADR-0090): journal
 * intake and the archive, no mail through the gateway. `false` while `GET /auth/me` loads.
 */
export function useArchiveOnly(): boolean {
  return useMe().data?.organization.serviceProfile === 'archive_only';
}

/**
 * Drops every cached tenant response when the acting tenant changes (design P11): inactive
 * queries are removed, mounted ones are reset and refetched at once. `clear()` alone left
 * mounted observers (the shell's session query, hence the override banner) on their old data
 * until something re-rendered them (found by the step 7.1 e2e suite: "End now" kept the banner).
 */
export async function resetTenantCaches(queryClient: QueryClient): Promise<void> {
  queryClient.getMutationCache().clear();
  queryClient.removeQueries({ type: 'inactive' });
  await queryClient.resetQueries({ type: 'active' });
}

export function useStartOverride() {
  const queryClient = useQueryClient();
  return useCallback(
    async (input: {
      organizationId: string;
      reason: string;
      durationMinutes: number;
    }): Promise<OverrideStarted> => {
      const result = await startOverride(input);
      await resetTenantCaches(queryClient);
      return result;
    },
    [queryClient],
  );
}

export function useEndOverride() {
  const queryClient = useQueryClient();
  return useCallback(async () => {
    await endOverride();
    await resetTenantCaches(queryClient);
  }, [queryClient]);
}
