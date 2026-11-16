'use client';

import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { callOperation } from '@/lib/api/call';
import type { ApiError } from '@/lib/api/errors';
import { shouldRetry } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import type { BuilderDirectory, DirectoryNames, DirectoryOption } from './builder';

/** Pages of 100 read per directory list (the api's maximum page size). */
const PAGE_SIZE = 100;
/** At most this many pages (500 entries) per list; a larger directory is marked truncated. */
export const DIRECTORY_MAX_PAGES = 5;
const DIRECTORY_STALE_MS = 300_000;

interface Walked<T> {
  readonly items: T[];
  readonly truncated: boolean;
}

/** Walks a v0 list (`{ data, nextCursor }`) through the typed client, bounded. */
async function walk<T>(
  fetchPage: (cursor: string | undefined) => Promise<{ data: T[]; nextCursor: string | null }>,
): Promise<Walked<T>> {
  const items: T[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < DIRECTORY_MAX_PAGES; page += 1) {
    const body = await fetchPage(cursor);
    items.push(...body.data);
    if (!body.nextCursor) return { items, truncated: false };
    cursor = body.nextCursor;
  }
  return { items, truncated: true };
}

type Department = ListItem<'DepartmentsController_list_v1'>;
type User = ListItem<'UsersController_list_v1'>;

export interface DirectoryOptions {
  /** Options of the builder's directory pickers (absent lists → plain UUID entry). */
  readonly directory: BuilderDirectory;
  /** Names for the summary, the diff and the version table (author, publisher). */
  readonly names: DirectoryNames;
  /** A list was longer than the bounded read (pickers show the first entries only). */
  readonly truncated: boolean;
}

const userLabel = (user: User) =>
  user.displayName ? `${user.displayName} (${user.email})` : user.email;

/**
 * Departments and users of the organization for the directory pickers and names (design B3, B5,
 * B10), read only when the user may list them (`user:read`); without it the pickers fall back to
 * public id entry and the summaries show shortened ids.
 */
export function useDirectoryOptions(): DirectoryOptions {
  const canDepartments = useCan('DepartmentsController_list_v1');
  const canUsers = useCan('UsersController_list_v1');
  const departments = useQuery<Walked<Department>, ApiError>({
    queryKey: ['DepartmentsController_list_v1', { all: true }],
    queryFn: ({ signal }) =>
      walk((cursor) =>
        callOperation(
          'DepartmentsController_list_v1',
          { query: { limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) } },
          { signal },
        ),
      ),
    enabled: canDepartments,
    staleTime: DIRECTORY_STALE_MS,
    retry: shouldRetry,
  });
  const users = useQuery<Walked<User>, ApiError>({
    queryKey: ['UsersController_list_v1', { all: true }],
    queryFn: ({ signal }) =>
      walk((cursor) =>
        callOperation(
          'UsersController_list_v1',
          { query: { limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) } },
          { signal },
        ),
      ),
    enabled: canUsers,
    staleTime: DIRECTORY_STALE_MS,
    retry: shouldRetry,
  });
  const departmentData = departments.data;
  const userData = users.data;
  const loading = (canDepartments && departments.isLoading) || (canUsers && users.isLoading);
  return useMemo(() => {
    const departmentOptions: DirectoryOption[] | undefined = departmentData?.items.map((d) => ({
      id: d.id,
      label: d.name,
    }));
    const userOptions: DirectoryOption[] | undefined = userData?.items.map((u) => ({
      id: u.id,
      label: userLabel(u),
    }));
    return {
      directory: {
        ...(departmentOptions ? { departments: departmentOptions } : {}),
        ...(userOptions ? { users: userOptions } : {}),
        loading,
      },
      names: {
        departments: new Map((departmentOptions ?? []).map((o) => [o.id, o.label])),
        users: new Map((userData?.items ?? []).map((u) => [u.id, u.displayName || u.email])),
      },
      truncated: Boolean(departmentData?.truncated || userData?.truncated),
    };
  }, [departmentData, userData, loading]);
}
