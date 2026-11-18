'use client';

import {
  keepPreviousData,
  useQuery,
  useQueryClient,
  type QueryClient,
} from '@tanstack/react-query';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { callOperationRaw } from '@/lib/api/call';
import { ApiError } from '@/lib/api/errors';
import { shouldRetry, useApiMutation } from '@/lib/api/hooks';
import type { ArchiveMessage, ArchiveReveal } from './model';
import type { ArchiveSearchQuery } from './search-state';

const SEARCH = 'ArchiveMessagesController_list_v1';
const REVEAL = 'ArchiveMessagesController_reveal_v1';

/** Seconds counting down to zero (429 `Retry-After`); restarts whenever `key` changes. */
export function useCountdown(seconds: number | null | undefined, key: unknown): number {
  const [left, setLeft] = useState(seconds ?? 0);
  useEffect(() => setLeft(seconds ?? 0), [seconds, key]);
  useEffect(() => {
    if (left <= 0) return;
    const timer = setTimeout(() => setLeft((s) => Math.max(0, s - 1)), 1000);
    return () => clearTimeout(timer);
  }, [left]);
  return left;
}

interface SearchPage {
  readonly data: ArchiveMessage[];
  readonly nextCursor: string | null;
  /** `X-EG-Index-Lag-Seconds`: age of the organization's oldest queued index operation. */
  readonly indexLagSeconds: number | null;
}

function searchRetry(failureCount: number, error: unknown): boolean {
  // A search the api refused because OpenSearch is down is not retried automatically: the
  // page explains it and offers a manual retry (each first page is audited).
  if (error instanceof ApiError && error.code === 'archive_search_unavailable') return false;
  return shouldRetry(failureCount, error);
}

/**
 * Forward keyset pagination of `GET /archive/messages` (A17) with the freshness header. The
 * cursor stack lives in component state and resets whenever the filters change (a v1 cursor is
 * bound to its filters, range and sort). No totals (`track_total_hits: false`).
 */
export function useArchiveSearch(
  filters: ArchiveSearchQuery,
  options: { enabled?: boolean; limit?: number } = {},
) {
  const limit = options.limit ?? 25;
  const filterKey = JSON.stringify([filters, limit]);
  const [stack, setStack] = useState<{ key: string; cursors: (string | null)[] }>({
    key: filterKey,
    cursors: [null],
  });
  const cursors = useMemo(
    () => (stack.key === filterKey ? stack.cursors : [null]),
    [filterKey, stack],
  );
  useEffect(() => {
    if (stack.key !== filterKey) setStack({ key: filterKey, cursors: [null] });
  }, [filterKey, stack.key]);
  const cursor = cursors[cursors.length - 1] ?? null;
  const query = { ...filters, limit: String(limit), ...(cursor ? { cursor } : {}) };
  const result = useQuery<SearchPage, ApiError>({
    queryKey: [SEARCH, { query }, 'page'],
    queryFn: async ({ signal }) => {
      const { data, response } = await callOperationRaw(SEARCH, { query }, { signal });
      const lag = Number(response.headers.get('x-eg-index-lag-seconds'));
      return {
        data: data.data,
        nextCursor: data.nextCursor,
        indexLagSeconds:
          response.headers.has('x-eg-index-lag-seconds') && Number.isFinite(lag) ? lag : null,
      };
    },
    placeholderData: keepPreviousData,
    enabled: options.enabled ?? true,
    retry: searchRetry,
    refetchOnWindowFocus: false,
    staleTime: 30_000,
  });
  const rows = useMemo(() => result.data?.data ?? [], [result.data]);
  const nextCursor = result.data?.nextCursor ?? null;
  const next = useCallback(() => {
    if (!nextCursor) return;
    setStack({ key: filterKey, cursors: [...cursors, nextCursor] });
  }, [cursors, filterKey, nextCursor]);
  const previous = useCallback(() => {
    if (cursors.length <= 1) return;
    setStack({ key: filterKey, cursors: cursors.slice(0, -1) });
  }, [cursors, filterKey]);
  return {
    rows,
    page: cursors.length,
    hasNext: nextCursor !== null,
    hasPrevious: cursors.length > 1,
    isShortPage: nextCursor !== null && rows.length < limit,
    next,
    previous,
    indexLagSeconds: result.data?.indexLagSeconds ?? null,
    query: result,
  };
}

/** Removes settled reveal mutations (and their clear values) from the TanStack mutation cache. */
export function forgetArchiveRevealMutations(queryClient: QueryClient): void {
  const cache = queryClient.getMutationCache();
  for (const mutation of cache.findAll({ mutationKey: [REVEAL] })) {
    if (mutation.state.status !== 'pending') cache.remove(mutation);
  }
}

export interface RevealedArchiveValues {
  /** `undefined` = not revealed; `null` = the message has no subject. */
  readonly subject: string | null | undefined;
  /** Envelope recipients by `seq`. */
  readonly recipients: ReadonlyMap<number, string>;
  /** To / Cc / Subject header values in stored order. */
  readonly headers: readonly { name: string; value: string }[];
  readonly revealedAt: string;
}

function toRevealed(body: ArchiveReveal): RevealedArchiveValues {
  return {
    subject: 'subject' in body ? (body.subject ?? null) : undefined,
    recipients: new Map((body.recipients ?? []).map((r) => [r.seq, r.address])),
    headers: body.headers ?? [],
    revealedAt: body.revealedAt,
  };
}

export interface ArchiveRevealState {
  /** Revealed values by message id (this page view only). */
  readonly values: ReadonlyMap<string, RevealedArchiveValues>;
  readonly pending: boolean;
  readonly error: ApiError | null;
  /** Seconds until a rate-limited reveal may be retried. */
  readonly retryAfterSeconds: number;
  readonly announcement: string;
  /** Reveals the given messages, one audited call each (stops at the first refusal). */
  readonly reveal: (
    messageIds: readonly string[],
    fields?: readonly ('subject' | 'recipients' | 'headers')[],
  ) => Promise<void>;
  /** Forgets every revealed value. */
  readonly hide: () => void;
}

/**
 * Reveal of archived messages (A17, ADR-0062): `POST /archive/messages/{id}/reveal` per message,
 * each audited (`archive.revealed`) by the api before it answers. Revealed values live **only in
 * this hook's React state**: never in the query or mutation cache (each mutation is reset and
 * removed right after the call), the URL or browser storage. "Hide again", another message set
 * (`resetKey`) or unmounting forgets them. A `429` stops the run and starts the countdown.
 */
export function useArchiveReveal(resetKey: unknown): ArchiveRevealState {
  const queryClient = useQueryClient();
  const mutation = useApiMutation(REVEAL, { successMessage: null });
  const [values, setValues] = useState<ReadonlyMap<string, RevealedArchiveValues>>(() => new Map());
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [announcement, setAnnouncement] = useState('');
  const generation = useRef(0);
  const mounted = useRef(true);
  const submitRef = useRef(mutation.submit);
  submitRef.current = mutation.submit;
  const resetRef = useRef(mutation.reset);
  resetRef.current = mutation.reset;
  const retryAfter = useCountdown(
    error?.status === 429 ? (error.retryAfterSeconds ?? 60) : 0,
    error,
  );

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      generation.current += 1;
      forgetArchiveRevealMutations(queryClient);
    };
  }, [queryClient]);

  useEffect(() => {
    generation.current += 1;
    setValues(new Map());
    setError(null);
    setPending(false);
    setAnnouncement('');
  }, [resetKey]);

  const reveal = useCallback(
    async (
      messageIds: readonly string[],
      fields: readonly ('subject' | 'recipients' | 'headers')[] = ['subject', 'recipients'],
    ) => {
      const run = generation.current;
      setPending(true);
      setError(null);
      let revealed = 0;
      for (const messageId of messageIds) {
        const outcome = await submitRef.current({
          path: { messageId },
          body: { fields: [...fields] },
        });
        // Never keep clear values in the TanStack caches.
        resetRef.current();
        forgetArchiveRevealMutations(queryClient);
        if (!mounted.current || run !== generation.current) return;
        if (!outcome.ok) {
          setError(outcome.error);
          break;
        }
        revealed += 1;
        const entry = toRevealed(outcome.data);
        setValues((current) => new Map(current).set(messageId, entry));
      }
      if (!mounted.current || run !== generation.current) return;
      setPending(false);
      setAnnouncement(
        `Revealed ${revealed} message${revealed === 1 ? '' : 's'}. Each reveal is recorded in the audit log.`,
      );
    },
    [queryClient],
  );

  const hide = useCallback(() => {
    generation.current += 1;
    setValues(new Map());
    setError(null);
    setPending(false);
    setAnnouncement('Revealed values are hidden again.');
  }, []);

  return useMemo(
    () => ({ values, pending, error, retryAfterSeconds: retryAfter, announcement, reveal, hide }),
    [values, pending, error, retryAfter, announcement, reveal, hide],
  );
}
