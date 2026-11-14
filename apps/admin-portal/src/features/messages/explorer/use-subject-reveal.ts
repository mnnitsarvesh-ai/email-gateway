'use client';

import { useQueryClient, type QueryClient } from '@tanstack/react-query';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation } from '@/lib/api/hooks';
import type { MessageRow, RevealedSubjects } from './columns';

const REVEAL_OPERATION = 'MessageRevealController_revealMany_v1';
/** `POST /messages/reveal` accepts at most 100 ids (a page holds 50). */
const MAX_IDS_PER_REVEAL = 100;

/** Removes settled reveal mutations (and their clear subjects) from the TanStack mutation cache. */
export function forgetRevealMutations(queryClient: QueryClient): void {
  const cache = queryClient.getMutationCache();
  for (const mutation of cache.findAll({ mutationKey: [REVEAL_OPERATION] })) {
    if (mutation.state.status !== 'pending') cache.remove(mutation);
  }
}

export interface SubjectReveal {
  /** Revealed subjects of this page view (message id → subject). */
  readonly revealed: RevealedSubjects;
  readonly pending: boolean;
  readonly error: ApiError | null;
  /** Tries the current page again after an error. */
  readonly retry: () => void;
}

/**
 * The explorer's "Show subjects" (step 7.2 §2 E10, ADR-0062): while `enabled`, every loaded page
 * with masked subjects triggers **one** `POST /messages/reveal` with that page's ids (audited by
 * the api, one row per message). Revealed subjects live only in this component state: never in
 * the URL, browser storage or the TanStack caches (the mutation is reset and removed from the
 * mutation cache right after use). Turning the switch off forgets them; unmounting drops them.
 */
export function useSubjectReveal(rows: readonly MessageRow[], enabled: boolean): SubjectReveal {
  const queryClient = useQueryClient();
  const mutation = useApiMutation(REVEAL_OPERATION, { successMessage: null });
  const [revealed, setRevealed] = useState<ReadonlyMap<string, string | null>>(() => new Map());
  const [error, setError] = useState<ApiError | null>(null);
  const [inFlight, setInFlight] = useState(0);
  const [attempt, setAttempt] = useState(0);
  /** Ids already requested in this page view (a page is revealed once; StrictMode-safe). */
  const requested = useRef(new Set<string>());
  const mounted = useRef(true);
  const generation = useRef(0);
  const submitRef = useRef(mutation.submit);
  submitRef.current = mutation.submit;
  const resetRef = useRef(mutation.reset);
  resetRef.current = mutation.reset;

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  // Off: forget every revealed value of this page view.
  useEffect(() => {
    if (enabled) return;
    generation.current += 1;
    requested.current = new Set();
    setRevealed(new Map());
    setError(null);
  }, [enabled]);

  const rowKey = rows.map((row) => `${row.id}:${row.subjectMasked ? 1 : 0}`).join(',');
  useEffect(() => {
    if (!enabled) return;
    const ids = rows
      .filter((row) => row.subjectMasked && !requested.current.has(row.id))
      .map((row) => row.id)
      .slice(0, MAX_IDS_PER_REVEAL);
    if (ids.length === 0) return;
    for (const id of ids) requested.current.add(id);
    const run = generation.current;
    setInFlight((n) => n + 1);
    void (async () => {
      const outcome = await submitRef.current({ body: { messageIds: ids } });
      // Never keep clear subjects in the TanStack caches (§2 E10).
      resetRef.current();
      forgetRevealMutations(queryClient);
      if (!mounted.current) return;
      setInFlight((n) => Math.max(0, n - 1));
      if (run !== generation.current) return;
      if (outcome.ok) {
        setError(null);
        setRevealed((current) => {
          const next = new Map(current);
          for (const item of outcome.data.data) next.set(item.id, item.subject);
          return next;
        });
      } else {
        for (const id of ids) requested.current.delete(id);
        setError(outcome.error);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the page's ids drive it
  }, [enabled, rowKey, attempt, queryClient]);

  const retry = useCallback(() => {
    setError(null);
    setAttempt((n) => n + 1);
  }, []);

  return { revealed, pending: inFlight > 0, error, retry };
}
