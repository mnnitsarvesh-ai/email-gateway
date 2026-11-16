'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { callOperation } from '@/lib/api/call';
import { ApiError } from '@/lib/api/errors';
import type { SuccessBody } from '@/lib/api/types';
import { canonicalJson, type PolicyDslDocument } from './builder';

/**
 * Server validation of the edited document (design B4): `POST /policies/validate` writes nothing
 * and is the only place DSL semantics are checked (never the browser, ADR-0063 decision 2).
 *
 * Automatic runs: 2 s after the last edit when the document changed since the last validation,
 * at most once per 10 s, only while the tab is visible, paused for `Retry-After` after a `429`
 * (the same document is retried after the pause; after any other failure only an edit or the
 * Validate button runs again). Explicit runs (the Validate button) go out at once and count for
 * the 10 s interval.
 */

export const AUTO_VALIDATE_DEBOUNCE_MS = 2_000;
export const AUTO_VALIDATE_MIN_INTERVAL_MS = 10_000;
/** Pause after a `429` without `Retry-After`. */
const DEFAULT_PAUSE_S = 30;

export type ValidateResponse = SuccessBody<'PolicyToolsController_validate_v1'>;
export type ValidateRequest = (
  definition: PolicyDslDocument,
  signal: AbortSignal,
) => Promise<ValidateResponse>;

export interface ValidationOutcome {
  /** Canonical JSON of the validated document (compare with the current one). */
  readonly key: string;
  readonly response: ValidateResponse;
  readonly origin: 'auto' | 'manual';
}

export interface ServerValidation {
  /** The last completed validation (of this or an earlier document). */
  readonly outcome: ValidationOutcome | null;
  readonly pending: boolean;
  /** The last failed attempt (network, `429`, `413`, …); cleared by the next success. */
  readonly error: ApiError | null;
  /** Automatic validation is paused until then (epoch ms) after a `429`. */
  readonly pausedUntil: number | null;
  /** Validates the current document now; resolves with the outcome (null on failure). */
  readonly validateNow: () => Promise<ValidationOutcome | null>;
}

const defaultRequest: ValidateRequest = (definition, signal) =>
  callOperation('PolicyToolsController_validate_v1', { body: { definition } }, { signal });

const isVisible = () => typeof document === 'undefined' || document.visibilityState === 'visible';

export function useServerValidation(
  definition: PolicyDslDocument | null,
  options: {
    /** Automatic validation (edit mode with `policy:manage`). */
    auto: boolean;
    /** Called with every completed validation (pages map the violations onto the nodes). */
    onOutcome?: (outcome: ValidationOutcome) => void;
    request?: ValidateRequest;
  },
): ServerValidation {
  const { auto } = options;
  const key = useMemo(() => (definition ? canonicalJson(definition) : null), [definition]);
  const [outcome, setOutcome] = useState<ValidationOutcome | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [pausedUntil, setPausedUntil] = useState<number | null>(null);
  const [visibleTick, setVisibleTick] = useState(0);
  const [settledTick, setSettledTick] = useState(0);

  const latest = useRef({
    key,
    definition,
    onOutcome: options.onOutcome,
    request: options.request ?? defaultRequest,
  });
  latest.current = {
    key,
    definition,
    onOutcome: options.onOutcome,
    request: options.request ?? defaultRequest,
  };
  /** When the last run started (the 10 s interval). */
  const lastRunAt = useRef<number | null>(null);
  /**
   * The document of the last success or non-retryable failure (no automatic re-run). The
   * document the page opened with counts as settled: only an edit starts automatic validation
   * (a stored draft was validated when it was saved; an empty new policy is not yet worth one).
   */
  const settledKey = useRef<string | null>(key);
  const inflight = useRef<{
    key: string;
    promise: Promise<ValidationOutcome | null>;
    controller: AbortController;
  } | null>(null);
  const editedAt = useRef<{ key: string | null; at: number }>({ key, at: Date.now() });
  const pausedRef = useRef<number | null>(null);
  pausedRef.current = pausedUntil;
  const mounted = useRef(true);

  // When the document last changed (the 2 s debounce counts from the latest edit).
  useEffect(() => {
    if (editedAt.current.key !== key) editedAt.current = { key, at: Date.now() };
  }, [key]);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      inflight.current?.controller.abort();
    };
  }, []);

  const run = useCallback((origin: 'auto' | 'manual'): Promise<ValidationOutcome | null> => {
    const { key: runKey, definition: doc, request } = latest.current;
    if (runKey === null || doc === null) return Promise.resolve(null);
    if (inflight.current?.key === runKey) return inflight.current.promise;
    inflight.current?.controller.abort();
    const controller = new AbortController();
    lastRunAt.current = Date.now();
    setPending(true);
    const promise = request(doc, controller.signal)
      .then((response): ValidationOutcome | null => {
        if (!mounted.current || controller.signal.aborted) return null;
        const next: ValidationOutcome = { key: runKey, response, origin };
        settledKey.current = runKey;
        setOutcome(next);
        setError(null);
        latest.current.onOutcome?.(next);
        return next;
      })
      .catch((caught: unknown): ValidationOutcome | null => {
        if (!mounted.current || controller.signal.aborted) return null;
        const apiError =
          caught instanceof ApiError
            ? caught
            : new ApiError({ status: 0, code: 'client_error', message: 'Validation failed' });
        if (apiError.status === 429) {
          setPausedUntil(Date.now() + (apiError.retryAfterSeconds ?? DEFAULT_PAUSE_S) * 1000);
        } else {
          settledKey.current = runKey;
        }
        setError(apiError);
        return null;
      })
      .finally(() => {
        if (inflight.current?.controller === controller) {
          inflight.current = null;
          if (mounted.current) {
            setPending(false);
            setSettledTick((n) => n + 1);
          }
        }
      });
    inflight.current = { key: runKey, promise, controller };
    return promise;
  }, []);

  const validateNow = useCallback(() => run('manual'), [run]);

  // The automatic schedule, re-planned on every edit, settled run, pause change and tab return.
  useEffect(() => {
    if (!auto || key === null) return undefined;
    if (settledKey.current === key || inflight.current?.key === key) return undefined;
    const due = Math.max(
      editedAt.current.key === key ? editedAt.current.at + AUTO_VALIDATE_DEBOUNCE_MS : 0,
      (lastRunAt.current ?? Number.NEGATIVE_INFINITY) + AUTO_VALIDATE_MIN_INTERVAL_MS,
      pausedRef.current ?? Number.NEGATIVE_INFINITY,
    );
    const timer = setTimeout(
      () => {
        if (!isVisible()) return; // resumed by the visibilitychange listener
        if (latest.current.key !== key || settledKey.current === key) return;
        void run('auto');
      },
      Math.max(0, due - Date.now()),
    );
    return () => clearTimeout(timer);
  }, [auto, key, pausedUntil, visibleTick, settledTick, run]);

  useEffect(() => {
    if (!auto || typeof document === 'undefined') return undefined;
    const onVisibility = () => {
      if (document.visibilityState === 'visible') setVisibleTick((n) => n + 1);
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => document.removeEventListener('visibilitychange', onVisibility);
  }, [auto]);

  // The pause ends by itself (the schedule is re-planned when it expires).
  useEffect(() => {
    if (pausedUntil === null) return undefined;
    const timer = setTimeout(() => setPausedUntil(null), Math.max(0, pausedUntil - Date.now()));
    return () => clearTimeout(timer);
  }, [pausedUntil]);

  return { outcome, pending, error, pausedUntil, validateNow };
}
