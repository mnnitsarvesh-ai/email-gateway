'use client';

import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
  type QueryKey,
  type UseQueryOptions,
  type UseQueryResult,
} from '@tanstack/react-query';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { toast } from 'sonner';
import { emitSessionEvent } from '@/lib/session/events';
import { callOperation, callOperationRaw, type OperationInput } from './call';
import { newIdempotencyKey } from './client';
import { ApiError, mapValidationErrors } from './errors';
import { operations } from './operations.gen';
import type { ListItem, OperationId, QueryParams, SuccessBody } from './types';

/** Query key convention (P8): `[operationId, params]`. */
export function queryKeyFor<Id extends OperationId>(
  operationId: Id,
  input?: Omit<OperationInput<Id>, 'body'>,
): QueryKey {
  return input ? [operationId, input] : [operationId];
}

/** Retry only network errors and 503, never 4xx (P8). */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (failureCount >= 2) return false;
  return error instanceof ApiError && (error.status === 0 || error.status === 503);
}

function defaultsFor(operationId: OperationId) {
  const op = operations[operationId];
  if (op.tag === 'reports') return { staleTime: 60_000, refetchOnWindowFocus: false } as const;
  if (op.listKey) return { staleTime: 30_000 } as const;
  return { staleTime: 30_000 } as const;
}

type QueryOpts<Id extends OperationId> = Omit<
  UseQueryOptions<SuccessBody<Id>, ApiError, SuccessBody<Id>, QueryKey>,
  'queryKey' | 'queryFn'
>;

/** A typed GET (or other read) of one operation through the BFF. */
export function useApiQuery<Id extends OperationId>(
  operationId: Id,
  input?: Omit<OperationInput<Id>, 'body'>,
  options: QueryOpts<Id> = {},
): UseQueryResult<SuccessBody<Id>, ApiError> {
  return useQuery<SuccessBody<Id>, ApiError, SuccessBody<Id>, QueryKey>({
    queryKey: queryKeyFor(operationId, input),
    queryFn: ({ signal }) => callOperation(operationId, input ?? {}, { signal }),
    retry: shouldRetry,
    ...defaultsFor(operationId),
    ...(operations[operationId].returnsSecret ? { gcTime: 0 } : {}),
    ...options,
  });
}

export interface CursorListState<Id extends OperationId> {
  readonly rows: ListItem<Id>[];
  readonly nextCursor: string | null;
  /** 1-based page number of the forward keyset walk ("Page 3 · 25 rows"; no totals). */
  readonly page: number;
  readonly hasPrevious: boolean;
  readonly hasNext: boolean;
  /** Fewer rows than `limit` but more may exist (scan budget, 6.1 D6). */
  readonly isShortPage: boolean;
  readonly limit: number;
  readonly next: () => void;
  readonly previous: () => void;
  readonly reset: () => void;
  readonly query: UseQueryResult<SuccessBody<Id>, ApiError>;
}

/**
 * Forward keyset pagination of a list operation (`{ data | items, nextCursor }`, cursor v0 and
 * v1). The cursor stack lives in component state; any change of `filters` resets it (a v1
 * cursor is bound to its filters). Short pages with a `nextCursor` stay navigable.
 */
export function useCursorList<Id extends OperationId>(
  operationId: Id,
  filters: QueryParams<Id> | undefined,
  options: { path?: OperationInput<Id>['path']; limit?: number; enabled?: boolean } = {},
): CursorListState<Id> {
  const op = operations[operationId];
  if (!op.listKey) throw new Error(`${operationId} is not a list operation`);
  const listKey = op.listKey;
  const limit = options.limit ?? 25;
  const filterKey = JSON.stringify([filters ?? {}, options.path ?? {}, limit]);
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
  const query = {
    ...(filters ?? {}),
    limit,
    ...(cursor ? { cursor } : {}),
  } as unknown as QueryParams<Id>;
  const result = useApiQuery(
    operationId,
    { path: options.path, query },
    { placeholderData: keepPreviousData, enabled: options.enabled ?? true },
  );
  const body = result.data as Record<string, unknown> | undefined;
  const rows = useMemo(
    () => (Array.isArray(body?.[listKey]) ? body?.[listKey] : EMPTY) as ListItem<Id>[],
    [body, listKey],
  );
  const nextCursor = typeof body?.nextCursor === 'string' ? body.nextCursor : null;

  const next = useCallback(() => {
    if (!nextCursor) return;
    setStack({ key: filterKey, cursors: [...cursors, nextCursor] });
  }, [cursors, filterKey, nextCursor]);
  const previous = useCallback(() => {
    if (cursors.length <= 1) return;
    setStack({ key: filterKey, cursors: cursors.slice(0, -1) });
  }, [cursors, filterKey]);
  const reset = useCallback(() => setStack({ key: filterKey, cursors: [null] }), [filterKey]);

  return {
    rows,
    nextCursor,
    page: cursors.length,
    hasPrevious: cursors.length > 1,
    hasNext: nextCursor !== null,
    isShortPage: nextCursor !== null && rows.length < limit,
    limit,
    next,
    previous,
    reset,
    query: result,
  };
}

const EMPTY: readonly never[] = [];

/** Wait between automatic retries of `409 idempotency_request_in_progress` (P8). */
const MAX_IN_PROGRESS_WAIT_S = 10;
const MAX_IN_PROGRESS_RETRIES = 2;

export interface ApiMutationOptions<Id extends OperationId> {
  /** Called after success (also after a replayed success). */
  onSuccess?: (data: SuccessBody<Id>, meta: { replayed: boolean }) => void | Promise<void>;
  /** Operations whose cached queries become stale after success. */
  invalidates?: readonly OperationId[];
  /** Toast text on success (`null` = no toast). */
  successMessage?: string | null;
  /** Injectable sleep (tests). */
  sleep?: (ms: number) => Promise<void>;
}

/** Result of one submit: success with the (possibly empty, 204) body, or the ApiError. */
export type MutationOutcome<Id extends OperationId> =
  | { readonly ok: true; readonly data: SuccessBody<Id> }
  | { readonly ok: false; readonly error: ApiError };

export interface ApiMutation<Id extends OperationId> {
  /** Starts a new user intent (new Idempotency-Key). Never throws. */
  submit: (input: OperationInput<Id>) => Promise<MutationOutcome<Id>>;
  /** Manual retry of the last intent: same input, same Idempotency-Key. */
  retry: () => Promise<MutationOutcome<Id>>;
  readonly data: SuccessBody<Id> | undefined;
  readonly error: ApiError | null;
  readonly isPending: boolean;
  readonly isSuccess: boolean;
  /** Seconds until a rate-limited submit may be retried (429 countdown), else 0. */
  readonly retryAfterSeconds: number;
  /** The current intent's key (exposed for tests and diagnostics only). */
  readonly idempotencyKey: string | null;
  /** Field and form-level messages of a 400/409/422 error for a form with these fields. */
  formErrors: (fields: readonly string[]) => {
    fieldErrors: Record<string, string>;
    formErrors: string[];
  };
  /** Forgets data and error (secret dialogs call this on close: P12). */
  reset: () => void;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * A mutation with the P8 rules: one Idempotency-Key per intent, reused for retries of that
 * intent; `409 idempotency_request_in_progress` waits `Retry-After` (≤ 10 s) and retries with
 * the same key (twice at most); `Idempotency-Replayed: true` counts as success ("Already
 * applied"); `422 idempotency_key_reused` is a programming error (toast with requestId); `429`
 * starts a countdown; `403 mfa_required` raises the MFA dialog event; other 4xx stay on the form.
 */
export function useApiMutation<Id extends OperationId>(
  operationId: Id,
  options: ApiMutationOptions<Id> = {},
): ApiMutation<Id> {
  const op = operations[operationId];
  const queryClient = useQueryClient();
  const keyRef = useRef<string | null>(null);
  const inputRef = useRef<OperationInput<Id> | null>(null);
  const [retryAfter, setRetryAfter] = useState(0);
  const sleep = options.sleep ?? defaultSleep;
  const optionsRef = useRef(options);
  optionsRef.current = options;

  useEffect(() => {
    if (retryAfter <= 0) return;
    const timer = setTimeout(() => setRetryAfter((s) => Math.max(0, s - 1)), 1000);
    return () => clearTimeout(timer);
  }, [retryAfter]);

  const mutation = useMutation<SuccessBody<Id>, ApiError, OperationInput<Id>>({
    mutationKey: [operationId],
    gcTime: op.returnsSecret ? 0 : undefined,
    retry: false,
    mutationFn: async (input) => {
      const idempotencyKey = op.idempotency ? (keyRef.current ?? undefined) : undefined;
      for (let attempt = 0; ; attempt += 1) {
        try {
          const { data, response } = await callOperationRaw(operationId, input, { idempotencyKey });
          const replayed = response.headers.get('idempotency-replayed') === 'true';
          const current = optionsRef.current;
          if (replayed) toast.success('Already applied');
          else if (current.successMessage) toast.success(current.successMessage);
          await current.onSuccess?.(data, { replayed });
          for (const id of current.invalidates ?? []) {
            await queryClient.invalidateQueries({ queryKey: [id] });
          }
          keyRef.current = null;
          return data;
        } catch (error) {
          if (
            error instanceof ApiError &&
            error.status === 409 &&
            error.code === 'idempotency_request_in_progress' &&
            attempt < MAX_IN_PROGRESS_RETRIES
          ) {
            await sleep(Math.min(error.retryAfterSeconds ?? 1, MAX_IN_PROGRESS_WAIT_S) * 1000);
            continue;
          }
          throw error;
        }
      }
    },
    onError: (error) => {
      if (!(error instanceof ApiError)) return;
      if (error.status === 429) {
        const seconds = error.retryAfterSeconds ?? 30;
        setRetryAfter(seconds);
        toast.error(`Too many requests. Try again in ${seconds} s.`);
      } else if (error.status === 403 && error.code === 'mfa_required') {
        emitSessionEvent({ type: 'mfa-required' });
      } else if (error.status === 422 && error.code === 'idempotency_key_reused') {
        keyRef.current = null;
        toast.error(
          `The request could not be applied (idempotency key reused). Request ID: ${error.requestId ?? 'unknown'}`,
        );
      } else if (error.status === 0) {
        toast.error(error.message);
      }
    },
  });

  const run = useCallback(
    async (input: OperationInput<Id>): Promise<MutationOutcome<Id>> => {
      try {
        return { ok: true, data: await mutation.mutateAsync(input) };
      } catch (error) {
        return {
          ok: false,
          error:
            error instanceof ApiError
              ? error
              : new ApiError({ status: 0, code: 'client_error', message: 'The request failed' }),
        };
      }
    },
    [mutation],
  );

  const submit = useCallback(
    async (input: OperationInput<Id>): Promise<MutationOutcome<Id>> => {
      keyRef.current = op.idempotency ? newIdempotencyKey() : null;
      inputRef.current = input;
      return run(input);
    },
    [op.idempotency, run],
  );

  const retry = useCallback(async (): Promise<MutationOutcome<Id>> => {
    if (!inputRef.current) {
      return {
        ok: false,
        error: new ApiError({
          status: 0,
          code: 'no_previous_request',
          message: 'Nothing to retry',
        }),
      };
    }
    if (op.idempotency && !keyRef.current) keyRef.current = newIdempotencyKey();
    return run(inputRef.current);
  }, [op.idempotency, run]);

  const formErrors = useCallback(
    (fields: readonly string[]) => {
      const error = mutation.error;
      if (!error) return { fieldErrors: {}, formErrors: [] };
      return mapValidationErrors(error, fields);
    },
    [mutation.error],
  );

  const reset = mutation.reset;
  return useMemo(
    () => ({
      submit,
      retry,
      data: mutation.data,
      error: mutation.error ?? null,
      isPending: mutation.isPending,
      isSuccess: mutation.isSuccess,
      retryAfterSeconds: retryAfter,
      idempotencyKey: keyRef.current,
      formErrors,
      reset,
    }),
    [
      submit,
      retry,
      mutation.data,
      mutation.error,
      mutation.isPending,
      mutation.isSuccess,
      retryAfter,
      formErrors,
      reset,
    ],
  );
}
