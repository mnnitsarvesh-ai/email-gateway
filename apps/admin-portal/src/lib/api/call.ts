import { api, unwrap } from './client';
import { ApiError, networkError, toApiError } from './errors';
import { operations } from './operations.gen';
import type { OperationId, PathParams, QueryParams, RequestBody, SuccessBody } from './types';

/** Request input of an operation: path and query parameters, JSON body. */
export type OperationInput<Id extends OperationId> = {
  path?: PathParams<Id>;
  query?: QueryParams<Id>;
  body?: RequestBody<Id>;
};

export interface CallOptions {
  readonly signal?: AbortSignal;
  readonly idempotencyKey?: string;
}

export interface RawResult<Id extends OperationId> {
  readonly data: SuccessBody<Id>;
  readonly response: Response;
}

type LooseMethod = (
  path: string,
  init: Record<string, unknown>,
) => Promise<{ data?: unknown; error?: unknown; response: Response }>;

function invoke<Id extends OperationId>(
  operationId: Id,
  input: OperationInput<Id>,
  options: CallOptions,
) {
  const op = operations[operationId];
  const method = (api as unknown as Record<string, LooseMethod>)[op.method];
  if (!method) throw new Error(`Unsupported method ${op.method}`);
  const headers: Record<string, string> = {};
  if (options.idempotencyKey && op.idempotency) headers['Idempotency-Key'] = options.idempotencyKey;
  return method(op.path, {
    params: { path: input.path, query: input.query },
    ...(input.body !== undefined ? { body: input.body } : {}),
    headers,
    signal: options.signal,
  });
}

/** Calls an operation by id through the typed client; throws ApiError on failure. */
export function callOperation<Id extends OperationId>(
  operationId: Id,
  input: OperationInput<Id> = {},
  options: CallOptions = {},
): Promise<SuccessBody<Id>> {
  return unwrap(invoke(operationId, input, options), operationId) as Promise<SuccessBody<Id>>;
}

/** Like `callOperation` but also returns the response (headers such as `Idempotency-Replayed`). */
export async function callOperationRaw<Id extends OperationId>(
  operationId: Id,
  input: OperationInput<Id> = {},
  options: CallOptions = {},
): Promise<RawResult<Id>> {
  let result: { data?: unknown; error?: unknown; response: Response };
  try {
    result = await invoke(operationId, input, options);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw networkError(error, operationId);
  }
  if (!result.response.ok) throw toApiError(result.response, result.error, operationId);
  return { data: result.data as SuccessBody<Id>, response: result.response };
}
