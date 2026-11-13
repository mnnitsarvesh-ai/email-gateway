import 'server-only';
import type { OperationId, SuccessBody } from '@/lib/api/types';

/** Present in every dev fixture module; `scripts/assert-no-mock-layer.mjs` fails the build on it. */
export const DEV_MOCK_MARKER = 'eg-dev-mock-layer-7f3a9c';

export interface FixtureRequest {
  readonly operationId: OperationId;
  readonly method: string;
  readonly params: Readonly<Record<string, string>>;
  readonly query: URLSearchParams;
  readonly body: unknown;
  /** Bearer token the BFF sent (`null` for public operations). */
  readonly token: string | null;
  readonly headers: Headers;
}

export interface FixtureResponse {
  readonly status: number;
  readonly body?: unknown;
  readonly headers?: Readonly<Record<string, string>>;
}

export type FixtureHandler = (
  request: FixtureRequest,
) => FixtureResponse | Promise<FixtureResponse>;

/** Fixture handlers of one feature, keyed by operation (design P9). */
export type FixtureHandlers = Partial<Record<OperationId, FixtureHandler>>;

/** A typed success response: the body is checked against the operation's OpenAPI schema. */
export function ok<Id extends OperationId>(
  _operationId: Id,
  body: SuccessBody<Id>,
  status: 200 | 201 | 202 = 200,
): FixtureResponse {
  return { status, body };
}

export function noContent(): FixtureResponse {
  return { status: 204 };
}

/** An error in the api envelope. */
export function apiError(
  status: number,
  code: string,
  message: string | string[],
  extra: Record<string, unknown> = {},
): FixtureResponse {
  return {
    status,
    body: {
      statusCode: status,
      error: code.toUpperCase(),
      code,
      message,
      requestId: crypto.randomUUID(),
      ...extra,
    },
  };
}
