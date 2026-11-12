import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
  ForbiddenException,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { ApiResponse } from '@nestjs/swagger';
import type { SchemaObject } from '@nestjs/swagger/dist/interfaces/open-api-spec.interface';
import { getCorrelationId } from '@email-gateway/logger';
import type { Response } from 'express';
import { ensureRequestId } from './request-id.middleware';

type CodedErrorScalar = string | number | boolean | null;

/**
 * Extra fields of a coded error body: ids, states, versions and codes only, never content. A
 * field may be a list of flat records (e.g. the `violations` of `scan_settings_invalid`).
 */
export type CodedErrorDetails = Readonly<
  Record<string, CodedErrorScalar | readonly Readonly<Record<string, CodedErrorScalar>>[]>
>;

/**
 * An HTTP error with a stable machine-readable `code` (e.g. `message_version_conflict`) next to
 * the human `message`, plus optional detail fields. Rendered by the global `ApiExceptionFilter`
 * (step 6.1) and, identically, by the controller-scoped `CodedExceptionFilter`. Step 3.3 L10/L11.
 */
export class CodedHttpException extends HttpException {
  constructor(
    status: HttpStatus,
    readonly code: string,
    message: string,
    readonly details: CodedErrorDetails = {},
  ) {
    super({ message, code }, status);
  }
}

/**
 * A coded `403` that is also a `ForbiddenException` (step 6.1 D2), for the global
 * PermissionsGuard whose callers and tests treat its refusals as ForbiddenException. The global
 * ApiExceptionFilter renders its `code` (it reads the code of the exception's response object),
 * so the body is the same as a CodedHttpException's.
 */
export class CodedForbiddenException extends ForbiddenException {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super({ message, code });
  }
}

/** The body of a coded error: the standard error body plus `code` and the details. */
export interface CodedErrorBody {
  statusCode: number;
  error: string;
  code: string;
  message: string;
  correlationId?: string;
  /** The server-minted `X-Request-Id` of the request (step 6.1 D1). */
  requestId?: string;
  [detail: string]: unknown;
}

export function codedErrorBody(exception: CodedHttpException): CodedErrorBody {
  const status = exception.getStatus();
  return {
    ...exception.details,
    statusCode: status,
    error: HttpStatus[status] ?? 'Error',
    code: exception.code,
    message: exception.message,
  };
}

/**
 * Writes an error body with the request's `correlationId` and `requestId` (step 6.1 D1). Shared by
 * the global ApiExceptionFilter and CodedExceptionFilter so both render the same bytes.
 */
export function sendErrorBody(res: Response, body: CodedErrorBody | Record<string, unknown>): void {
  const out: Record<string, unknown> = { ...body };
  const correlationId = getCorrelationId();
  if (correlationId !== undefined) out.correlationId = correlationId;
  out.requestId = ensureRequestId(res);
  res.status(out.statusCode as number).json(out);
}

/**
 * Response headers a coded error asks for: `Retry-After` from a numeric `retryAfterSeconds`
 * property (e.g. `409 idempotency_request_in_progress`), unless a guard already set one.
 */
export function applyCodedHeaders(res: Response, exception: CodedHttpException): void {
  const retryAfter = (exception as { retryAfterSeconds?: unknown }).retryAfterSeconds;
  if (
    typeof retryAfter === 'number' &&
    Number.isFinite(retryAfter) &&
    !res.headersSent &&
    res.getHeader('Retry-After') === undefined
  ) {
    res.setHeader('Retry-After', String(Math.max(1, Math.ceil(retryAfter))));
  }
}

/**
 * Renders CodedHttpException with its `code` and details. Kept for the controllers that scope
 * it (since step 6.1 the global ApiExceptionFilter renders the same body for every route).
 */
@Catch(CodedHttpException)
export class CodedExceptionFilter implements ExceptionFilter<CodedHttpException> {
  catch(exception: CodedHttpException, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();
    applyCodedHeaders(res, exception);
    sendErrorBody(res, codedErrorBody(exception));
  }
}

/** OpenAPI schema of a coded error with the listed codes and optional detail properties. */
export function codedErrorSchema(
  status: number,
  codes: readonly string[],
  details: Record<string, SchemaObject> = {},
): SchemaObject {
  return {
    type: 'object',
    properties: {
      statusCode: { type: 'integer', enum: [status] },
      error: { type: 'string' },
      code: { type: 'string', enum: [...codes] },
      message: { type: 'string' },
      ...details,
      correlationId: { type: 'string' },
      requestId: { type: 'string', format: 'uuid' },
    },
    required: ['statusCode', 'error', 'code', 'message'],
  };
}

/** Documents one status answered with a coded error body. */
export const ApiCodedError = (
  status: number,
  description: string,
  codes: readonly string[],
  details: Record<string, SchemaObject> = {},
): MethodDecorator =>
  ApiResponse({ status, description, schema: codedErrorSchema(status, codes, details) });
