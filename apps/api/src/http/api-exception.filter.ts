import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import {
  applyCodedHeaders,
  CodedHttpException,
  codedErrorBody,
  sendErrorBody,
} from './coded-exception';

/** Default `code` of an uncoded HttpException by status (step 6.1 §3.2). */
export const DEFAULT_ERROR_CODES: Readonly<Record<number, string>> = Object.freeze({
  [HttpStatus.BAD_REQUEST]: 'validation_failed',
  [HttpStatus.UNAUTHORIZED]: 'unauthorized',
  [HttpStatus.FORBIDDEN]: 'forbidden',
  [HttpStatus.NOT_FOUND]: 'not_found',
  [HttpStatus.CONFLICT]: 'conflict',
  [HttpStatus.PAYLOAD_TOO_LARGE]: 'payload_too_large',
  [HttpStatus.UNSUPPORTED_MEDIA_TYPE]: 'unsupported_media_type',
  [HttpStatus.UNPROCESSABLE_ENTITY]: 'unprocessable',
  [HttpStatus.TOO_MANY_REQUESTS]: 'rate_limited',
  [HttpStatus.INTERNAL_SERVER_ERROR]: 'internal_error',
  [HttpStatus.SERVICE_UNAVAILABLE]: 'service_unavailable',
});

/** `404` of a path no route serves (the router's not-found handler). */
export const ROUTE_NOT_FOUND = 'route_not_found';
export const INTERNAL_ERROR = 'internal_error';
const INTERNAL_MESSAGE = 'Internal server error';

/** A code an HttpException's own response object may carry (`{ message, code }`). */
const CODE_PATTERN = /^[a-z][a-z0-9_]{1,63}$/;

/** The default code of a status: §3.2, else the lower-cased status name, else by class. */
export function defaultErrorCode(status: number): string {
  const listed = DEFAULT_ERROR_CODES[status];
  if (listed !== undefined) return listed;
  if (status >= 500) return INTERNAL_ERROR;
  const name = HttpStatus[status];
  return name ? name.toLowerCase() : 'error';
}

/** `message` of an HttpException exactly as the shared AllExceptionsFilter rendered it. */
function messageOf(exception: HttpException): string | string[] {
  const response = exception.getResponse();
  if (typeof response === 'object' && response !== null && 'message' in response) {
    return (response as { message: string | string[] }).message;
  }
  return exception.message;
}

/**
 * The client error of Express's body parser (body-parser 2, `http-errors`) as an HttpException:
 * a `4xx` with `expose: true` and a `type` such as `entity.too.large` (413), `charset.unsupported`
 * (415) or `request.aborted` (400). Nest maps only the parser's `SyntaxError` (malformed JSON,
 * `400`); without this the others reached the filter as unexpected errors and were answered
 * `500 internal_error` (step 7.3 §14.8, B16). Anything else is `undefined`.
 */
export function bodyParserHttpException(exception: unknown): HttpException | undefined {
  if (!(exception instanceof Error)) return undefined;
  const e = exception as Error & { type?: unknown; status?: unknown; expose?: unknown };
  const status = e.status;
  if (typeof e.type !== 'string' || e.expose !== true || typeof status !== 'number') {
    return undefined;
  }
  if (!Number.isInteger(status) || status < 400 || status > 499) return undefined;
  if (e.type === 'entity.too.large') {
    const limit = (e as { limit?: unknown }).limit;
    const message =
      typeof limit === 'number'
        ? `Request body is larger than the ${limit}-byte limit of this route`
        : 'Request body is larger than the limit of this route';
    return new HttpException(message, status);
  }
  return new HttpException(e.message, status);
}

function ownCode(exception: HttpException): string | undefined {
  const response = exception.getResponse();
  if (typeof response !== 'object' || response === null) return undefined;
  const code = (response as { code?: unknown }).code;
  return typeof code === 'string' && CODE_PATTERN.test(code) ? code : undefined;
}

/**
 * The single error renderer of the api (step 6.1 D1, D2, §3.2), registered with `APP_FILTER` so
 * it takes precedence over the shared `AllExceptionsFilter` of `configureHttpApp` (proved by
 * test/conventions.e2e.test.ts). Every error is
 * `{ statusCode, error, code, message, correlationId, requestId, ...details }`:
 *
 * - `CodedHttpException` → its code and details (the same body as `CodedExceptionFilter`);
 * - another `HttpException` → its status and message (`string`, or `string[]` for validation)
 *   with the default code of its status (`route_not_found` for a path no route serves);
 * - a client error of the body parser (`bodyParserHttpException`) → as that HttpException
 *   (`413 payload_too_large` for a body above the route's JSON limit);
 * - anything else → `500 internal_error` with a generic message; logged with its stack, never
 *   rendered (no internals leak).
 */
@Catch()
export class ApiExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger('ApiExceptionFilter');

  catch(thrown: unknown, host: ArgumentsHost): void {
    const exception = bodyParserHttpException(thrown) ?? thrown;
    const http = host.switchToHttp();
    const res = http.getResponse<Response>();
    const req = http.getRequest<Request | undefined>();
    if (res.headersSent) {
      this.logger.error({ message: 'Exception after the response was sent', err: exception });
      return;
    }
    if (exception instanceof CodedHttpException) {
      if (exception.getStatus() >= 500) this.logServerError(exception);
      applyCodedHeaders(res, exception);
      sendErrorBody(res, codedErrorBody(exception));
      return;
    }
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      if (status >= 500) this.logServerError(exception);
      const unmatched = status === Number(HttpStatus.NOT_FOUND) && req !== undefined && !req.route;
      sendErrorBody(res, {
        statusCode: status,
        error: HttpStatus[status] ?? 'Error',
        code: unmatched ? ROUTE_NOT_FOUND : (ownCode(exception) ?? defaultErrorCode(status)),
        message: messageOf(exception),
      });
      return;
    }
    this.logServerError(exception);
    sendErrorBody(res, {
      statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
      error: 'INTERNAL_SERVER_ERROR',
      code: INTERNAL_ERROR,
      message: INTERNAL_MESSAGE,
    });
  }

  private logServerError(exception: unknown): void {
    this.logger.error({ message: 'Unhandled exception', err: exception });
  }
}
