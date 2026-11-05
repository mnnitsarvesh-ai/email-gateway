import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { ApiResponse } from '@nestjs/swagger';
import type { SchemaObject } from '@nestjs/swagger/dist/interfaces/open-api-spec.interface';
import { getCorrelationId } from '@email-gateway/logger';
import type { Response } from 'express';

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
 * the human `message`, plus optional detail fields. Rendered by `CodedExceptionFilter` (the
 * global AllExceptionsFilter keeps only status and message). Step 3.3 L10/L11.
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

/** The body of a coded error: the standard error body plus `code` and the details. */
export interface CodedErrorBody {
  statusCode: number;
  error: string;
  code: string;
  message: string;
  correlationId?: string;
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

/** Renders CodedHttpException with its `code` and details; scope it to the controllers using it. */
@Catch(CodedHttpException)
export class CodedExceptionFilter implements ExceptionFilter<CodedHttpException> {
  catch(exception: CodedHttpException, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();
    const body: CodedErrorBody = { ...codedErrorBody(exception) };
    const correlationId = getCorrelationId();
    if (correlationId !== undefined) body.correlationId = correlationId;
    res.status(exception.getStatus()).json(body);
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
