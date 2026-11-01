import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { getCorrelationId, type Logger } from '@email-gateway/logger';
import type { Response } from 'express';

export interface ErrorBody {
  statusCode: number;
  error: string;
  message: string | string[];
  correlationId?: string;
}

/**
 * Single place where exceptions become HTTP responses. Expected errors (HttpException) keep
 * their status and message; anything else is logged with its stack and returned as a generic
 * 500 so internals never leak to clients.
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  constructor(private readonly logger: Logger) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();
    const correlationId = getCorrelationId();
    const body = this.toBody(exception);
    body.correlationId = correlationId;

    if (body.statusCode >= 500) {
      this.logger.error({ err: exception }, 'Unhandled exception');
    }
    res.status(body.statusCode).json(body);
  }

  private toBody(exception: unknown): ErrorBody {
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const response = exception.getResponse();
      const message =
        typeof response === 'object' && response !== null && 'message' in response
          ? (response as { message: string | string[] }).message
          : exception.message;
      return { statusCode: status, error: HttpStatus[status] ?? 'Error', message };
    }
    return {
      statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'Internal server error',
    };
  }
}
