import {
  type CallHandler,
  type ExecutionContext,
  Injectable,
  type NestInterceptor,
} from '@nestjs/common';
import type { Response } from 'express';
import { catchError, type Observable, throwError } from 'rxjs';
import { DomainRateLimitedException } from '../domains.errors';

/** Sets `Retry-After` on the response when a service refuses with a known wait time. */
@Injectable()
export class RetryAfterInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    return next.handle().pipe(
      catchError((err: unknown) => {
        if (err instanceof DomainRateLimitedException) {
          context
            .switchToHttp()
            .getResponse<Response>()
            .setHeader('Retry-After', String(err.retryAfterSeconds));
        }
        return throwError(() => err);
      }),
    );
  }
}
