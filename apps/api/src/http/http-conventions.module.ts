import { type MiddlewareConsumer, Module, type NestModule } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { ApiExceptionFilter } from './api-exception.filter';
import { HttpMetricsMiddleware } from './http-metrics.middleware';
import { RequestIdMiddleware } from './request-id.middleware';

/**
 * HTTP conventions of every api route (step 6.1 D1, D2, D16): the request id and
 * `Cache-Control` middleware, the HTTP metrics middleware and the `ApiExceptionFilter` as an
 * `APP_FILTER`. Nest registers `APP_FILTER`s before `useGlobalFilters`, so behind
 * `configureHttpApp` the shared catch-all `AllExceptionsFilter` would win; `configureApiApp`
 * therefore also registers the filter with `useGlobalFilters` after it (that registration is
 * the one that renders errors in the running api; the `APP_FILTER` covers an app compiled
 * without `configureHttpApp`).
 *
 * Deliberately NOT global: Nest registers the middleware of global modules before every other
 * module's, and the request-id middleware must run after `CorrelationModule`'s (it extends the
 * async context the correlation middleware opens). AppModule imports it right after
 * CorrelationModule; both are at the same distance, so registration follows import order. The
 * building blocks other modules inject (cursor codec, idempotency interceptor, metrics) are
 * provided by the global ApiCommonModule.
 */
@Module({
  providers: [
    RequestIdMiddleware,
    HttpMetricsMiddleware,
    { provide: APP_FILTER, useClass: ApiExceptionFilter },
  ],
})
export class HttpConventionsModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestIdMiddleware, HttpMetricsMiddleware).forRoutes('*path');
  }
}
