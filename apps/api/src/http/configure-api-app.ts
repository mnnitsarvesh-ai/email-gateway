import { type INestApplication, RequestMethod } from '@nestjs/common';
import type { ApiConfig } from '../config';
import { ApiExceptionFilter } from './api-exception.filter';

/** The business API lives under `/api/v1/...` (ADR-0015). */
export const API_GLOBAL_PREFIX = 'api';

/**
 * API-specific HTTP setup, applied after the shared `configureHttpApp` by `main.ts` and by every
 * in-process test: the `/api` prefix (probes stay at `/health/live` and `/health/ready`, the
 * Prometheus scrape at `/metrics`, for the internal port only: never route it publicly) and the
 * Express `trust proxy` hop count that makes `req.ip` the real client behind the load balancer,
 * and the api's global `ApiExceptionFilter` (step 6.1 D1). Must run AFTER `configureHttpApp`
 * and before `app.init()` / `app.listen()`: Nest consults the last registered global filter
 * first, and the shared catch-all `AllExceptionsFilter` of `configureHttpApp` would otherwise
 * render every error without `code` and `requestId` (an `APP_FILTER` provider is registered
 * before both and loses to it; proved by test/conventions.e2e.test.ts).
 */
export function configureApiApp(
  app: INestApplication,
  config: Pick<ApiConfig, 'HTTP_TRUST_PROXY'>,
): void {
  app.setGlobalPrefix(API_GLOBAL_PREFIX, {
    exclude: [
      { path: 'health/live', method: RequestMethod.GET },
      { path: 'health/ready', method: RequestMethod.GET },
      { path: 'metrics', method: RequestMethod.GET },
    ],
  });
  const express = app.getHttpAdapter().getInstance() as {
    set: (setting: string, value: unknown) => void;
  };
  express.set('trust proxy', config.HTTP_TRUST_PROXY);
  app.useGlobalFilters(new ApiExceptionFilter());
}
