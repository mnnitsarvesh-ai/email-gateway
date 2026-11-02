import { type INestApplication, RequestMethod } from '@nestjs/common';
import type { ApiConfig } from '../config';

/** The business API lives under `/api/v1/...` (ADR-0015). */
export const API_GLOBAL_PREFIX = 'api';

/**
 * API-specific HTTP setup, applied after the shared `configureHttpApp` by `main.ts` and by every
 * in-process test: the `/api` prefix (probes stay at `/health/live` and `/health/ready`) and the
 * Express `trust proxy` hop count that makes `req.ip` the real client behind the load balancer.
 * Must run before `app.init()` / `app.listen()`.
 */
export function configureApiApp(
  app: INestApplication,
  config: Pick<ApiConfig, 'HTTP_TRUST_PROXY'>,
): void {
  app.setGlobalPrefix(API_GLOBAL_PREFIX, {
    exclude: [
      { path: 'health/live', method: RequestMethod.GET },
      { path: 'health/ready', method: RequestMethod.GET },
    ],
  });
  const express = app.getHttpAdapter().getInstance() as {
    set: (setting: string, value: unknown) => void;
  };
  express.set('trust proxy', config.HTTP_TRUST_PROXY);
}
