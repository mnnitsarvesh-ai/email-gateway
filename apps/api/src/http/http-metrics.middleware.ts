import { Injectable, type NestMiddleware } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { ApiConventionMetrics } from './api-metrics';

/** `route` label of a request no route served (unknown path, or failed before routing). */
export const UNMATCHED_ROUTE = 'unmatched';

/**
 * The route label of a finished request: the Express route template including the `/api`
 * prefix (e.g. `/api/v1/messages/:messageId`), or `unmatched`. Never the concrete path, so ids
 * never become label values.
 */
export function routeLabel(req: Pick<Request, 'route' | 'baseUrl'>): string {
  const template = (req.route as { path?: unknown } | undefined)?.path;
  if (typeof template !== 'string') return UNMATCHED_ROUTE;
  return `${req.baseUrl ?? ''}${template}`;
}

export function statusClass(status: number): string {
  return status >= 100 && status < 600 ? `${Math.floor(status / 100)}xx` : 'other';
}

/**
 * `api_http_requests_total{method,route,status_class}` and
 * `api_http_request_duration_seconds{method,route}` (step 6.1 D16), recorded when the response
 * finishes (or the connection closes first).
 */
@Injectable()
export class HttpMetricsMiddleware implements NestMiddleware {
  constructor(private readonly metrics: ApiConventionMetrics) {}

  use(req: Request, res: Response, next: NextFunction): void {
    const started = process.hrtime.bigint();
    let recorded = false;
    const record = (): void => {
      if (recorded) return;
      recorded = true;
      const route = routeLabel(req);
      const method = req.method.toUpperCase();
      this.metrics.httpRequests.inc({ method, route, status_class: statusClass(res.statusCode) });
      this.metrics.httpDuration.observe(
        { method, route },
        Number(process.hrtime.bigint() - started) / 1e9,
      );
    };
    res.once('finish', record);
    res.once('close', record);
    next();
  }
}
