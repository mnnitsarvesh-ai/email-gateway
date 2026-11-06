import http, { type Server } from 'node:http';
import type { HealthService, MetricsService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';

/**
 * The admin listener (U14: CLICK_ADMIN_PORT, never behind the Ingress): `GET /health/live`,
 * `GET /health/ready` (MySQL through the click account, Redis) and `GET /metrics`. A separate
 * plain HTTP server, so none of these routes exists on the public listener; it shares the
 * process's HealthService and MetricsService (one registry).
 */
export function createAdminServer(deps: {
  health: Pick<HealthService, 'liveness' | 'readiness'>;
  metrics: Pick<MetricsService, 'metrics' | 'contentType'>;
  logger: Logger;
}): Server {
  const server = http.createServer((req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const path = (req.url ?? '/').split('?')[0];
    const json = (status: number, body: unknown): void => {
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(body));
    };
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      json(405, { statusCode: 405, error: 'Method Not Allowed' });
      return;
    }
    if (path === '/health/live') {
      json(200, deps.health.liveness());
      return;
    }
    if (path === '/health/ready') {
      deps.health.readiness().then(
        (report) => json(report.status === 'ok' ? 200 : 503, report),
        () => json(503, { status: 'error' }),
      );
      return;
    }
    if (path === '/metrics') {
      deps.metrics.metrics().then(
        (body) => {
          res.writeHead(200, { 'Content-Type': deps.metrics.contentType });
          res.end(body);
        },
        (error: unknown) => {
          deps.logger.error(
            { errName: error instanceof Error ? error.name : typeof error },
            'metrics failed',
          );
          json(500, { statusCode: 500, error: 'Internal Server Error' });
        },
      );
      return;
    }
    json(404, { statusCode: 404, error: 'Not Found' });
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  return server;
}

export function listen(server: Server, port: number, host: string): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      const address = server.address();
      resolve(typeof address === 'object' && address ? address.port : port);
    });
  });
}

export function close(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections();
  });
}
