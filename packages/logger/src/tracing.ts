import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';

let sdk: NodeSDK | undefined;

export interface TracingOptions {
  /**
   * Incoming HTTP path prefixes that are never traced (e.g. the click-service's `/c/`, whose
   * paths and queries carry click tokens and continue nonces, ADR-0031). Matching is
   * case-insensitive (Express routes are) with repeated slashes collapsed. A matching request
   * runs with tracing suppressed: no server span, and no child span (database, Redis, fetcher)
   * is recorded either.
   */
  untracedIncomingPaths?: readonly string[];
}

/** The path of a request target (origin form or absolute form), lower case, slashes collapsed. */
function requestPath(target: string | undefined): string {
  let path = target ?? '/';
  if (!path.startsWith('/')) {
    try {
      path = new URL(path).pathname;
    } catch {
      return '/';
    }
  }
  const end = path.search(/[?#]/);
  return (end === -1 ? path : path.slice(0, end)).replace(/\/{2,}/g, '/').toLowerCase();
}

/** `ignoreIncomingRequestHook` of the http instrumentation for `untracedIncomingPaths`. */
export function untracedIncomingRequest(
  prefixes: readonly string[],
): (request: { url?: string }) => boolean {
  const normalized = prefixes.map((p) => p.toLowerCase());
  return (request) => {
    if (normalized.length === 0) return false;
    const path = requestPath(request.url);
    return normalized.some((prefix) => path.startsWith(prefix));
  };
}

/**
 * Starts OpenTelemetry tracing when OTEL_EXPORTER_OTLP_ENDPOINT is set; a no-op otherwise.
 * Must run before any instrumented module (http, express, mysql2, amqplib, ioredis) is loaded,
 * so each service imports its `instrumentation.ts` as the very first statement of `main.ts`.
 * Requests to untrusted URLs (the `@email-gateway/url-security` guarded fetcher) suppress
 * tracing themselves, so no propagation header ever reaches them (step 4.3 U8).
 */
export function startTracing(serviceName: string, options: TracingOptions = {}): void {
  const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  if (!endpoint || sdk) return;
  sdk = new NodeSDK({
    resource: resourceFromAttributes({
      [ATTR_SERVICE_NAME]: serviceName,
      [ATTR_SERVICE_VERSION]: process.env.SERVICE_VERSION ?? '0.0.0-dev',
    }),
    traceExporter: new OTLPTraceExporter({ url: `${endpoint.replace(/\/$/, '')}/v1/traces` }),
    instrumentations: [
      getNodeAutoInstrumentations({
        '@opentelemetry/instrumentation-fs': { enabled: false },
        '@opentelemetry/instrumentation-http': {
          ignoreIncomingRequestHook: untracedIncomingRequest(options.untracedIncomingPaths ?? []),
        },
      }),
    ],
  });
  sdk.start();
  const shutdown = (): void => {
    void sdk?.shutdown();
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}
