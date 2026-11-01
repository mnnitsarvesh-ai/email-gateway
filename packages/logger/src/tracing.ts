import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';

let sdk: NodeSDK | undefined;

/**
 * Starts OpenTelemetry tracing when OTEL_EXPORTER_OTLP_ENDPOINT is set; a no-op otherwise.
 * Must run before any instrumented module (http, express, mysql2, amqplib, ioredis) is loaded,
 * so each service imports its `instrumentation.ts` as the very first statement of `main.ts`.
 */
export function startTracing(serviceName: string): void {
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
