# ADR-0011: Structured logs, correlation IDs, OpenTelemetry, Prometheus, Grafana

**Status:** Accepted (metrics bullet amended by [ADR-0019](0019-smtp-gateway-topology.md))

**Decision.**

- **Logs**: pino JSON to stdout with `level`, `time`, `service`, `version`, `message`, plus `correlationId`, `tenantId`, `traceId` and `spanId` when known. Credentials and auth headers are redacted. `console.*` is banned by lint.
- **Correlation**: `x-correlation-id` is accepted only when it matches `[A-Za-z0-9._:-]{8,128}` (preventing log injection) and is minted otherwise. It is echoed on responses, held in `AsyncLocalStorage` and copied into every event envelope.
- **Tracing**: OpenTelemetry Node SDK with auto-instrumentation, started before any instrumented module loads (`src/instrumentation.ts`, imported first in `main.ts`). It is enabled by setting `OTEL_EXPORTER_OTLP_ENDPOINT`. Spans export over OTLP/HTTP to an OpenTelemetry Collector. Exceptions (step 4.3): requests of the URL guarded fetcher to untrusted sites run with tracing suppressed (no propagation headers, no spans with their paths), and a service may exclude incoming path prefixes (`startTracing(service, { untracedIncomingPaths })`; the click-service excludes `/c/`, whose paths carry click tokens).
- **Metrics**: the Collector exposes OTLP metrics to Prometheus. RabbitMQ is scraped directly. Grafana is provisioned with Prometheus as a data source. Locally these run under the Compose `observability` profile.

**Consequences.** Every new service imports `instrumentation.ts` first. The production tracing backend (Tempo or X-Ray) is chosen with the infrastructure phase.
