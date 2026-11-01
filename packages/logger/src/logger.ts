import { trace } from '@opentelemetry/api';
import pino, { type Logger, type LoggerOptions } from 'pino';
import { getContext } from './context';

export type { Logger } from 'pino';

export interface CreateLoggerOptions {
  service: string;
  level?: string;
  version?: string;
  /** Override the destination (tests). Defaults to stdout. */
  destination?: pino.DestinationStream;
}

/** Paths that must never reach logs. Extend rather than bypass. */
export const REDACT_PATHS = [
  'password',
  '*.password',
  'secret',
  '*.secret',
  'token',
  '*.token',
  'authorization',
  'req.headers.authorization',
  'req.headers.cookie',
  'headers.authorization',
  'headers.cookie',
];

/**
 * Structured JSON logger. Every line carries service, correlationId, tenantId and
 * trace/span ids when available, so logs join up with traces in Grafana.
 */
export function createLogger(options: CreateLoggerOptions): Logger {
  const config: LoggerOptions = {
    level: options.level ?? 'info',
    base: { service: options.service, version: options.version },
    timestamp: pino.stdTimeFunctions.isoTime,
    messageKey: 'message',
    formatters: {
      level: (label) => ({ level: label }),
    },
    redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
    mixin() {
      const ctx = getContext();
      const span = trace.getActiveSpan()?.spanContext();
      return {
        ...(ctx?.correlationId && { correlationId: ctx.correlationId }),
        ...(ctx?.tenantId && { tenantId: ctx.tenantId }),
        ...(span && { traceId: span.traceId, spanId: span.spanId }),
      };
    },
  };
  return options.destination ? pino(config, options.destination) : pino(config);
}
