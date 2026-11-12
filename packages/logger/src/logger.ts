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

/** Credential-bearing field names censored at the top level and one level down (`*.<name>`). */
const SECRET_FIELDS = [
  'password',
  'secret',
  'token',
  'authorization',
  'accessToken',
  'refreshToken',
  'mfaToken',
  'recoveryCode',
  'recoveryCodes',
  'code',
  'newPassword',
  'currentPassword',
  'key',
  'apiKey',
  'otpauthUri',
  // DKIM signing keys (step 2.1, ADR-0018).
  'privateKey',
  'privateKeyPem',
  'privateKeyCiphertext',
];

/**
 * Mail-content field names censored at the top level and one level down (step 3.1 M15). Defence
 * in depth: services log ids, codes and counts, never subjects, filenames, addresses, header
 * values or bodies. `recipients`, `from` and `to` are deliberately absent: they are used as
 * counts, status names and masked addresses.
 */
const MAIL_CONTENT_FIELDS = [
  'subject',
  'filename',
  'originalFilename',
  'envelopeFrom',
  'headerFrom',
  'headerValue',
  'textBody',
  'htmlBody',
  'rawHeaders',
];

/** Paths that must never reach logs. Extend rather than bypass. */
export const REDACT_PATHS = [
  ...SECRET_FIELDS.flatMap((field) => [field, `*.${field}`]),
  ...MAIL_CONTENT_FIELDS.flatMap((field) => [field, `*.${field}`]),
  // An event envelope logged whole (`{ event }` or the envelope itself).
  'payload.envelopeFrom',
  '*.payload.envelopeFrom',
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-api-key"]',
  'headers.authorization',
  'headers.cookie',
  'headers["x-api-key"]',
];

/**
 * Structured JSON logger. Every line carries service, correlationId, tenantId, requestId (api) and
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
        ...(ctx?.requestId && { requestId: ctx.requestId }),
        ...(span && { traceId: span.traceId, spanId: span.spanId }),
      };
    },
  };
  return options.destination ? pino(config, options.destination) : pino(config);
}
