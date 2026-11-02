import { type LoggerService } from '@nestjs/common';
import { type Logger } from '@email-gateway/logger';

type Fields = Record<string, unknown>;

/**
 * Nest's `Logger` passes the first argument through unchanged. A plain object becomes structured
 * pino fields (its `message` property is the log message), so `logger.log({ message, kind })`
 * keeps `kind` queryable and subject to redaction. Anything else is stringified.
 */
function split(message: unknown): [Fields, string] {
  if (message !== null && typeof message === 'object' && !(message instanceof Error)) {
    const { message: text, ...fields } = message as Fields;
    return [fields, typeof text === 'string' ? text : ''];
  }
  return [{}, String(message)];
}

/** Routes NestJS framework logs through the structured pino logger. */
export class NestPinoLogger implements LoggerService {
  constructor(private readonly logger: Logger) {}

  log(message: unknown, context?: string): void {
    const [fields, text] = split(message);
    this.logger.info({ ...fields, context }, text);
  }

  error(message: unknown, trace?: string, context?: string): void {
    const [fields, text] = split(message);
    this.logger.error({ ...fields, context, stack: trace }, text);
  }

  warn(message: unknown, context?: string): void {
    const [fields, text] = split(message);
    this.logger.warn({ ...fields, context }, text);
  }

  debug(message: unknown, context?: string): void {
    const [fields, text] = split(message);
    this.logger.debug({ ...fields, context }, text);
  }

  verbose(message: unknown, context?: string): void {
    const [fields, text] = split(message);
    this.logger.trace({ ...fields, context }, text);
  }
}
