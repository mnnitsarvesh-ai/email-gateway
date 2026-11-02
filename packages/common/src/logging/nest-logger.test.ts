import { Writable } from 'node:stream';
import { createLogger } from '@email-gateway/logger';
import { describe, expect, it } from 'vitest';
import { NestPinoLogger } from './nest-logger';

function captured(): { logger: NestPinoLogger; lines: () => Record<string, unknown>[] } {
  const chunks: string[] = [];
  const destination = new Writable({
    write(chunk: Buffer, _enc, cb) {
      chunks.push(chunk.toString());
      cb();
    },
  });
  return {
    logger: new NestPinoLogger(createLogger({ service: 'test', level: 'trace', destination })),
    lines: () =>
      chunks
        .join('')
        .trim()
        .split('\n')
        .map((l) => JSON.parse(l) as Record<string, unknown>),
  };
}

describe('NestPinoLogger', () => {
  it('logs string messages with their context', () => {
    const { logger, lines } = captured();
    logger.log('started', 'Bootstrap');
    expect(lines()[0]).toMatchObject({ level: 'info', message: 'started', context: 'Bootstrap' });
  });

  it('turns object messages into structured, redacted fields', () => {
    const { logger, lines } = captured();
    logger.warn({ message: 'email logged', kind: 'invitation', token: 'egt_secret' }, 'Email');
    const [line] = lines();
    expect(line).toMatchObject({
      level: 'warn',
      message: 'email logged',
      kind: 'invitation',
      context: 'Email',
      token: '[REDACTED]',
    });
  });

  it('keeps the stack trace on errors', () => {
    const { logger, lines } = captured();
    logger.error({ message: 'send failed', responseCode: 451 }, 'stack-trace', 'Email');
    expect(lines()[0]).toMatchObject({
      level: 'error',
      message: 'send failed',
      responseCode: 451,
      stack: 'stack-trace',
    });
  });
});
