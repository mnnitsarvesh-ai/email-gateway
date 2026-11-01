import { Writable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { normalizeCorrelationId, runWithContext } from './context';
import { createLogger } from './logger';

function capture(): { stream: Writable; lines: () => Record<string, unknown>[] } {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk: Buffer, _enc, cb) {
      chunks.push(chunk.toString());
      cb();
    },
  });
  return {
    stream,
    lines: () =>
      chunks
        .join('')
        .trim()
        .split('\n')
        .map((l) => JSON.parse(l) as Record<string, unknown>),
  };
}

describe('createLogger', () => {
  it('emits JSON with service and correlation id from async context', () => {
    const out = capture();
    const logger = createLogger({ service: 'test-svc', destination: out.stream });
    runWithContext({ correlationId: 'corr-12345678', tenantId: 't-1' }, () => logger.info('hello'));
    const [line] = out.lines();
    expect(line).toMatchObject({
      level: 'info',
      service: 'test-svc',
      message: 'hello',
      correlationId: 'corr-12345678',
      tenantId: 't-1',
    });
  });

  it('redacts secrets', () => {
    const out = capture();
    const logger = createLogger({ service: 'test-svc', destination: out.stream });
    logger.info({ password: 'hunter2', headers: { authorization: 'Bearer x' } }, 'login');
    const serialized = JSON.stringify(out.lines()[0]);
    expect(serialized).not.toContain('hunter2');
    expect(serialized).not.toContain('Bearer x');
  });
});

describe('normalizeCorrelationId', () => {
  it('keeps a well-formed id', () => {
    expect(normalizeCorrelationId('abc-12345678')).toBe('abc-12345678');
  });

  it('replaces malformed or hostile ids', () => {
    const injected = 'x\n{"level":"fatal"}';
    expect(normalizeCorrelationId(injected)).not.toBe(injected);
    expect(normalizeCorrelationId(undefined)).toMatch(/^[0-9a-f-]{36}$/);
  });
});
