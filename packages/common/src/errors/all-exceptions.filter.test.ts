import { type ArgumentsHost, BadRequestException } from '@nestjs/common';
import { runWithContext } from '@email-gateway/logger';
import { describe, expect, it, vi } from 'vitest';
import { AllExceptionsFilter } from './all-exceptions.filter';

function harness() {
  const json = vi.fn();
  const status = vi.fn(() => ({ json }));
  const host = {
    switchToHttp: () => ({ getResponse: () => ({ status }) }),
  } as unknown as ArgumentsHost;
  const logger = { error: vi.fn() };
  const filter = new AllExceptionsFilter(logger as never);
  return { filter, host, status, json, logger };
}

describe('AllExceptionsFilter', () => {
  it('keeps the status and message of expected HTTP errors', () => {
    const { filter, host, status, json, logger } = harness();
    runWithContext({ correlationId: 'corr-abcdefgh' }, () =>
      filter.catch(new BadRequestException(['domain must be a valid hostname']), host),
    );
    expect(status).toHaveBeenCalledWith(400);
    expect(json).toHaveBeenCalledWith({
      statusCode: 400,
      error: 'BAD_REQUEST',
      message: ['domain must be a valid hostname'],
      correlationId: 'corr-abcdefgh',
    });
    expect(logger.error).not.toHaveBeenCalled();
  });

  it('hides internals of unexpected errors and logs them', () => {
    const { filter, host, status, json, logger } = harness();
    filter.catch(new Error('ECONNREFUSED 10.0.0.5:3306 password=...'), host);
    expect(status).toHaveBeenCalledWith(500);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: 500, message: 'Internal server error' }),
    );
    expect(logger.error).toHaveBeenCalledOnce();
  });
});
