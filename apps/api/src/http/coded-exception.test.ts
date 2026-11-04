import type { ArgumentsHost } from '@nestjs/common';
import { HttpStatus } from '@nestjs/common';
import { runWithContext } from '@email-gateway/logger';
import { describe, expect, it, vi } from 'vitest';
import { CodedExceptionFilter, CodedHttpException, codedErrorSchema } from './coded-exception';

function hostFor(res: { status: (n: number) => unknown; json: (b: unknown) => unknown }) {
  return { switchToHttp: () => ({ getResponse: () => res }) } as unknown as ArgumentsHost;
}

describe('CodedHttpException and CodedExceptionFilter', () => {
  it('renders the standard body plus code and details', () => {
    const json = vi.fn();
    const res = { status: vi.fn(() => res), json };
    const error = new CodedHttpException(HttpStatus.CONFLICT, 'message_state_conflict', 'No', {
      currentState: 'delivered',
      currentVersion: 4,
    });
    runWithContext({ correlationId: 'corr-12345678' }, () =>
      new CodedExceptionFilter().catch(error, hostFor(res)),
    );
    expect(res.status).toHaveBeenCalledWith(409);
    expect(json).toHaveBeenCalledWith({
      statusCode: 409,
      error: 'CONFLICT',
      code: 'message_state_conflict',
      message: 'No',
      currentState: 'delivered',
      currentVersion: 4,
      correlationId: 'corr-12345678',
    });
  });

  it('details never override the standard fields', () => {
    const json = vi.fn();
    const res = { status: vi.fn(() => res), json };
    new CodedExceptionFilter().catch(
      new CodedHttpException(HttpStatus.NOT_FOUND, 'message_not_found', 'Message not found', {
        code: 'forged',
        statusCode: 200,
      }),
      hostFor(res),
    );
    expect(json.mock.calls[0]![0]).toMatchObject({ statusCode: 404, code: 'message_not_found' });
  });

  it('documents the codes and detail properties', () => {
    const schema = codedErrorSchema(409, ['a', 'b'], { currentVersion: { type: 'integer' } });
    expect(schema.required).toEqual(['statusCode', 'error', 'code', 'message']);
    expect(schema.properties).toMatchObject({
      statusCode: { enum: [409] },
      code: { enum: ['a', 'b'] },
      currentVersion: { type: 'integer' },
    });
  });
});
