import { describe, expect, it } from 'vitest';
import { AmqpQueueDepth } from './queue-depth';

function fakeConnection(options: { connected?: boolean; fail?: boolean } = {}) {
  const closed: string[] = [];
  const declared: string[] = [];
  const connection = {
    connected: options.connected ?? true,
    createChannel: () =>
      Promise.resolve({
        on: () => undefined,
        checkQueue: (queue: string) => {
          declared.push(queue);
          return options.fail
            ? Promise.reject(Object.assign(new Error('NOT_FOUND'), { code: 404 }))
            : Promise.resolve({ queue, messageCount: 17, consumerCount: 1 });
        },
        close: () => {
          closed.push('channel');
          return Promise.resolve();
        },
      }),
  };
  return { connection: connection as never, closed, declared };
}

describe('AmqpQueueDepth', () => {
  it('returns the ready count of a passive declare and closes its channel', async () => {
    const f = fakeConnection();
    expect(await new AmqpQueueDepth(f.connection).readyMessages('email.received')).toBe(17);
    expect(f.declared).toEqual(['email.received']);
    expect(f.closed).toEqual(['channel']);
  });

  it('rejects while disconnected and when the declare fails (the reconciler defers)', async () => {
    await expect(
      new AmqpQueueDepth(fakeConnection({ connected: false }).connection).readyMessages(
        'email.received',
      ),
    ).rejects.toThrow(/not connected/);
    const f = fakeConnection({ fail: true });
    await expect(
      new AmqpQueueDepth(f.connection).readyMessages('email.received'),
    ).rejects.toThrow();
    expect(f.closed).toEqual(['channel']);
  });
});
