import { describe, expect, it } from 'vitest';
import { ConnectionLimiter } from './limiter';

describe('ConnectionLimiter', () => {
  it('grants up to the limit and serves waiters in FIFO order', async () => {
    const limiter = new ConnectionLimiter(2);
    const a = await limiter.acquire();
    const b = await limiter.acquire();
    const order: string[] = [];
    const c = limiter.acquire().then((release) => {
      order.push('c');
      return release;
    });
    const d = limiter.acquire().then((release) => {
      order.push('d');
      return release;
    });
    expect(limiter.inFlight).toBe(2);
    expect(limiter.waiting).toBe(2);
    a();
    a(); // idempotent
    (await c)();
    b();
    (await d)();
    expect(order).toEqual(['c', 'd']);
    expect(limiter.inFlight).toBe(0);
  });

  it('removes an aborted waiter', async () => {
    const limiter = new ConnectionLimiter(1);
    const release = await limiter.acquire();
    const controller = new AbortController();
    const waiting = limiter.acquire(controller.signal);
    controller.abort(new Error('stop'));
    await expect(waiting).rejects.toThrow('stop');
    expect(limiter.waiting).toBe(0);
    release();
    expect(limiter.inFlight).toBe(0);
  });

  it('refuses a non-positive limit', () => {
    expect(() => new ConnectionLimiter(0)).toThrow(RangeError);
  });
});
