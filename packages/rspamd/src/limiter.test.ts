import { describe, expect, it } from 'vitest';
import { InFlightLimiter } from './limiter';

describe('InFlightLimiter', () => {
  it('grants up to the limit and queues the rest in FIFO order', async () => {
    const limiter = new InFlightLimiter(2);
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
    a(); // releasing twice is a no-op
    (await c)();
    b();
    (await d)();
    expect(order).toEqual(['c', 'd']);
    expect(limiter.inFlight).toBe(0);
  });

  it('removes an aborted waiter from the queue', async () => {
    const limiter = new InFlightLimiter(1);
    const held = await limiter.acquire();
    const controller = new AbortController();
    const waiting = limiter.acquire(controller.signal);
    controller.abort(new Error('gone'));
    await expect(waiting).rejects.toThrow('gone');
    expect(limiter.waiting).toBe(0);
    held();
    expect(limiter.inFlight).toBe(0);
    await expect(limiter.acquire(AbortSignal.abort(new Error('already')))).rejects.toThrow(
      'already',
    );
  });

  it('runs tasks inside a slot and releases on failure', async () => {
    const limiter = new InFlightLimiter(1);
    await expect(limiter.run(() => Promise.reject(new Error('x')))).rejects.toThrow('x');
    await expect(limiter.run(() => Promise.resolve(7))).resolves.toBe(7);
    expect(limiter.inFlight).toBe(0);
  });

  it('refuses a non-positive limit', () => {
    expect(() => new InFlightLimiter(0)).toThrow(RangeError);
  });
});
