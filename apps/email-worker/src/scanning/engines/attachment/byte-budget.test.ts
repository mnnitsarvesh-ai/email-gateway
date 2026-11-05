import { describe, expect, it } from 'vitest';
import { ByteBudget } from './byte-budget';

describe('attachment byte budget (step 4.2 A3, A14)', () => {
  it('admits within the limit and queues FIFO above it', async () => {
    const seen: number[] = [];
    const budget = new ByteBudget(100, (used) => seen.push(used));
    const a = await budget.acquire(60);
    let bGranted = false;
    const b = budget.acquire(50).then((release) => {
      bGranted = true;
      return release;
    });
    // FIFO: a small request does not overtake the queued large one.
    let cGranted = false;
    const c = budget.acquire(10).then((release) => {
      cGranted = true;
      return release;
    });
    await Promise.resolve();
    expect(bGranted).toBe(false);
    expect(cGranted).toBe(false);
    expect(budget.waiting).toBe(2);
    a();
    a(); // idempotent
    const releaseB = await b;
    const releaseC = await c;
    expect(budget.inUse).toBe(60);
    releaseB();
    releaseC();
    expect(budget.inUse).toBe(0);
    expect(seen[0]).toBe(0);
  });

  it('caps one request at the limit (one attachment always fits) and honours aborts', async () => {
    const budget = new ByteBudget(100);
    const release = await budget.acquire(1_000);
    expect(budget.inUse).toBe(100);
    const controller = new AbortController();
    const waiting = budget.acquire(1, controller.signal);
    controller.abort(new Error('timeout'));
    await expect(waiting).rejects.toThrow('timeout');
    expect(budget.waiting).toBe(0);
    release();
    await expect(budget.acquire(1, AbortSignal.abort())).rejects.toBeDefined();
    expect(() => new ByteBudget(0)).toThrow(RangeError);
  });
});
