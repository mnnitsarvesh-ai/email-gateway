import { describe, expect, it } from 'vitest';
import { CircuitBreaker, type CircuitState } from './circuit-breaker';

function breaker(overrides: Partial<ConstructorParameters<typeof CircuitBreaker>[0]> = {}) {
  let now = 0;
  const transitions: Array<[CircuitState, CircuitState]> = [];
  const b = new CircuitBreaker({
    failureThreshold: 5,
    failureRatio: 0.5,
    window: 20,
    openMs: 15_000,
    halfOpenProbes: 1,
    now: () => now,
    onTransition: (from, to) => transitions.push([from, to]),
    ...overrides,
  });
  return { b, transitions, advance: (ms: number) => (now += ms) };
}

const call = (b: CircuitBreaker, ok: boolean) => {
  const permit = b.tryAcquire();
  if (!permit) return false;
  if (ok) permit.success();
  else permit.failure();
  return true;
};

describe('CircuitBreaker (S10)', () => {
  it('opens after the consecutive failure threshold and refuses calls while open', () => {
    const { b, transitions } = breaker();
    for (let i = 0; i < 4; i += 1) call(b, false);
    expect(b.state).toBe('closed');
    call(b, false);
    expect(b.state).toBe('open');
    expect(b.tryAcquire()).toBeNull();
    expect(transitions).toEqual([['closed', 'open']]);
  });

  it('a success resets the consecutive count', () => {
    const { b } = breaker();
    for (let i = 0; i < 4; i += 1) call(b, false);
    call(b, true);
    for (let i = 0; i < 4; i += 1) call(b, false);
    expect(b.state).toBe('closed');
  });

  it('opens on the failure ratio over the window, only with at least 10 calls', () => {
    const { b } = breaker({ failureThreshold: 100 });
    // Alternate: never 5 in a row, 50 % failures.
    for (let i = 0; i < 9; i += 1) call(b, i % 2 === 0);
    expect(b.state).toBe('closed');
    call(b, false); // 10 calls, 5 failures
    expect(b.state).toBe('open');
  });

  it('half-open after openMs: one probe at a time; success closes, failure re-opens', () => {
    const { b, advance, transitions } = breaker({ failureThreshold: 1 });
    call(b, false);
    expect(b.state).toBe('open');
    advance(14_999);
    expect(b.state).toBe('open');
    advance(1);
    expect(b.state).toBe('half_open');
    const probe = b.tryAcquire();
    expect(probe).not.toBeNull();
    expect(b.tryAcquire()).toBeNull(); // the probe slot is taken
    probe!.failure();
    expect(b.state).toBe('open');
    advance(15_000);
    expect(b.state).toBe('half_open');
    b.tryAcquire()!.success();
    expect(b.state).toBe('closed');
    expect(transitions.map(([, to]) => to)).toEqual([
      'open',
      'half_open',
      'open',
      'half_open',
      'closed',
    ]);
  });

  it('a released permit counts neither way and frees the probe slot', () => {
    const { b, advance } = breaker({ failureThreshold: 1 });
    call(b, false);
    advance(15_000);
    b.tryAcquire()!.release();
    expect(b.state).toBe('half_open');
    expect(b.tryAcquire()).not.toBeNull();
  });

  it('settles a permit once', () => {
    const { b } = breaker({ failureThreshold: 2 });
    const permit = b.tryAcquire()!;
    permit.failure();
    permit.failure();
    expect(b.state).toBe('closed');
  });

  it('validates its options', () => {
    expect(() => breaker({ failureRatio: 0 })).toThrow();
    expect(() => breaker({ window: 0 })).toThrow();
    expect(() => breaker({ halfOpenProbes: 0 })).toThrow();
  });
});
