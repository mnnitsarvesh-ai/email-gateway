import { describe, expect, it } from 'vitest';
import { RelayLifecycle } from './relay-lifecycle';
import { silentLogger } from './testing/fakes';

function component(name: string, calls: string[], fail = false) {
  return {
    start: () => calls.push(`start:${name}`),
    stop: () => {
      calls.push(`stop:${name}`);
      return fail ? Promise.reject(new Error('boom')) : Promise.resolve();
    },
    close: () => {
      calls.push(`close:${name}`);
      return Promise.resolve();
    },
  };
}

describe('RelayLifecycle', () => {
  it('starts the enabled roles and stops in order: relay, reconciler, locks, AMQP', async () => {
    const calls: string[] = [];
    const lifecycle = new RelayLifecycle(
      {
        relay: component('relay', calls),
        reconciler: component('reconciler', calls, true),
        locks: component('locks', calls),
        publisher: component('publisher', calls),
        connection: component('connection', calls),
      },
      silentLogger,
    );
    lifecycle.start();
    expect(lifecycle.startedRoles).toEqual(['relay', 'reconciler']);
    await lifecycle.stop();
    await lifecycle.stop(); // idempotent
    expect(calls).toEqual([
      'start:relay',
      'start:reconciler',
      'stop:relay',
      'stop:reconciler', // fails: the next steps still run
      'close:locks',
      'close:publisher',
      'close:connection',
    ]);
  });

  it('runs without roles and still closes the connections', async () => {
    const calls: string[] = [];
    const lifecycle = new RelayLifecycle(
      {
        locks: component('locks', calls),
        publisher: component('publisher', calls),
        connection: component('connection', calls),
      },
      silentLogger,
    );
    lifecycle.start();
    expect(lifecycle.startedRoles).toEqual([]);
    await lifecycle.stop();
    expect(calls).toEqual(['close:locks', 'close:publisher', 'close:connection']);
  });
});
