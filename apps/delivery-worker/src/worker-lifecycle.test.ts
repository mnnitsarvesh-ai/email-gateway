import { createLogger } from '@email-gateway/logger';
import { describe, expect, it } from 'vitest';
import { WorkerLifecycle, type WorkerComponents, type WorkerRoles } from './worker-lifecycle';

function components(order: string[]): WorkerComponents {
  const part = (name: string) => ({
    start: () => order.push(`start:${name}`),
    stop: () => {
      order.push(`stop:${name}`);
      return Promise.resolve();
    },
  });
  return {
    approvals: part('approvals'),
    passThrough: part('passthrough'),
    scheduler: part('scheduler'),
    tailer: part('tailer'),
    reconciler: part('reconciler'),
    locks: { close: () => (order.push('close:locks'), Promise.resolve()) },
  } as unknown as WorkerComponents;
}

const roles = (overrides: Partial<WorkerRoles> = {}): WorkerRoles => ({
  DELIVERY_APPROVALS_ENABLED: true,
  DELIVERY_REINJECTION_ENABLED: true,
  DELIVERY_STATUS_LOG_ENABLED: true,
  DELIVERY_DEV_PASSTHROUGH_ENABLED: false,
  ...overrides,
});
const logger = createLogger({ service: 't', level: 'silent' });

describe('WorkerLifecycle', () => {
  it('starts every enabled role and stops consumers first, the lock connection last', async () => {
    const order: string[] = [];
    const lifecycle = new WorkerLifecycle(
      components(order),
      roles({ DELIVERY_DEV_PASSTHROUGH_ENABLED: true }),
      logger,
    );
    lifecycle.start();
    expect(lifecycle.startedRoles).toEqual([
      'approvals',
      'dev_passthrough',
      'reinjection',
      'reconciler',
      'status_log',
    ]);
    await lifecycle.stop();
    expect(order).toEqual([
      'start:approvals',
      'start:passthrough',
      'start:scheduler',
      'start:reconciler',
      'start:tailer',
      'stop:passthrough',
      'stop:approvals',
      'stop:scheduler',
      'stop:tailer',
      'stop:reconciler',
      'close:locks',
    ]);
  });

  it('runs only the status log role in the production sidecar configuration', async () => {
    const order: string[] = [];
    const lifecycle = new WorkerLifecycle(
      components(order),
      roles({ DELIVERY_APPROVALS_ENABLED: false, DELIVERY_REINJECTION_ENABLED: false }),
      logger,
    );
    lifecycle.start();
    expect(lifecycle.startedRoles).toEqual(['status_log']);
    await lifecycle.stop();
    expect(order).toEqual(['start:tailer', 'stop:tailer', 'close:locks']);
  });

  it('never starts the pass-through without the approvals role', () => {
    const order: string[] = [];
    const lifecycle = new WorkerLifecycle(
      components(order),
      roles({ DELIVERY_APPROVALS_ENABLED: false, DELIVERY_DEV_PASSTHROUGH_ENABLED: true }),
      logger,
    );
    lifecycle.start();
    expect(order).not.toContain('start:passthrough');
  });
});
