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
  ...overrides,
});
const logger = createLogger({ service: 't', level: 'silent' });

describe('WorkerLifecycle', () => {
  it('starts every enabled role and stops consumers first, the lock connection last', async () => {
    const order: string[] = [];
    const lifecycle = new WorkerLifecycle(components(order), roles(), logger);
    lifecycle.start();
    expect(lifecycle.startedRoles).toEqual([
      'approvals',
      'reinjection',
      'reconciler',
      'status_log',
    ]);
    await lifecycle.stop();
    expect(order).toEqual([
      'start:approvals',
      'start:scheduler',
      'start:reconciler',
      'start:tailer',
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

  it('has no development pass-through role any more (step 5.2 P14)', () => {
    const order: string[] = [];
    const lifecycle = new WorkerLifecycle(components(order), roles(), logger);
    lifecycle.start();
    expect(lifecycle.startedRoles).not.toContain('dev_passthrough' as never);
    expect(order.some((step) => step.includes('passthrough'))).toBe(false);
  });
});
