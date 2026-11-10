import { createLogger } from '@email-gateway/logger';
import { describe, expect, it } from 'vitest';
import type { BackendSelfTest } from '../backends/backend';
import { DisabledBackend } from '../backends/disabled.backend';
import { NOOP_METRICS, type ControllerMetricsPort } from '../metrics/controller-metrics';
import { BackendHealth, boundaryOf, SandboxStorageHealth } from './backend-health';

const logger = createLogger({ service: 'health-test', level: 'silent' });

function recorder(): ControllerMetricsPort & { ready: boolean[]; info: string[] } {
  const ready: boolean[] = [];
  const info: string[] = [];
  return {
    ...NOOP_METRICS,
    ready,
    info,
    setReady: (_b, ok) => ready.push(ok),
    backend: (b, i, e) => info.push(`${b}/${i}/${String(e)}`),
  };
}

describe('BackendHealth', () => {
  it('reports backend, isolation, executes and boundary in readiness details', async () => {
    const metrics = recorder();
    const health = new BackendHealth(
      new DisabledBackend(),
      { ok: true, code: 'ok', details: { execution: false } },
      metrics,
      logger,
      60_000,
    );
    expect(await health.checkHealth()).toMatchObject({
      backend: 'disabled',
      isolation: 'none',
      executes: false,
      boundary: 'no-execution',
      selfTest: 'ok',
      execution: false,
    });
    expect(metrics.info).toEqual(['disabled/none/false']);
    expect(metrics.ready).toEqual([true]);
    expect(boundaryOf('container')).toBe('container-not-a-vm-boundary');
  });

  it('fails readiness when the self-test fails and tells listeners on every flip', async () => {
    const backend = new DisabledBackend();
    let next: BackendSelfTest = { ok: false, code: 'self_test_failed', details: {} };
    backend.selfTest = () => Promise.resolve(next);
    const metrics = recorder();
    const health = new BackendHealth(
      backend,
      { ok: true, code: 'ok', details: {} },
      metrics,
      logger,
      60_000,
    );
    const flips: boolean[] = [];
    health.onChange((ok) => flips.push(ok));
    await health.runSelfTest();
    await expect(health.checkHealth()).rejects.toThrow(
      /sandbox backend not ready: self_test_failed \(backend disabled, isolation none, executes false\)/,
    );
    await health.runSelfTest();
    next = { ok: true, code: 'ok', details: {} };
    await health.runSelfTest();
    expect(flips).toEqual([false, true]);
    expect(metrics.ready).toEqual([true, false, false, true]);
    backend.selfTest = () => Promise.reject(new Error('boom'));
    expect((await health.runSelfTest()).code).toBe('self_test_failed');
  });

  it('runs the self-test on its timer and stops', async () => {
    const backend = new DisabledBackend();
    let calls = 0;
    backend.selfTest = () => {
      calls += 1;
      return Promise.resolve({ ok: true, code: 'ok', details: {} });
    };
    const health = new BackendHealth(
      backend,
      { ok: true, code: 'ok', details: {} },
      NOOP_METRICS,
      logger,
      20,
    );
    health.start();
    await new Promise((r) => setTimeout(r, 100));
    await health.stop();
    const seen = calls;
    expect(seen).toBeGreaterThan(0);
    await new Promise((r) => setTimeout(r, 50));
    expect(calls).toBe(seen);
  });

  it('bucket readiness probes the store', async () => {
    const ok = new SandboxStorageHealth(
      {
        probe: () => Promise.resolve(),
        getSample: () => Promise.reject(new Error()),
        putArtifact: () => Promise.resolve(),
        close: () => undefined,
      },
      'b',
    );
    expect(await ok.checkHealth()).toEqual({ bucket: 'b', access: 'samples-read,artifacts-write' });
    const down = new SandboxStorageHealth(
      {
        probe: () => Promise.reject(new Error('unreachable')),
        getSample: () => Promise.reject(new Error()),
        putArtifact: () => Promise.resolve(),
        close: () => undefined,
      },
      'b',
    );
    await expect(down.checkHealth()).rejects.toThrow('unreachable');
  });
});
