import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLogger } from '@email-gateway/logger';
import { afterAll, describe, expect, it } from 'vitest';
import type { ReapReport, SandboxBackend } from '../backends/backend';
import { DisabledBackend } from '../backends/disabled.backend';
import { NOOP_METRICS, type ControllerMetricsPort } from '../metrics/controller-metrics';
import { ScratchArea } from '../scratch/scratch';
import { ReaperService } from './reaper.service';

const logger = createLogger({ service: 'reaper-test', level: 'silent' });
const base = mkdtempSync(join(tmpdir(), 'eg-sbx-reaper-'));
afterAll(() => rmSync(base, { recursive: true, force: true }));

function recorder(): ControllerMetricsPort & { events: string[] } {
  const events: string[] = [];
  return {
    ...NOOP_METRICS,
    events,
    reap: (kind, mode, count) => events.push(`reap:${kind}:${mode}:${String(count)}`),
    cleanupFailure: (kind, count = 1) => events.push(`fail:${kind}:${String(count)}`),
  };
}

function backendWith(
  report: ReapReport | Error,
  seen: { active?: ReadonlySet<string>; mode?: string }[] = [],
): SandboxBackend {
  const b: SandboxBackend = new DisabledBackend();
  b.reap = (active: ReadonlySet<string>, mode: 'startup' | 'periodic') => {
    seen.push({ active, mode });
    return report instanceof Error ? Promise.reject(report) : Promise.resolve(report);
  };
  return b;
}

describe('ReaperService (X8)', () => {
  it('startup removes all scratch and asks the backend for every runner; periodic spares active tasks', async () => {
    const scratch = new ScratchArea(join(base, randomUUID()));
    await scratch.init();
    const activeId = randomUUID();
    const active = await scratch.create(activeId);
    const orphan = await scratch.create(randomUUID());
    const metrics = recorder();
    const seen: { active?: ReadonlySet<string>; mode?: string }[] = [];
    const reaper = new ReaperService({
      backend: backendWith({ runnersRemoved: 2, scratchRemoved: 0, failures: 0 }, seen),
      scratch,
      activeTaskIds: () => new Set([activeId]),
      metrics,
      logger,
      intervalMs: 60_000,
      taskTimeoutMs: 180_000,
    });
    const past = new Date(Date.now() - 3_600_000);
    utimesSync(active, past, past);
    utimesSync(orphan, past, past);
    expect(await reaper.run('periodic')).toEqual({
      runnersRemoved: 2,
      scratchRemoved: 1,
      failures: 0,
    });
    expect(existsSync(active)).toBe(true);
    expect(existsSync(orphan)).toBe(false);
    expect(seen[0]?.mode).toBe('periodic');
    expect([...(seen[0]?.active ?? [])]).toEqual([activeId]);
    expect(metrics.events).toEqual(
      expect.arrayContaining(['reap:scratch:periodic:1', 'reap:runner:periodic:2']),
    );

    const fresh = await scratch.create(randomUUID());
    const startup = new ReaperService({
      backend: backendWith({ runnersRemoved: 0, scratchRemoved: 0, failures: 0 }),
      scratch,
      activeTaskIds: () => new Set(),
      metrics,
      logger,
      intervalMs: 60_000,
      taskTimeoutMs: 180_000,
    });
    expect((await startup.run('startup')).scratchRemoved).toBe(2);
    expect(existsSync(fresh)).toBe(false);
  });

  it('meters failures and never throws', async () => {
    const scratch = new ScratchArea(join(base, randomUUID()));
    await scratch.init();
    const metrics = recorder();
    const reaper = new ReaperService({
      backend: backendWith(new Error('docker unreachable')),
      scratch,
      activeTaskIds: () => new Set(),
      metrics,
      logger,
      intervalMs: 60_000,
      taskTimeoutMs: 180_000,
    });
    expect(await reaper.run('startup')).toEqual({
      runnersRemoved: 0,
      scratchRemoved: 0,
      failures: 1,
    });
    expect(metrics.events).toContain('fail:runner:1');
    const failing = new ReaperService({
      backend: backendWith({ runnersRemoved: 0, scratchRemoved: 0, failures: 3 }),
      scratch,
      activeTaskIds: () => new Set(),
      metrics,
      logger,
      intervalMs: 60_000,
      taskTimeoutMs: 180_000,
    });
    expect((await failing.run('periodic')).failures).toBe(3);
    expect(metrics.events).toContain('fail:runner:3');
  });

  it('runs periodically after start and stops', async () => {
    const scratch = new ScratchArea(join(base, randomUUID()));
    await scratch.init();
    const seen: { mode?: string }[] = [];
    const reaper = new ReaperService({
      backend: backendWith({ runnersRemoved: 0, scratchRemoved: 0, failures: 0 }, seen),
      scratch,
      activeTaskIds: () => new Set(),
      metrics: NOOP_METRICS,
      logger,
      intervalMs: 20,
      taskTimeoutMs: 180_000,
    });
    reaper.start();
    await new Promise((r) => setTimeout(r, 120));
    await reaper.stop();
    const count = seen.length;
    expect(count).toBeGreaterThan(0);
    expect(seen.every((s) => s.mode === 'periodic')).toBe(true);
    await new Promise((r) => setTimeout(r, 60));
    expect(seen.length).toBe(count);
  });
});
