import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { DockerApiError, type DockerApi } from '../../src/runner/docker-client';
import { RunAbortedError } from '../../src/runner/hardened-container.backend';
import { buildRunnerSpec, type RunnerPolicy } from '../../src/runner/hardened-spec';
import {
  context,
  CONTROLLER_NAME,
  DEFAULT_LIMITS,
  docker,
  harness,
  makeBackend,
  NETWORK,
  probe,
  RUNNER_IMAGE,
  BROWSER_IMAGE,
  runnerContainers,
  scratchEntries,
  SINKHOLE_IP,
  task,
} from './support';

/**
 * Cleanup paths of the hardened-container runner (step 4.6 X8, §9.3): success, start failure,
 * spec not enforced, outer timeout, runner crash, abort, removal retries, startup reap of orphans
 * (a killed controller), periodic reap of an expired orphan, an active runner never reaped. Real
 * Docker; faults are injected around the real client. LOCAL/CI ONLY, NOT A VM BOUNDARY.
 */

const h = harness();

/** The real Docker client with some operations replaced. */
function faulty(overrides: Partial<DockerApi>): DockerApi {
  return new Proxy(docker, {
    get(target, prop, receiver) {
      const override: unknown =
        typeof prop === 'string' ? (overrides as Record<string, unknown>)[prop] : undefined;
      if (override !== undefined) return override;
      const value: unknown = Reflect.get(target, prop, receiver);
      return typeof value === 'function'
        ? (value as (...a: unknown[]) => unknown).bind(target)
        : value;
    },
  });
}

const policy: RunnerPolicy = {
  images: { runner: RUNNER_IMAGE, browser: BROWSER_IMAGE },
  network: NETWORK,
  sinkholeDns: SINKHOLE_IP,
  controllerName: CONTROLLER_NAME,
  apparmor: false,
};

/** A running orphan runner (created and started directly, as a crashed controller would leave it). */
async function orphan(
  options: { controller?: string; taskId?: string; expiredAgoMs?: number } = {},
) {
  const taskId = options.taskId ?? `orphan-${Math.random().toString(16).slice(2, 10)}`;
  const spec = buildRunnerSpec(
    {
      taskId,
      profile: 'execute',
      limits: DEFAULT_LIMITS,
      nowMs: Date.now() - (options.expiredAgoMs ?? 0),
      graceMs: 0,
    },
    { ...policy, controllerName: options.controller ?? CONTROLLER_NAME },
  );
  const { Id } = await docker.createContainer(spec, `eg-sbx-${taskId}`);
  await docker.startContainer(Id);
  return { id: Id, taskId };
}

const exists = async (id: string) => (await docker.inspectContainer(id)) !== null;

beforeAll(async () => {
  await h.setup();
}, 180_000);

afterAll(async () => {
  await h.teardown();
}, 180_000);

describe('per-task cleanup', () => {
  it('success: the runner is removed and nothing is left', async () => {
    const run = await h.run(probe('benign-marker.sh'), 'script_shell');
    expect(run.observation).toMatchObject({
      status: 'completed',
      cleanup: { runnerRemoved: true },
    });
  });

  it('start failure: the created runner is removed (runner_start_failed)', async () => {
    const created: string[] = [];
    const backend = makeBackend(h.transport(), {
      docker: faulty({
        createContainer: async (spec, name, signal) => {
          const result = await docker.createContainer(spec, name, signal);
          created.push(result.Id);
          return result;
        },
        startContainer: () => Promise.reject(new DockerApiError('start', 500, 'injected')),
      }),
    });
    const ctx = context();
    const observation = await backend.run(
      task(probe('benign-marker.sh'), 'script_shell', 'execute'),
      ctx,
    );
    expect(observation).toMatchObject({
      status: 'failed',
      errorCode: 'runner_start_failed',
      cleanup: { runnerRemoved: true },
    });
    expect(created).toHaveLength(1);
    expect(await exists(created[0]!)).toBe(false);
    expect(scratchEntries(ctx.scratchDir)).toEqual([]);
    ctx.cleanup();
    expect(await runnerContainers()).toEqual([]);
  });

  it('spec not enforced: a mismatching inspect removes the runner without starting it', async () => {
    const created: string[] = [];
    const starts = vi.fn();
    const backend = makeBackend(h.transport(), {
      docker: faulty({
        createContainer: async (spec, name, signal) => {
          const result = await docker.createContainer(spec, name, signal);
          created.push(result.Id);
          return result;
        },
        inspectContainer: async (id, signal) => {
          const real = await docker.inspectContainer(id, signal);
          if (!real) return real;
          return {
            ...real,
            HostConfig: { ...real.HostConfig, Privileged: true, CapAdd: ['SYS_ADMIN'] },
          };
        },
        startContainer: (id, signal) => {
          starts();
          return docker.startContainer(id, signal);
        },
      }),
    });
    const ctx = context();
    const observation = await backend.run(
      task(probe('benign-marker.sh'), 'script_shell', 'execute'),
      ctx,
    );
    expect(observation).toMatchObject({
      status: 'failed',
      errorCode: 'spec_not_enforced',
      executed: false,
    });
    expect(starts).not.toHaveBeenCalled();
    expect(await exists(created[0]!)).toBe(false);
    ctx.cleanup();
    expect(await runnerContainers()).toEqual([]);
  });

  it('outer timeout: a frozen runner is killed and removed within wall + 5 s', async () => {
    const wall = 6_000;
    const run = await h.run(probe('freeze-runner.sh'), 'script_shell', 'execute', {
      wallTimeoutMs: wall,
    });
    expect(run.observation.status).toBe('completed');
    expect(run.observation.observations.limitsHit).toEqual(
      expect.arrayContaining(['wall_timeout', 'output_truncated']),
    );
    expect(run.elapsedMs).toBeGreaterThanOrEqual(wall + 5_000 - 500);
    expect(run.elapsedMs).toBeLessThan(wall + 5_000 + 6_000);
    expect(run.observation.cleanup.runnerRemoved).toBe(true);
  });

  it('runner crash: the bootstrap is killed by the sample → runner_crashed, runner removed', async () => {
    const run = await h.run(probe('crash-runner.sh'), 'script_shell');
    expect(run.observation).toMatchObject({
      status: 'failed',
      errorCode: 'runner_crashed',
      cleanup: { runnerRemoved: true },
    });
  });

  it('abort (task timeout / shutdown): the run rejects only after the runner is removed', async () => {
    const backend = makeBackend(h.transport());
    const abort = new AbortController();
    const ctx = context(abort.signal);
    setTimeout(() => abort.abort(), 2_000);
    await expect(
      backend.run(
        task(probe('long-sleep.sh'), 'script_shell', 'execute', { wallTimeoutMs: 60_000 }),
        ctx,
      ),
    ).rejects.toBeInstanceOf(RunAbortedError);
    expect(await runnerContainers()).toEqual([]);
    ctx.cleanup();
  });

  it('removal is retried; a permanent failure is metered and logged, not thrown', async () => {
    let failuresLeft = 2;
    const backend = makeBackend(h.transport(), {
      docker: faulty({
        removeContainer: (id, signal) => {
          if (failuresLeft > 0) {
            failuresLeft -= 1;
            return Promise.reject(new DockerApiError('remove', 500, 'injected'));
          }
          return docker.removeContainer(id, signal);
        },
      }),
    });
    const ctx = context();
    const ok = await backend.run(task(probe('benign-marker.sh'), 'script_shell', 'execute'), ctx);
    expect(ok.cleanup.runnerRemoved).toBe(true);
    expect(await runnerContainers()).toEqual([]);

    const cleanupFailure = vi.fn();
    const created: string[] = [];
    const stuck = makeBackend(h.transport(), {
      metrics: { cleanupFailure },
      docker: faulty({
        createContainer: async (spec, name, signal) => {
          const result = await docker.createContainer(spec, name, signal);
          created.push(result.Id);
          return result;
        },
        removeContainer: () => Promise.reject(new DockerApiError('remove', 500, 'injected')),
      }),
    });
    const failed = await stuck.run(task(probe('benign-marker.sh'), 'script_shell', 'execute'), ctx);
    expect(failed.cleanup.runnerRemoved).toBe(false);
    expect(cleanupFailure).toHaveBeenCalledWith('runner');
    expect(await exists(created[0]!)).toBe(true);
    // The leftover is what the reaper is for.
    const report = await makeBackend(h.transport()).reap(new Set(), 'startup');
    expect(report.runnersRemoved).toBe(1);
    expect(await runnerContainers()).toEqual([]);
    ctx.cleanup();
  });
});

describe('reaper (X8)', () => {
  it('startup: removes every runner of this controller (a killed controller), none of another', async () => {
    const a = await orphan();
    const b = await orphan();
    const other = await orphan({ controller: 'another-controller' });
    const reaped = vi.fn();
    try {
      const backend = makeBackend(h.transport(), { metrics: { reaped } });
      const report = await backend.reap(new Set(), 'startup');
      expect(report).toEqual({ runnersRemoved: 2, scratchRemoved: 0, failures: 0 });
      expect(reaped).toHaveBeenCalledWith('runner', 'startup', 2);
      expect(await exists(a.id)).toBe(false);
      expect(await exists(b.id)).toBe(false);
      expect(await exists(other.id)).toBe(true);
    } finally {
      await docker.removeContainer(other.id);
    }
    expect(await runnerContainers()).toEqual([]);
  });

  it('periodic: removes an expired orphan only; a live one and an active task are never reaped', async () => {
    const expired = await orphan({ expiredAgoMs: 10 * 60_000 });
    const live = await orphan();
    const active = await orphan({ expiredAgoMs: 10 * 60_000 });
    const backend = makeBackend(h.transport());
    const report = await backend.reap(new Set([active.taskId]), 'periodic');
    expect(report).toEqual({ runnersRemoved: 1, scratchRemoved: 0, failures: 0 });
    expect(await exists(expired.id)).toBe(false);
    expect(await exists(live.id)).toBe(true);
    expect(await exists(active.id)).toBe(true);
    // Still active at the next pass → still kept, even in startup mode.
    expect((await backend.reap(new Set([active.taskId]), 'startup')).runnersRemoved).toBe(1);
    expect(await exists(active.id)).toBe(true);
    expect((await backend.reap(new Set(), 'startup')).runnersRemoved).toBe(1);
    expect(await runnerContainers()).toEqual([]);
  });
});
