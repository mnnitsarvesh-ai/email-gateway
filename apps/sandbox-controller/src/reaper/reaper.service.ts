import type { Logger } from '@email-gateway/logger';
import type { SandboxBackend } from '../backends/backend';
import type { ControllerMetricsPort, ReapMode } from '../metrics/controller-metrics';
import type { ScratchArea } from '../scratch/scratch';

/**
 * The reaper (step 4.6 X8): removes what a crash left behind.
 *
 * - `startup` (before the consumer starts): every scratch entry and every runner of this
 *   controller (`SANDBOX_CONTROLLER_NAME`) — nothing of this process can be running yet;
 * - `periodic` (every `SANDBOX_REAPER_INTERVAL_MS`): scratch entries older than
 *   `SANDBOX_TASK_TIMEOUT_MS + 60 s` and runners past their expiry label, never those of a task
 *   in the active set (in flight in this process).
 *
 * Scratch reaping is the controller's (`ScratchArea.reap`, path-safe); runners are the backend's
 * (`backend.reap`). Metrics `sandbox_reaped_total{kind,mode}` and
 * `sandbox_cleanup_failures_total{kind}`; logs carry counts only.
 */

export interface ReaperOptions {
  backend: SandboxBackend;
  scratch: ScratchArea;
  activeTaskIds: () => ReadonlySet<string>;
  metrics: ControllerMetricsPort;
  logger: Logger;
  intervalMs: number;
  taskTimeoutMs: number;
}

export interface ReaperPass {
  runnersRemoved: number;
  scratchRemoved: number;
  failures: number;
}

/** Scratch older than this is an orphan for the periodic pass. */
export const ORPHAN_GRACE_MS = 60_000;

export class ReaperService {
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<ReaperPass> | undefined;

  constructor(private readonly o: ReaperOptions) {}

  /** One pass; concurrent calls share the running pass. Never throws. */
  run(mode: ReapMode): Promise<ReaperPass> {
    this.running ??= this.pass(mode).finally(() => {
      this.running = undefined;
    });
    return this.running;
  }

  private async pass(mode: ReapMode): Promise<ReaperPass> {
    const o = this.o;
    const active = o.activeTaskIds();
    const result: ReaperPass = { runnersRemoved: 0, scratchRemoved: 0, failures: 0 };
    try {
      const scratch = await o.scratch.reap(active, mode, o.taskTimeoutMs + ORPHAN_GRACE_MS);
      result.scratchRemoved += scratch.removed;
      result.failures += scratch.failures;
      o.metrics.reap('scratch', mode, scratch.removed);
      o.metrics.cleanupFailure('scratch', scratch.failures);
    } catch {
      result.failures += 1;
      o.metrics.cleanupFailure('scratch');
    }
    try {
      const report = await o.backend.reap(active, mode);
      result.runnersRemoved += report.runnersRemoved;
      result.scratchRemoved += report.scratchRemoved;
      result.failures += report.failures;
      o.metrics.reap('runner', mode, report.runnersRemoved);
      o.metrics.reap('scratch', mode, report.scratchRemoved);
      o.metrics.cleanupFailure('runner', report.failures);
    } catch {
      result.failures += 1;
      o.metrics.cleanupFailure('runner');
    }
    if (result.runnersRemoved + result.scratchRemoved + result.failures > 0) {
      const log =
        result.failures > 0 ? o.logger.error.bind(o.logger) : o.logger.warn.bind(o.logger);
      log({ mode, ...result }, 'sandbox reaper removed leftovers');
    }
    return result;
  }

  /** Starts the periodic pass (after the startup pass). */
  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.run('periodic'), this.o.intervalMs);
    this.timer.unref();
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.running?.catch(() => undefined);
  }
}
