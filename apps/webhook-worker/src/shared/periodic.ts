import { backoffDelay, sleep as defaultSleep } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';

/**
 * Runs `task` every `intervalMs` until stopped; a failing pass is logged (class name and code
 * only) and retried with backoff. `stop()` waits for the pass in progress.
 */
export class Periodic {
  private abort = new AbortController();
  private loop: Promise<void> | undefined;
  private failures = 0;

  constructor(
    private readonly name: string,
    private readonly intervalMs: number,
    private readonly task: () => Promise<unknown>,
    private readonly logger: Logger,
    private readonly sleep: (ms: number, signal: AbortSignal) => Promise<boolean> = defaultSleep,
  ) {}

  get running(): boolean {
    return this.loop !== undefined;
  }

  start(): void {
    if (this.loop) return;
    this.abort = new AbortController();
    this.loop = this.run(this.abort.signal);
  }

  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop;
    this.loop = undefined;
  }

  private async run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      let delay = this.intervalMs;
      try {
        await this.task();
        this.failures = 0;
      } catch (error) {
        this.failures += 1;
        delay = Math.max(delay, backoffDelay(this.failures, { baseMs: 1_000, maxMs: 60_000 }));
        this.logger.warn(
          {
            task: this.name,
            errName: (error as Error).name,
            errCode: (error as { code?: string }).code,
          },
          'periodic task failed; retried',
        );
      }
      if (!(await this.sleep(delay, signal))) break;
    }
  }
}
