import type { HealthIndicator } from '@email-gateway/common';
import type { HealthDetails } from '@email-gateway/shared-types';
import type { Logger } from '@email-gateway/logger';
import type { BackendSelfTest, SandboxBackend } from '../backends/backend';
import type { ControllerMetricsPort } from '../metrics/controller-metrics';
import type { SampleStore } from '../storage/sandbox-s3';

/**
 * Readiness of the isolation backend (step 4.6 X1, ADR-0039 decision 7): the last self-test
 * (startup, then every `SANDBOX_SELF_TEST_INTERVAL_MS`) with the backend, its isolation class,
 * whether it executes and — for a shared-kernel container — that it is NOT a VM boundary.
 * Listeners (the task consumer) are told when readiness flips, so the consumer is cancelled
 * while the backend is not ready and resumed when it passes again (no nack loop).
 */

const MAX_DETAILS = 16;
const SELF_TEST_TIMEOUT_MS = 60_000;

export function boundaryOf(isolation: SandboxBackend['isolation']): string {
  switch (isolation) {
    case 'none':
      return 'no-execution';
    case 'process':
      return 'analyzer-process-no-execution';
    case 'container':
      return 'container-not-a-vm-boundary';
    case 'vm':
      return 'vm';
  }
}

export class BackendHealth implements HealthIndicator {
  readonly healthName = 'sandbox-backend';
  private last: BackendSelfTest;
  private lastAt: Date;
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<BackendSelfTest> | undefined;
  private readonly listeners = new Set<(ok: boolean) => void>();

  constructor(
    private readonly backend: SandboxBackend,
    initial: BackendSelfTest,
    private readonly metrics: ControllerMetricsPort,
    private readonly logger: Logger,
    private readonly intervalMs: number,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.last = initial;
    this.lastAt = now();
    metrics.backend(backend.name, backend.isolation, backend.executes);
    metrics.setReady(backend.name, initial.ok);
  }

  get ok(): boolean {
    return this.last.ok;
  }

  get lastSelfTest(): BackendSelfTest {
    return this.last;
  }

  onChange(listener: (ok: boolean) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  details(): HealthDetails {
    const own: HealthDetails = {
      backend: this.backend.name,
      backendVersion: this.backend.version,
      isolation: this.backend.isolation,
      executes: this.backend.executes,
      boundary: boundaryOf(this.backend.isolation),
      selfTest: this.last.code,
      lastSelfTestAt: this.lastAt.toISOString(),
    };
    const extra = Object.entries(this.last.details)
      .filter(([key]) => !(key in own) && /^[A-Za-z][A-Za-z0-9_]{0,47}$/.test(key))
      .slice(0, MAX_DETAILS);
    return { ...own, ...Object.fromEntries(extra) };
  }

  checkHealth(): Promise<HealthDetails> {
    if (this.last.ok) return Promise.resolve(this.details());
    const d = this.details();
    return Promise.reject(
      new Error(
        `sandbox backend not ready: ${this.last.code} (backend ${String(d.backend)}, isolation ${String(d.isolation)}, executes ${String(d.executes)})`,
      ),
    );
  }

  /** Runs the self-test now (shared when one is running); never throws. */
  runSelfTest(): Promise<BackendSelfTest> {
    this.running ??= (async () => {
      let result: BackendSelfTest;
      try {
        result = await this.backend.selfTest(
          AbortSignal.timeout(Math.min(this.intervalMs, SELF_TEST_TIMEOUT_MS)),
        );
      } catch {
        result = { ok: false, code: 'self_test_failed', details: {} };
      }
      const changed = result.ok !== this.last.ok;
      this.last = result;
      this.lastAt = this.now();
      this.metrics.setReady(this.backend.name, result.ok);
      if (changed) {
        (result.ok ? this.logger.info.bind(this.logger) : this.logger.error.bind(this.logger))(
          { backend: this.backend.name, selfTest: result.code },
          result.ok ? 'sandbox backend self-test passes again' : 'sandbox backend self-test failed',
        );
        for (const listener of this.listeners) listener(result.ok);
      }
      return result;
    })().finally(() => {
      this.running = undefined;
    });
    return this.running;
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.runSelfTest(), this.intervalMs);
    this.timer.unref();
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.running?.catch(() => undefined);
  }
}

/** Readiness of the sandbox bucket (only when the backend reads samples / writes artifacts). */
export class SandboxStorageHealth implements HealthIndicator {
  readonly healthName = 'sandbox-s3';

  constructor(
    private readonly store: SampleStore,
    private readonly bucket: string,
  ) {}

  async checkHealth(): Promise<HealthDetails> {
    await this.store.probe(AbortSignal.timeout(1_800));
    return { bucket: this.bucket, access: 'samples-read,artifacts-write' };
  }
}
