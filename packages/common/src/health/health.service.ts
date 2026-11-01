import { Inject, Injectable } from '@nestjs/common';
import type { DependencyHealth, HealthReport } from '@email-gateway/shared-types';
import {
  HEALTH_INDICATORS,
  type HealthIndicator,
  SERVICE_INFO,
  type ServiceInfo,
} from './health-indicator';

const CHECK_TIMEOUT_MS = 2_000;

@Injectable()
export class HealthService {
  private readonly startedAt = Date.now();

  constructor(
    @Inject(HEALTH_INDICATORS) private readonly indicators: HealthIndicator[],
    @Inject(SERVICE_INFO) private readonly service: ServiceInfo,
  ) {}

  /** Liveness: the process is running and the event loop responds. No dependency checks. */
  liveness(): HealthReport {
    return this.report([]);
  }

  /** Readiness: every dependency answered within the timeout. */
  async readiness(): Promise<HealthReport> {
    const checks = await Promise.all(this.indicators.map((i) => this.run(i)));
    return this.report(checks);
  }

  private report(checks: DependencyHealth[]): HealthReport {
    return {
      service: this.service.name,
      version: this.service.version,
      status: checks.every((c) => c.status === 'ok') ? 'ok' : 'error',
      uptimeSeconds: Math.round((Date.now() - this.startedAt) / 1000),
      checks,
    };
  }

  private async run(indicator: HealthIndicator): Promise<DependencyHealth> {
    const started = performance.now();
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        indicator.checkHealth(),
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(new Error(`timed out after ${CHECK_TIMEOUT_MS}ms`)),
            CHECK_TIMEOUT_MS,
          );
        }),
      ]);
      return { name: indicator.healthName, status: 'ok', latencyMs: this.elapsed(started) };
    } catch (err) {
      return {
        name: indicator.healthName,
        status: 'error',
        latencyMs: this.elapsed(started),
        error: err instanceof Error ? err.message : String(err),
      };
    } finally {
      clearTimeout(timer);
    }
  }

  private elapsed(started: number): number {
    return Math.round(performance.now() - started);
  }
}
