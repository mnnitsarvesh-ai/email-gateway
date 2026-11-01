import { describe, expect, it } from 'vitest';
import type { HealthIndicator } from './health-indicator';
import { HealthService } from './health.service';

const ok: HealthIndicator = { healthName: 'ok-dep', checkHealth: () => Promise.resolve() };
const failing: HealthIndicator = {
  healthName: 'bad-dep',
  checkHealth: () => Promise.reject(new Error('connection refused')),
};
const service = { name: 'svc', version: '1.0.0' };

describe('HealthService', () => {
  it('reports liveness without touching dependencies', () => {
    const health = new HealthService([failing], service);
    expect(health.liveness()).toMatchObject({ service: 'svc', status: 'ok', checks: [] });
  });

  it('is ready only when every dependency is ok', async () => {
    expect((await new HealthService([ok], service).readiness()).status).toBe('ok');

    const report = await new HealthService([ok, failing], service).readiness();
    expect(report.status).toBe('error');
    expect(report.checks).toEqual([
      expect.objectContaining({ name: 'ok-dep', status: 'ok' }),
      expect.objectContaining({ name: 'bad-dep', status: 'error', error: 'connection refused' }),
    ]);
  });

  it('times out a hanging dependency instead of hanging the probe', async () => {
    const hanging: HealthIndicator = {
      healthName: 'slow',
      checkHealth: () => new Promise(() => {}),
    };
    const report = await new HealthService([hanging], service).readiness();
    expect(report.checks[0]).toMatchObject({
      status: 'error',
      error: expect.stringContaining('timed out'),
    });
  }, 5_000);
});
