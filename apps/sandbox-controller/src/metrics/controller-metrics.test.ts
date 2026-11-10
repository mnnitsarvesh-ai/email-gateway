import { MetricsService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { ControllerMetrics } from './controller-metrics';

/** The exact controller series of X20 (no tenant, hash, host or task labels). */
const X20_SERIES: Record<string, string[]> = {
  sandbox_tasks_total: ['backend', 'status'],
  sandbox_task_duration_seconds: ['backend', 'profile'],
  sandbox_backend_ready: ['backend'],
  sandbox_backend_info: ['backend', 'isolation', 'executes'],
  sandbox_runners_active: [],
  sandbox_reaped_total: ['kind', 'mode'],
  sandbox_cleanup_failures_total: ['kind'],
  sandbox_limit_hits_total: ['limit'],
  sandbox_findings_total: ['severity'],
  sandbox_artifacts_total: ['kind'],
  sandbox_artifact_bytes_total: [],
  sandbox_s3_errors_total: ['op'],
  sandbox_publish_failures_total: [],
};

describe('ControllerMetrics (X20)', () => {
  it('registers exactly the controller series with bounded labels', async () => {
    const service = new MetricsService({ service: 'sandbox-controller' });
    const m = new ControllerMetrics(service);
    m.backend('static', 'process', false);
    m.setReady('static', true);
    m.task('static', 'completed');
    m.taskDuration('static', 'static', 1.2);
    m.setRunnersActive(1);
    m.reap('scratch', 'startup', 2);
    m.reap('runner', 'periodic', 0);
    m.cleanupFailure('runner');
    m.limitHit('analyzer_resources');
    m.finding('high');
    m.artifact('static_report', 100);
    m.s3Error('get_sample');
    m.publishFailure();
    const metrics = await service.registry.getMetricsAsJSON();
    const own = metrics.filter((x) => x.name.startsWith('sandbox_'));
    expect(own.map((x) => x.name).sort()).toEqual(Object.keys(X20_SERIES).sort());
    for (const metric of own) {
      for (const value of metric.values) {
        const labels = Object.keys(value.labels).filter((l) => l !== 'service' && l !== 'le');
        for (const label of labels) expect(X20_SERIES[metric.name]).toContain(label);
      }
    }
    const text = await service.metrics();
    expect(text).toContain(
      'sandbox_backend_info{backend="static",isolation="process",executes="false",service="sandbox-controller"} 1',
    );
    expect(text).toContain(
      'sandbox_reaped_total{kind="scratch",mode="startup",service="sandbox-controller"} 2',
    );
    expect(text).not.toMatch(/sandbox_reaped_total\{kind="runner"/);
    expect(text).not.toMatch(/task_id|taskId|organization|sha256|host=/);
  });
});
