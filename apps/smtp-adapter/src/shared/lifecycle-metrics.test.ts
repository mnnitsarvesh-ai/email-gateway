import { MetricsService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { lifecycleMetrics } from './lifecycle-metrics';

describe('lifecycleMetrics (step 3.3 L5.5)', () => {
  it('adapts the transition service metrics onto the shared lifecycle series', async () => {
    const service = new MetricsService({ service: 'test' });
    const metrics = lifecycleMetrics(service);
    metrics.transition('delivery_pending', 'rejected', 'applied');
    metrics.ignored('final_state');
    metrics.versionConflict();
    metrics.derivedSkipped('expired');
    // Registering twice (several components) reuses the same series.
    lifecycleMetrics(service).derivedSkipped('expired');
    const text = await service.metrics();
    expect(text).toContain(
      'lifecycle_transitions_total{from="delivery_pending",to="rejected",result="applied",service="test"} 1',
    );
    expect(text).toContain(
      'lifecycle_transitions_ignored_total{reason="final_state",service="test"} 1',
    );
    expect(text).toContain('lifecycle_version_conflicts_total{service="test"} 1');
    expect(text).toContain('lifecycle_derived_skipped_total{state="expired",service="test"} 2');
  });
});
