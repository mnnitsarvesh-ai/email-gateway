import { MetricsService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { DeliveryMetrics } from './delivery-metrics';

describe('DeliveryMetrics.outboxPoller', () => {
  it('maps the shared poller metrics onto the unchanged step 2.3 series', async () => {
    const service = new MetricsService({ service: 'test' });
    const metrics = new DeliveryMetrics(service).outboxPoller();
    metrics.pollLag('delivery-worker.planner', 12.5);
    metrics.invalid('delivery-worker.planner');
    metrics.invalid('delivery-worker.planner');
    const text = await service.metrics();
    expect(text).toContain(
      'delivery_outbox_poll_lag_seconds{consumer="delivery-worker.planner",service="test"} 12.5',
    );
    expect(text).toContain(
      'delivery_outbox_invalid_events_total{consumer="delivery-worker.planner",service="test"} 2',
    );
  });
});

describe('DeliveryMetrics lifecycle series (step 3.3)', () => {
  it('counts approval outcomes and adapts the transition service metrics', async () => {
    const service = new MetricsService({ service: 'test' });
    const metrics = new DeliveryMetrics(service);
    metrics.approvalsSkipped.inc({ reason: 'lifecycle_stale' });
    metrics.approvalsRejected.inc({ reason: 'lifecycle_state' });
    metrics.lifecycle.transition('approved', 'delivery_pending', 'applied');
    metrics.lifecycle.ignored('older_round');
    metrics.lifecycle.versionConflict();
    metrics.lifecycle.derivedSkipped('expired');
    const text = await service.metrics();
    for (const line of [
      'delivery_approvals_skipped_total{reason="lifecycle_stale",service="test"} 1',
      'delivery_approvals_rejected_total{reason="lifecycle_state",service="test"} 1',
      'lifecycle_transitions_total{from="approved",to="delivery_pending",result="applied",service="test"} 1',
      'lifecycle_transitions_ignored_total{reason="older_round",service="test"} 1',
      'lifecycle_version_conflicts_total{service="test"} 1',
      'lifecycle_derived_skipped_total{state="expired",service="test"} 1',
    ]) {
      expect(text).toContain(line);
    }
  });
});

describe('DeliveryMetrics risk holds (step 5.1 R17, R19)', () => {
  it('counts the pass-through risk holds by action and the new skip reasons', async () => {
    const service = new MetricsService({ service: 'test' });
    const metrics = new DeliveryMetrics(service);
    metrics.riskHolds.inc({ action: 'quarantine' });
    metrics.riskHolds.inc({ action: 'missing' });
    metrics.approvalsSkipped.inc({ reason: 'risk_recommendation' });
    metrics.approvalsSkipped.inc({ reason: 'risk_missing' });
    metrics.inconsistentReads.inc({ read: 'risk_score' });
    const text = await service.metrics();
    for (const line of [
      'delivery_risk_holds_total{action="quarantine",service="test"} 1',
      'delivery_risk_holds_total{action="missing",service="test"} 1',
      'delivery_approvals_skipped_total{reason="risk_recommendation",service="test"} 1',
      'delivery_approvals_skipped_total{reason="risk_missing",service="test"} 1',
      'delivery_inconsistent_reads_total{read="risk_score",service="test"} 1',
    ]) {
      expect(text).toContain(line);
    }
  });
});
