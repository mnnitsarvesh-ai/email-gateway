import { MetricsService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { DeliveryMetrics } from './delivery-metrics';

describe('DeliveryMetrics lifecycle series (step 3.3)', () => {
  it('counts approval outcomes and adapts the transition service metrics', async () => {
    const service = new MetricsService({ service: 'test' });
    const metrics = new DeliveryMetrics(service);
    metrics.approvalsRejected.inc({ reason: 'lifecycle_state' });
    metrics.lifecycle.transition('approved', 'delivery_pending', 'applied');
    metrics.lifecycle.ignored('older_round');
    metrics.lifecycle.versionConflict();
    metrics.lifecycle.derivedSkipped('expired');
    const text = await service.metrics();
    for (const line of [
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

describe('DeliveryMetrics approvals (step 4.3 U20, step 5.2 P14, P24)', () => {
  it('counts approvals by source and delivered object, including policy copies', async () => {
    const service = new MetricsService({ service: 'test' });
    const metrics = new DeliveryMetrics(service);
    metrics.approvals.inc({ source: 'policy', object: 'policy_copy' });
    metrics.approvals.inc({ source: 'policy', object: 'rewritten' });
    metrics.approvals.inc({ source: 'quarantine_release', object: 'original' });
    const text = await service.metrics();
    for (const line of [
      'delivery_approvals_total{source="policy",object="policy_copy",service="test"} 1',
      'delivery_approvals_total{source="policy",object="rewritten",service="test"} 1',
      'delivery_approvals_total{source="quarantine_release",object="original",service="test"} 1',
    ]) {
      expect(text).toContain(line);
    }
  });

  it('no longer registers the series of the removed development pass-through (step 5.2 P14)', async () => {
    const service = new MetricsService({ service: 'test' });
    new DeliveryMetrics(service);
    const text = await service.metrics();
    for (const removed of [
      'delivery_approvals_skipped_total',
      'delivery_risk_holds_total',
      'delivery_dlp_holds_total',
      'delivery_dlp_alerts_approved_total',
      'delivery_bec_ai_only_not_held_total',
      'delivery_outbox_poll_lag_seconds',
      'delivery_outbox_invalid_events_total',
    ]) {
      expect(text).not.toContain(removed);
    }
    expect(text).toContain('# HELP delivery_approvals_total');
    expect(text).toContain('policy_copy');
  });
});
