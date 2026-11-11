import { MetricsService } from '@email-gateway/common';
import type { EventEnvelope } from '@email-gateway/event-contracts';
import { EventTypes } from '@email-gateway/event-contracts';
import { describe, expect, it, vi } from 'vitest';
import { PolicyMetrics } from '../metrics/policy-metrics';
import type {
  EvaluationOutcome,
  PolicyEvaluationService,
  TriggerPayload,
} from './evaluation.service';
import { POLICY_EVALUATE_CONSUMER } from './evaluation.service';
import {
  createPolicyEvaluateFeed,
  POLICY_EVALUATE_QUEUE,
  POLICY_EVENT_TYPES,
  PolicyEvaluateConsumer,
  recordOutcome,
} from './policy-evaluate.consumer';

const evaluated = (overrides: Partial<Extract<EvaluationOutcome, { status: 'evaluated' }>> = {}) =>
  ({
    status: 'evaluated',
    result: {
      round: { trigger: 'scanned', direction: 'inbound', lifecycleRound: 0, scanId: '1' },
      disposition: 'quarantine',
      decisive: { source: 'floor' },
      floor: { reasons: ['policy.floor.hard_block', 'policy.floor.risk_missing'] },
      override: null,
      clamps: [{ ref: 'x', from: 'allow', to: 'quarantine', reason: 'override_disabled' }],
      actions: [{ type: 'QUARANTINE' }, { type: 'TAG' }],
    },
    statuses: ['enforced', 'not_applicable'],
    copy: null,
    cache: 'hit',
    invalidVersions: 2,
    durationSeconds: 0.004,
    riskMissing: true,
    approvals: 0,
    outcome: {
      edge: 'E11',
      to: 'quarantined',
      reason: 'policy_quarantine',
      finalAction: 'quarantine',
    },
    ...overrides,
  }) as unknown as EvaluationOutcome;

describe('recordOutcome (P24 series)', () => {
  it('records every P24 series of a committed evaluation with bounded labels', async () => {
    const service = new MetricsService({ service: 't' });
    const metrics = new PolicyMetrics(service);
    recordOutcome(metrics, evaluated());
    recordOutcome(
      metrics,
      evaluated({ copy: 'too_large', cache: 'miss', invalidVersions: 0, riskMissing: false }),
    );
    recordOutcome(metrics, { status: 'skipped', result: 'stale' });
    const text = await service.metrics();
    for (const line of [
      'policy_evaluations_total{trigger="scanned",disposition="quarantine",source="floor",direction="inbound",service="t"} 2',
      'policy_evaluation_duration_seconds_count{service="t"} 2',
      'policy_floor_raises_total{reason="hard_block",service="t"} 2',
      'policy_floor_raises_total{reason="risk_missing",service="t"} 2',
      'policy_overrides_total{result="clamped",service="t"} 2',
      'policy_actions_total{type="QUARANTINE",status="enforced",service="t"} 2',
      'policy_actions_total{type="TAG",status="not_applicable",service="t"} 2',
      'policy_lifecycle_skipped_total{result="stale",service="t"} 1',
      'policy_snapshot_cache_total{result="hit",service="t"} 1',
      'policy_snapshot_cache_total{result="miss",service="t"} 1',
      'policy_snapshot_invalid_versions_total{service="t"} 2',
      'policy_copy_total{result="too_large",service="t"} 1',
      'policy_risk_missing_total{service="t"} 1',
    ]) {
      expect(text).toContain(line);
    }
  });

  it('registers exactly the P24 names (plus the shared lifecycle series)', async () => {
    const service = new MetricsService({ service: 't' });
    new PolicyMetrics(service);
    const text = await service.metrics();
    for (const name of [
      'policy_evaluations_total',
      'policy_evaluation_duration_seconds',
      'policy_floor_raises_total',
      'policy_overrides_total',
      'policy_actions_total',
      'policy_lifecycle_skipped_total',
      'policy_inconsistent_reads_total',
      'policy_input_errors_total',
      'policy_snapshot_cache_total',
      'policy_snapshot_invalid_versions_total',
      'policy_copy_total',
      'policy_risk_missing_total',
      'lifecycle_transitions_total',
    ]) {
      expect(text).toContain(`# TYPE ${name} `);
    }
  });
});

describe('PolicyEvaluateConsumer', () => {
  it('consumes email.policy.evaluate as policy-engine.evaluate for scanned.v1 and parse_failed.v1', () => {
    expect(POLICY_EVALUATE_QUEUE).toBe('email.policy.evaluate');
    expect(POLICY_EVALUATE_CONSUMER).toBe('policy-engine.evaluate');
    expect(POLICY_EVENT_TYPES).toEqual([EventTypes.MessageScanned, EventTypes.MessageParseFailed]);
    const feed = createPolicyEvaluateFeed({
      connection: { requireTopology: () => undefined } as never,
      publisher: {} as never,
      prefetch: 8,
      logger: { child: () => ({}) } as never,
    });
    expect(feed.queue).toBe('email.policy.evaluate');
    expect(feed.consumerName).toBe('policy-engine.evaluate');
    // The topology's v9 retry policy (P15): hold, 10 attempts, 2 s – 1 min, 24 h.
    expect(feed.retryPolicy).toMatchObject({
      strategy: 'hold',
      maxAttempts: 10,
      baseDelayMs: 2000,
      maxDelayMs: 60_000,
      maxRetryAgeMs: 86_400_000,
    });
  });

  it('records metrics only after the ledger transaction committed', async () => {
    const service = new MetricsService({ service: 't' });
    const metrics = new PolicyMetrics(service);
    const evaluation = { evaluate: vi.fn(() => Promise.resolve(evaluated())) };
    let commit = true;
    const prisma = {
      $transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => {
        const tx = { messageIdempotency: { create: vi.fn(() => Promise.resolve({})) } };
        const result = await fn(tx);
        if (!commit) throw new Error('commit failed');
        return result;
      }),
    };
    const consumer = new PolicyEvaluateConsumer(
      { start: vi.fn(), stop: vi.fn(() => Promise.resolve()) },
      evaluation as unknown as PolicyEvaluationService,
      prisma as never,
      metrics,
      120_000,
    );
    const event = {
      eventId: '0190f0f0-0000-7000-8000-000000000001',
    } as EventEnvelope<TriggerPayload>;
    commit = false;
    await expect(consumer.handler(event)).rejects.toThrow('commit failed');
    expect(await service.metrics()).not.toContain('policy_evaluations_total{');
    commit = true;
    expect(await consumer.handler(event)).toBe('handled');
    expect(await service.metrics()).toContain('policy_evaluations_total{');
  });
});
