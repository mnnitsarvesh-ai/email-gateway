import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  assistantReportEmailRequestedV1,
  assistantReportGenerateRequestedV1,
} from './assistant-events';
import { parseEvent } from './envelope';
import { EventTypes } from './events';
import { EXAMPLE_EVENT_PAYLOADS } from './examples';
import { EVENT_REGISTRY } from './registry';
import { eventRoutingKey, queueDefinition, retryRoutingKey, routeMessage } from './topology';

/**
 * Step AI-R §4.3 (docs/plan/steps/31-ai-chat-reports.md D8, ADR-0095):
 * `assistant.report.email_requested.v1` — strict; the delivery and report public ids and the
 * request time only. The content guard over the examples runs in @email-gateway/common
 * (content-guard.test.ts covers every registered type).
 */
const type = EventTypes.AssistantReportEmailRequested;
const example = EXAMPLE_EVENT_PAYLOADS[type] as Record<string, unknown>;
const ok = (fields: Record<string, unknown>) =>
  assistantReportEmailRequestedV1.safeParse({ ...example, ...fields }).success;
const envelope = (eventType: string, payload: unknown) => ({
  eventId: String(example.deliveryId),
  eventType,
  occurredAt: '2026-11-23T08:00:00.000Z',
  correlationId: 'corr-12345678',
  organizationId: '42',
  payload,
});

describe('assistant.report.email_requested.v1 (§4.3)', () => {
  it('is registered on email.policy (aggregate assistant_report_delivery), version 1', () => {
    expect(type).toBe('assistant.report.email_requested.v1');
    expect(EVENT_REGISTRY[type]).toMatchObject({
      type,
      exchange: 'email.policy',
      aggregateType: 'assistant_report_delivery',
      version: 1,
    });
    expect(EVENT_REGISTRY[type].schema).toBe(assistantReportEmailRequestedV1);
  });

  it('routes to the notification-worker and the firehose only (topology v15)', () => {
    expect(routeMessage('email.policy', eventRoutingKey('42', type))).toEqual([
      'email.analytics',
      'email.notifications',
    ]);
    // Its retry hop reaches exactly the notification queue.
    expect(
      routeMessage('email.policy', retryRoutingKey('email.notifications', '42', type)),
    ).toEqual(['email.notifications']);
    expect(queueDefinition('email.notifications').bindings).toContainEqual({
      exchange: 'email.policy',
      routingKey: `org.*.${type}`,
    });
  });

  it('parses the example in an envelope (eventId = the delivery id) and rejects an unversioned type', () => {
    expect(parseEvent(envelope(type, example), assistantReportEmailRequestedV1).payload).toEqual(
      example,
    );
    expect(() =>
      parseEvent(
        envelope('assistant.report.email_requested', example),
        assistantReportEmailRequestedV1,
      ),
    ).toThrow();
  });

  it('accepts generated UUIDs and millisecond or second precision times', () => {
    expect(ok({ deliveryId: randomUUID(), reportId: randomUUID() })).toBe(true);
    expect(ok({ requestedAt: '2026-11-23T08:00:00Z' })).toBe(true);
  });

  it('is strict: no recipient, HTML, figures, title, organization or key', () => {
    for (const extra of [
      { to: 'someone@example.test' },
      { recipientAddress: 'someone@example.test' },
      { recipientSha256: 'a'.repeat(64) },
      { html: '<html></html>' },
      { figures: [{ label: 'Messages', value: '1' }] },
      { title: 'Security report' },
      { organizationName: 'Example' },
      { organizationId: '42' },
      { objectKey: 'org/42/assistant/report/2026/11/23/x.html' },
      { confirmationId: '7' },
    ]) {
      expect(ok(extra), Object.keys(extra)[0]).toBe(false);
    }
  });

  it('rejects malformed ids and times and every missing field', () => {
    for (const field of ['deliveryId', 'reportId'] as const) {
      expect(ok({ [field]: '42' }), field).toBe(false);
      expect(ok({ [field]: 'not-a-uuid' }), field).toBe(false);
      expect(ok({ [field]: '' }), field).toBe(false);
    }
    expect(ok({ requestedAt: 'yesterday' })).toBe(false);
    expect(ok({ requestedAt: '2026-11-23' })).toBe(false);
    expect(ok({ requestedAt: 1_763_884_800_000 })).toBe(false);
    for (const field of ['deliveryId', 'reportId', 'requestedAt']) {
      const payload: Record<string, unknown> = { ...example };
      delete payload[field];
      expect(assistantReportEmailRequestedV1.safeParse(payload).success, field).toBe(false);
    }
  });
});

/**
 * Step AI-6 §4.2 (docs/plan/steps/34-ai-chat-hardening-operations.md D5, ADR-0096):
 * `assistant.report.generate_requested.v1` — strict; the job and report public ids and the
 * request time only (no window, session id or credential: the job row holds them).
 */
describe('assistant.report.generate_requested.v1 (AI-6 §4.2)', () => {
  const jobType = EventTypes.AssistantReportGenerateRequested;
  const jobExample = EXAMPLE_EVENT_PAYLOADS[jobType] as Record<string, unknown>;
  const valid = (fields: Record<string, unknown>) =>
    assistantReportGenerateRequestedV1.safeParse({ ...jobExample, ...fields }).success;

  it('is registered on email.policy (aggregate assistant_report_job), version 1', () => {
    expect(jobType).toBe('assistant.report.generate_requested.v1');
    expect(EVENT_REGISTRY[jobType]).toMatchObject({
      type: jobType,
      exchange: 'email.policy',
      aggregateType: 'assistant_report_job',
      version: 1,
    });
    expect(EVENT_REGISTRY[jobType].schema).toBe(assistantReportGenerateRequestedV1);
  });

  it('routes to the api-assistant consumer and the firehose only (topology v16)', () => {
    expect(routeMessage('email.policy', eventRoutingKey('42', jobType))).toEqual([
      'assistant.reports',
      'email.analytics',
    ]);
    expect(
      routeMessage('email.policy', retryRoutingKey('assistant.reports', '42', jobType)),
    ).toEqual(['assistant.reports']);
    expect(queueDefinition('assistant.reports').bindings).toContainEqual({
      exchange: 'email.policy',
      routingKey: `org.*.${jobType}`,
    });
  });

  it('parses the example in an envelope (eventId = the job id)', () => {
    const wrapped = {
      eventId: String(jobExample.jobId),
      eventType: jobType,
      occurredAt: '2026-11-26T08:00:00.000Z',
      correlationId: 'corr-12345678',
      organizationId: '42',
      payload: jobExample,
    };
    expect(parseEvent(wrapped, assistantReportGenerateRequestedV1).payload).toEqual(jobExample);
  });

  it('accepts only the strict ids-only shape', () => {
    expect(valid({})).toBe(true);
    expect(valid({ jobId: randomUUID(), reportId: randomUUID() })).toBe(true);
    expect(valid({ jobId: 'not-a-uuid' })).toBe(false);
    expect(valid({ reportId: 42 })).toBe(false);
    expect(valid({ requestedAt: '26.11.2026' })).toBe(false);
    // No window, session or credential may ride along.
    for (const extra of [
      { from: '2026-10-27T00:00:00.000Z' },
      { sessionId: randomUUID() },
      { accessToken: 'x' },
      { title: 'Security report' },
    ]) {
      expect(valid(extra), JSON.stringify(extra)).toBe(false);
    }
    for (const key of ['jobId', 'reportId', 'requestedAt']) {
      const { [key]: _omit, ...rest } = jobExample;
      expect(assistantReportGenerateRequestedV1.safeParse(rest).success, key).toBe(false);
    }
  });
});
