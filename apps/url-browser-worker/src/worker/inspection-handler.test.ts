import {
  urlInspectionCompletedV1,
  type EventEnvelope,
  type UrlInspectionRequestedV1,
} from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import { describe, expect, it } from 'vitest';
import type { InspectionOutcome } from '../browser/inspector';
import { emptySignals } from '../browser/signals';
import { inspectableUrl, inspectionHandler } from './inspection-handler';

const NOW = Date.parse('2026-11-06T10:00:00.000Z');
const request = (
  overrides: Partial<UrlInspectionRequestedV1> = {},
): EventEnvelope<UrlInspectionRequestedV1> => ({
  eventId: '0190f000-0000-7000-8000-000000000001',
  eventType: 'mail.url.inspection_requested.v1',
  occurredAt: new Date(NOW).toISOString(),
  correlationId: 'corr-12345678',
  organizationId: '42',
  payload: {
    inspectionId: '77',
    messageId: '1001',
    receivedAt: '2026-11-06T09:00:00.000Z',
    scanId: '5',
    lifecycleRound: 0,
    urlSeq: 3,
    url: 'http://phish-login.test/',
    urlSha256: 'a'.repeat(64),
    requestedAt: new Date(NOW - 1000).toISOString(),
    deadlineAt: new Date(NOW + 3_600_000).toISOString(),
    ...overrides,
  },
});

const outcome: InspectionOutcome = {
  status: 'completed',
  errorCode: null,
  navigations: [{ host: 'phish-login.test', status: 200, kind: 'initial' }],
  signals: {
    ...emptySignals(),
    passwordFields: 1,
    forms: 1,
    crossOriginFormAction: true,
    formActionHosts: ['collector-site.test'],
  },
  finalUrlSha256: 'b'.repeat(64),
  finalHost: 'phish-login.test',
  durationMs: 1234,
  crashed: false,
};

function setup(
  inspect: () => Promise<InspectionOutcome> = () => Promise.resolve(outcome),
  publish?: (e: EventEnvelope) => Promise<void>,
) {
  const published: EventEnvelope[] = [];
  const jobs: string[] = [];
  let inspected = 0;
  const handler = inspectionHandler({
    inspect: () => {
      inspected += 1;
      return inspect();
    },
    publish:
      publish ??
      ((e) => {
        published.push(e);
        return Promise.resolve();
      }),
    logger: createLogger({ service: 'test', level: 'fatal' }),
    workerVersion: 'url-browser-worker/test',
    browserVersion: () => 'chromium-headless-shell/156.0',
    onJob: (result) => jobs.push(result),
    now: () => NOW,
    newEventId: () => '0190f000-0000-7000-8000-000000000002',
  });
  return { handler, published, jobs, inspected: () => inspected };
}

describe('inspection handler', () => {
  it('publishes a valid completed event with the request organization and correlation', async () => {
    const { handler, published, jobs } = setup();
    await expect(handler(request())).resolves.toBe('handled');
    expect(published).toHaveLength(1);
    const envelope = published[0] as EventEnvelope;
    expect(envelope).toMatchObject({
      eventType: 'mail.url.inspection_completed.v1',
      organizationId: '42',
      correlationId: 'corr-12345678',
    });
    const payload = urlInspectionCompletedV1.parse(envelope.payload);
    expect(payload).toMatchObject({
      inspectionId: '77',
      messageId: '1001',
      urlSeq: 3,
      status: 'completed',
      errorCode: null,
    });
    expect(JSON.stringify(payload)).not.toContain('http://');
    expect(jobs).toEqual(['completed']);
  });

  it('deadline passed → failed/deadline_passed without navigating', async () => {
    const { handler, published, inspected } = setup();
    await handler(request({ deadlineAt: new Date(NOW - 1).toISOString() }));
    expect(inspected()).toBe(0);
    expect(urlInspectionCompletedV1.parse(published[0]?.payload)).toMatchObject({
      status: 'failed',
      errorCode: 'deadline_passed',
    });
  });

  it('a failed inspection is published with its error code', async () => {
    const { handler, published } = setup(() =>
      Promise.resolve({ ...outcome, status: 'failed', errorCode: 'job_timeout' }),
    );
    await handler(request());
    expect(urlInspectionCompletedV1.parse(published[0]?.payload)).toMatchObject({
      status: 'failed',
      errorCode: 'job_timeout',
    });
  });

  it('a publish that is not confirmed throws (no ack; the consumer retries)', async () => {
    const { handler } = setup(undefined, () => Promise.reject(new Error('nacked')));
    await expect(handler(request())).rejects.toThrow('nacked');
  });

  it('only http(s) URLs without userinfo are inspected', () => {
    expect(inspectableUrl('https://a.test/x')).toBe(true);
    expect(inspectableUrl('file:///etc/passwd')).toBe(false);
    expect(inspectableUrl('http://u:p@a.test/')).toBe(false);
    expect(inspectableUrl(`http://a.test/${'x'.repeat(2100)}`)).toBe(false);
  });
});
