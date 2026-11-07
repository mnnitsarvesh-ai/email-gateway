import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import { ENGINE_OUTCOME_VALUES, EventTypes, messageScanStageReadyV1 } from './events';
import { EXAMPLE_EVENT_PAYLOADS } from './examples';
import { EVENT_REGISTRY } from './registry';
import { eventRoutingKey, routeMessage } from './topology';

/** Step 4.4 B2: the second-stage trigger `mail.message.scan_stage_ready.v1`. */
const type = 'mail.message.scan_stage_ready.v1';
const example = EXAMPLE_EVENT_PAYLOADS[type] as Record<string, unknown>;
const ok = (payload: unknown) => messageScanStageReadyV1.safeParse(payload).success;
const patch = (fields: Record<string, unknown>) => ({ ...example, ...fields });

describe('mail.message.scan_stage_ready.v1 (step 4.4 B2)', () => {
  it('is registered on email.security with aggregate message, version 1', () => {
    expect(EventTypes.MessageScanStageReady).toBe(type);
    expect(EVENT_REGISTRY[type]).toMatchObject({
      type,
      version: 1,
      exchange: 'email.security',
      aggregateType: 'message',
    });
    expect(EVENT_REGISTRY[type].schema).toBe(messageScanStageReadyV1);
  });

  it('parses its example inside an envelope', () => {
    const event = parseEvent(
      {
        eventId: randomUUID(),
        eventType: type,
        occurredAt: '2026-11-01T10:15:31.300Z',
        correlationId: 'corr-12345678',
        organizationId: '42',
        payload: example,
      },
      messageScanStageReadyV1,
    );
    expect(event.payload).toEqual(example);
    expect(example).toMatchObject({ engine: 'bec', scanKind: 'initial', lifecycleRound: 0 });
  });

  it('routes only to scan.bec and the analytics firehose', () => {
    expect(routeMessage('email.security', eventRoutingKey('42', type))).toEqual([
      'email.analytics',
      'scan.bec',
    ]);
  });

  it('accepts every engine outcome of a dependency, failures and skipped included', () => {
    for (const outcome of ENGINE_OUTCOME_VALUES) {
      expect(ok(patch({ dependencies: [{ engine: 'rspamd', outcome }] })), outcome).toBe(true);
    }
    expect(ok(patch({ dependencies: [{ engine: 'rspamd', outcome: 'pending' }] }))).toBe(false);
  });

  it('accepts a rescan round with a new scan id', () => {
    expect(ok(patch({ scanKind: 'rescan', lifecycleRound: 3, scanId: '12' }))).toBe(true);
  });

  it('refuses malformed ids, keys, rounds, engines and dependency lists', () => {
    for (const fields of [
      { messageId: '0' },
      { messageId: 42 },
      { scanId: '011' },
      { receivedAt: '2026-11-01' },
      { readyAt: 'now' },
      { direction: 'sideways' },
      { emlS3Key: 'eml/2026/11/01/1.eml' },
      { emlS3Key: 'org/0/eml/x.eml' },
      { lifecycleRound: -1 },
      { lifecycleRound: 65_536 },
      { scanKind: 'stage' },
      { scanKind: 'initial', lifecycleRound: 2 },
      { scanKind: 'rescan', lifecycleRound: 0 },
      { engine: 'BEC' },
      { engine: '' },
      { engine: 'x'.repeat(33) },
      { dependencies: [] },
      {
        dependencies: Array.from({ length: 9 }, (_, i) => ({ engine: `e${i}`, outcome: 'clean' })),
      },
      {
        dependencies: [
          { engine: 'rspamd', outcome: 'clean' },
          { engine: 'rspamd', outcome: 'error' },
        ],
      },
      { dependencies: [{ engine: 'bec', outcome: 'clean' }] },
      { dependencies: [{ engine: 'rspamd', outcome: 'clean', score: 3 }] },
    ]) {
      expect(ok(patch(fields)), JSON.stringify(fields)).toBe(false);
    }
  });

  it('is strict: no content, addresses or reason codes can be added', () => {
    for (const extra of [
      { subject: 'Urgent wire' },
      { from: 'ceo@example.com' },
      { reasonCodes: ['bec.content.urgency'] },
      { verdict: 'clean' },
    ]) {
      expect(ok(patch(extra)), Object.keys(extra)[0]).toBe(false);
    }
    const { readyAt: _readyAt, ...missing } = example;
    expect(ok(missing)).toBe(false);
  });
});
