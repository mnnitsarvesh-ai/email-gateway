import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import { eventEnvelopeSchema } from './envelope';
import {
  DELIVERY_STATUSES,
  deliveryApprovedV1,
  deliveryStatusChangedV1,
  domainRoutingChangedV1,
  domainStatusChangedV1,
  EventTypes,
  messageReceivedV1,
  messageScannedV1,
  policyDecidedV1,
} from './events';
import { QUEUES, queueArguments } from './topology';

const organizationId = '42';
const receivedAt = '2026-11-01T10:15:30.123Z';

function envelope(payload: unknown, overrides: Record<string, unknown> = {}) {
  return {
    eventId: randomUUID(),
    eventType: EventTypes.MessageReceived,
    occurredAt: new Date().toISOString(),
    correlationId: 'corr-12345678',
    organizationId,
    payload,
    ...overrides,
  };
}

function receivedPayload(overrides: Record<string, unknown> = {}) {
  return {
    messageId: '9007199254740993',
    receivedAt,
    direction: 'inbound',
    emlS3Key: `org/${organizationId}/eml/2026/11/01/9007199254740993.eml`,
    sizeBytes: 1024,
    envelopeFrom: 'a@example.com',
    recipientCount: 1,
    ...overrides,
  };
}

describe('parseEvent', () => {
  it('accepts a valid message.received event', () => {
    const event = parseEvent(envelope(receivedPayload()), messageReceivedV1);
    expect(event.organizationId).toBe('42');
    expect(event.payload.messageId).toBe('9007199254740993');
    expect(event.payload.direction).toBe('inbound');
  });

  it('accepts a valid message.scanned event', () => {
    const event = parseEvent(
      envelope(
        { messageId: '7', receivedAt, scanIds: ['11', '12'], timedOutStages: [] },
        { eventType: EventTypes.MessageScanned },
      ),
      messageScannedV1,
    );
    expect(event.payload.scanIds).toEqual(['11', '12']);
  });

  it('accepts a valid policy.decided event', () => {
    const event = parseEvent(
      envelope(
        {
          messageId: '7',
          receivedAt,
          action: 'quarantine',
          matchedPolicyVersionIds: ['3'],
          archive: true,
        },
        { eventType: EventTypes.PolicyDecided },
      ),
      policyDecidedV1,
    );
    expect(event.payload.matchedPolicyVersionIds).toEqual(['3']);
  });

  it('rejects a UUID organization id', () => {
    expect(() =>
      parseEvent(envelope(receivedPayload(), { organizationId: randomUUID() }), messageReceivedV1),
    ).toThrow();
  });

  it('rejects ids with leading zeros', () => {
    expect(() =>
      parseEvent(envelope(receivedPayload(), { organizationId: '042' }), messageReceivedV1),
    ).toThrow();
    expect(() =>
      parseEvent(envelope(receivedPayload({ messageId: '0123' })), messageReceivedV1),
    ).toThrow();
    expect(() =>
      parseEvent(
        envelope(
          { messageId: '7', receivedAt, scanIds: ['011'], timedOutStages: [] },
          { eventType: EventTypes.MessageScanned },
        ),
        messageScannedV1,
      ),
    ).toThrow();
  });

  it('rejects a UUID message id', () => {
    expect(() =>
      parseEvent(envelope(receivedPayload({ messageId: randomUUID() })), messageReceivedV1),
    ).toThrow();
  });

  it('rejects S3 keys that are not organization-prefixed', () => {
    for (const emlS3Key of ['eml/x.eml', `org/${randomUUID()}/eml/x.eml`, 'org/042/eml/x.eml']) {
      expect(() =>
        parseEvent(envelope(receivedPayload({ emlS3Key })), messageReceivedV1),
      ).toThrow();
    }
  });

  it('rejects unversioned event types', () => {
    expect(() =>
      parseEvent(envelope(receivedPayload(), { eventType: 'mail.received' }), messageReceivedV1),
    ).toThrow();
  });
});

describe('domain.status.changed.v1', () => {
  const domainPayload = (overrides: Record<string, unknown> = {}) => ({
    domainId: '9007199254740993',
    domainPublicId: '01890a5d-ac96-774b-bcce-b302099a8057',
    name: 'xn--bcher-kva.example',
    previousStatus: 'verified',
    status: 'active',
    reason: null,
    changedAt: '2026-11-02T09:00:00.000Z',
    ...overrides,
  });
  const parse = (payload: unknown) =>
    parseEvent(
      envelope(payload, { eventType: EventTypes.DomainStatusChanged }),
      domainStatusChangedV1,
    );

  it('has a versioned event type', () => {
    expect(EventTypes.DomainStatusChanged).toBe('domain.status.changed.v1');
  });

  it('accepts a status change, a first status (previousStatus null) and a reason', () => {
    expect(parse(domainPayload()).payload.status).toBe('active');
    expect(
      parse(domainPayload({ previousStatus: null, status: 'pending_verification' })).payload
        .previousStatus,
    ).toBeNull();
    expect(
      parse(
        domainPayload({
          previousStatus: 'pending_verification',
          status: 'failed',
          reason: 'claimed_by_another_organization',
        }),
      ).payload.reason,
    ).toBe('claimed_by_another_organization');
  });

  it('rejects numeric or malformed ids, long names and reasons, and non-ISO timestamps', () => {
    for (const overrides of [
      { domainId: 9 },
      { domainId: '09' },
      { domainId: randomUUID().replaceAll('-', '') },
      { domainPublicId: '12' },
      { name: '' },
      { name: 'a'.repeat(254) },
      { status: '' },
      { reason: 'x'.repeat(513) },
      { changedAt: '2026-11-02' },
      { changedAt: 'yesterday' },
    ]) {
      expect(() => parse(domainPayload(overrides)), JSON.stringify(overrides)).toThrow();
    }
    const { reason: _reason, ...withoutReason } = domainPayload();
    expect(() => parse(withoutReason)).toThrow();
  });
});

describe('event types', () => {
  it('passes the envelope eventType rule for every type, without duplicates', () => {
    const types = Object.values(EventTypes);
    expect(new Set(types).size).toBe(types.length);
    for (const eventType of types) {
      expect(eventEnvelopeSchema.shape.eventType.safeParse(eventType).success, eventType).toBe(
        true,
      );
    }
    expect(EventTypes).toMatchObject({
      DeliveryApproved: 'mail.delivery.approved.v1',
      DeliveryStatusChanged: 'mail.delivery.status_changed.v1',
      DomainRoutingChanged: 'domain.routing.changed.v1',
    });
  });
});

describe('mail.delivery.approved.v1', () => {
  const approval = (overrides: Record<string, unknown> = {}) => ({
    messageId: '9007199254740993',
    receivedAt,
    deliverySeq: 0,
    source: 'policy',
    emlS3Key: `org/${organizationId}/eml/2026/11/01/abc.eml`,
    recipients: [
      { recipientId: '11', rcptSeq: 0 },
      { recipientId: '12', rcptSeq: 1 },
    ],
    approvedAt: '2026-11-01T10:16:00.000Z',
    ...overrides,
  });
  const parse = (payload: unknown) =>
    parseEvent(envelope(payload, { eventType: EventTypes.DeliveryApproved }), deliveryApprovedV1);

  it('accepts every source and the delivery sequence bounds', () => {
    for (const source of ['policy', 'quarantine_release', 'dev_passthrough']) {
      expect(parse(approval({ source })).payload.source).toBe(source);
    }
    expect(parse(approval({ deliverySeq: 65_535 })).payload.deliverySeq).toBe(65_535);
    const many = Array.from({ length: 1000 }, (_, i) => ({
      recipientId: String(i + 1),
      rcptSeq: i,
    }));
    expect(parse(approval({ recipients: many })).payload.recipients).toHaveLength(1000);
  });

  it('rejects malformed approvals', () => {
    const tooMany = Array.from({ length: 1001 }, (_, i) => ({
      recipientId: String(i + 1),
      rcptSeq: i,
    }));
    for (const overrides of [
      { messageId: '07' },
      { receivedAt: '2026-11-01' },
      { deliverySeq: -1 },
      { deliverySeq: 65_536 },
      { deliverySeq: 1.5 },
      { source: 'manual' },
      { emlS3Key: 'eml/x.eml' },
      { recipients: [] },
      { recipients: tooMany },
      {
        recipients: [
          { recipientId: '11', rcptSeq: 0 },
          { recipientId: '11', rcptSeq: 1 },
        ],
      },
      { recipients: [{ recipientId: 11, rcptSeq: 0 }] },
      { recipients: [{ recipientId: '11', rcptSeq: 70_000 }] },
      { recipients: [{ recipientId: '11' }] },
      { approvedAt: 'now' },
    ]) {
      expect(() => parse(approval(overrides)), JSON.stringify(overrides).slice(0, 80)).toThrow();
    }
  });
});

describe('mail.delivery.status_changed.v1', () => {
  const change = (overrides: Record<string, unknown> = {}) => ({
    messageId: '9007199254740993',
    receivedAt,
    deliveryId: '501',
    recipientId: '11',
    rcptSeq: 0,
    deliverySeq: 0,
    direction: 'outbound',
    previousStatus: 'queued',
    status: 'delivered',
    occurredAt: '2026-11-01T10:20:00.000Z',
    attemptCount: 1,
    smtpCode: 250,
    enhancedStatus: '2.0.0',
    queueId: '4ZkQ2s1Hb7z9',
    ...overrides,
  });
  const parse = (payload: unknown) =>
    parseEvent(
      envelope(payload, { eventType: EventTypes.DeliveryStatusChanged }),
      deliveryStatusChangedV1,
    );

  it('accepts every delivery status and a first status without optional fields', () => {
    expect(DELIVERY_STATUSES).toEqual([
      'pending',
      'in_progress',
      'queued',
      'deferred',
      'delivered',
      'bounced',
      'expired',
      'failed',
      'suppressed',
      'unknown',
    ]);
    for (const status of DELIVERY_STATUSES) {
      expect(parse(change({ status, previousStatus: status })).payload.status).toBe(status);
    }
    const {
      smtpCode: _code,
      enhancedStatus: _enhanced,
      queueId: _queue,
      ...minimal
    } = change({ previousStatus: null, status: 'pending', attemptCount: 0 });
    const parsed = parse(minimal).payload;
    expect(parsed.previousStatus).toBeNull();
    expect(parsed.smtpCode).toBeUndefined();
    expect(parse(change({ errorClass: 'remote_4xx' })).payload.errorClass).toBe('remote_4xx');
  });

  it('rejects unknown statuses, bad ids, codes and missing fields', () => {
    for (const overrides of [
      { status: 'sent' },
      { previousStatus: 'sent' },
      { direction: 'both' },
      { deliveryId: '0' },
      { recipientId: 'abc' },
      { rcptSeq: -1 },
      { attemptCount: -1 },
      { smtpCode: 99 },
      { enhancedStatus: '2.0' },
      { errorClass: 'Remote 4xx' },
      { queueId: 'a b' },
      { occurredAt: 'later' },
      { previousStatus: undefined },
    ]) {
      expect(() => parse(change(overrides)), JSON.stringify(overrides)).toThrow();
    }
  });

  it('carries no address field', () => {
    const parsed = parse(change({ address: 'user@example.com' })).payload as Record<
      string,
      unknown
    >;
    expect(parsed).not.toHaveProperty('address');
  });
});

describe('domain.routing.changed.v1', () => {
  const routing = (overrides: Record<string, unknown> = {}) => ({
    domainId: '77',
    domainPublicId: '01890a5d-ac96-774b-bcce-b302099a8057',
    name: 'acme.example',
    hosts: ['mx1.acme.example', 'acme-example.mail.protection.outlook.com'],
    changedAt: '2026-11-03T09:00:00.000Z',
    ...overrides,
  });
  const parse = (payload: unknown) =>
    parseEvent(
      envelope(payload, { eventType: EventTypes.DomainRoutingChanged }),
      domainRoutingChangedV1,
    );

  it('accepts a change with old and new hosts, and a removal without hosts', () => {
    expect(parse(routing()).payload.hosts).toHaveLength(2);
    expect(parse(routing({ hosts: [] })).payload.hosts).toEqual([]);
    const twenty = Array.from({ length: 20 }, (_, i) => `mx${i}.acme.example`);
    expect(parse(routing({ hosts: twenty })).payload.hosts).toHaveLength(20);
  });

  it('rejects malformed payloads', () => {
    for (const overrides of [
      { domainId: '0' },
      { domainPublicId: 'x' },
      { name: '' },
      { hosts: [''] },
      { hosts: Array.from({ length: 21 }, (_, i) => `mx${i}.acme.example`) },
      { changedAt: '2026-11-03' },
    ]) {
      expect(() => parse(routing(overrides)), JSON.stringify(overrides).slice(0, 80)).toThrow();
    }
  });
});

describe('topology', () => {
  it('declares every work queue as a quorum queue with a dead-letter route', () => {
    for (const queue of Object.values(QUEUES)) {
      expect(queueArguments(queue)).toMatchObject({
        'x-queue-type': 'quorum',
        'x-dead-letter-routing-key': `${queue.name}.dlq`,
      });
    }
  });
});
