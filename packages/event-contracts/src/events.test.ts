import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import { eventEnvelopeSchema } from './envelope';
import {
  ACTOR_ROLES,
  ATTACHMENT_FILE_TYPE_VALUES,
  actorRoleSchema,
  attachmentSandboxRequestedV1,
  DELIVERY_STATUSES,
  deliveryApprovedV1,
  ENGINE_OUTCOME_VALUES,
  deliveryStatusChangedV1,
  domainRoutingChangedV1,
  domainStatusChangedV1,
  EventTypes,
  MESSAGE_PARSE_STATUSES,
  MESSAGE_STATES,
  MIME_LIMIT_NAMES,
  messageParsedV1,
  messageParseFailedV1,
  messageReceivedV1,
  messageRescanRequestedV1,
  messageScannedV1,
  messageStateChangedV1,
  messageStateSchema,
  PARSE_FAILURE_REASONS,
  organizationIdOfKey,
  policyDecidedV1,
  SANDBOX_ATTACHMENT_VERDICT_VALUES,
  SCAN_VERDICT_VALUES,
} from './events';

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

function scannedPayload(overrides: Record<string, unknown> = {}) {
  return {
    messageId: '7',
    receivedAt,
    direction: 'inbound',
    emlS3Key: `org/${organizationId}/eml/2026/11/01/7.eml`,
    lifecycleRound: 0,
    scanId: '11',
    scanKind: 'initial',
    outcome: 'scanned',
    verdict: 'clean',
    engines: [{ engine: 'rspamd', required: true, outcome: 'clean', attempts: 1 }],
    reasonCodes: ['clean.below_threshold'],
    completedAt: '2026-11-01T10:15:31.000Z',
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
      envelope(scannedPayload(), { eventType: EventTypes.MessageScanned }),
      messageScannedV1,
    );
    expect(event.payload.scanId).toBe('11');
    expect(event.payload.engines[0]?.engine).toBe('rspamd');
  });

  it('refuses the step 1.1 placeholder shape of policy.decided (redefined by step 5.2)', () => {
    expect(() =>
      parseEvent(
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
      ),
    ).toThrow();
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
        envelope(scannedPayload({ scanId: '011' }), { eventType: EventTypes.MessageScanned }),
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
      MessageParsed: 'mail.message.parsed.v1',
      MessageParseFailed: 'mail.message.parse_failed.v1',
      MessageStateChanged: 'mail.message.state_changed.v1',
      MessageRescanRequested: 'mail.message.rescan_requested.v1',
      AttachmentSandboxRequested: 'mail.attachment.sandbox_requested.v1',
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

  it('accepts an optional lifecycle round (absent = round 0) within 0..65535', () => {
    expect(parse(approval()).payload.lifecycleRound).toBeUndefined();
    expect(parse(approval({ lifecycleRound: 0 })).payload.lifecycleRound).toBe(0);
    expect(parse(approval({ lifecycleRound: 65_535 })).payload.lifecycleRound).toBe(65_535);
    for (const lifecycleRound of [-1, 65_536, 1.5, '1', null]) {
      expect(() => parse(approval({ lifecycleRound })), String(lifecycleRound)).toThrow();
    }
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

describe('mail.message.parsed.v1', () => {
  const sha = 'a'.repeat(64);
  const partPrefix = `org/${organizationId}/part/2026/11/01/9007199254740993`;
  const parsed = (overrides: Record<string, unknown> = {}) => ({
    messageId: '9007199254740993',
    receivedAt,
    direction: 'inbound',
    emlS3Key: `org/${organizationId}/eml/2026/11/01/abc.eml`,
    parseStatus: 'parsed',
    parserVersion: '1.0.0',
    limitsExceeded: [],
    defects: [],
    textBody: { s3Key: `${partPrefix}/1.text`, sha256: sha, sizeBytes: 120 },
    htmlBody: { s3Key: `${partPrefix}/2.html`, sha256: 'b'.repeat(64), sizeBytes: 480 },
    attachmentCount: 2,
    flaggedAttachmentCount: 1,
    attachmentFlags: ['filename_double_extension', 'executable'],
    partCount: 5,
    maxDepth: 2,
    headerCount: 14,
    ...overrides,
  });
  const parse = (payload: unknown) =>
    parseEvent(envelope(payload, { eventType: EventTypes.MessageParsed }), messageParsedV1);

  it('exports the limit names, parse statuses and failure reasons of the design', () => {
    expect(MIME_LIMIT_NAMES).toEqual([
      'message_size',
      'nesting_depth',
      'part_count',
      'header_count',
      'header_line_length',
      'header_block_size',
      'attachment_count',
      'attachment_size',
      'body_size',
      'decoded_ratio',
      'total_decoded_size',
      'parse_timeout',
    ]);
    expect(MESSAGE_PARSE_STATUSES).toEqual([
      'parsed',
      'parsed_with_defects',
      'parse_limit_exceeded',
    ]);
    expect(PARSE_FAILURE_REASONS).toEqual([
      'eml_missing',
      'eml_key_mismatch',
      'integrity_mismatch',
      'max_attempts_exceeded',
      'parser_error',
    ]);
  });

  it('accepts every final status with consistent limits and defects', () => {
    expect(parse(parsed()).payload.parseStatus).toBe('parsed');
    expect(
      parse(parsed({ parseStatus: 'parsed_with_defects', defects: ['missing_closing_boundary'] }))
        .payload.defects,
    ).toEqual(['missing_closing_boundary']);
    const limited = parse(
      parsed({
        parseStatus: 'parse_limit_exceeded',
        limitsExceeded: ['attachment_size', 'parse_timeout'],
        defects: ['invalid_base64'],
      }),
    ).payload;
    expect(limited.limitsExceeded).toEqual(['attachment_size', 'parse_timeout']);
  });

  it('accepts every limit name once, absent bodies, an unstored body and zero counts', () => {
    expect(
      parse(parsed({ parseStatus: 'parse_limit_exceeded', limitsExceeded: [...MIME_LIMIT_NAMES] }))
        .payload.limitsExceeded,
    ).toHaveLength(12);
    const empty = parse(
      parsed({
        parseStatus: 'parse_limit_exceeded',
        limitsExceeded: ['message_size'],
        textBody: null,
        htmlBody: { s3Key: null, sha256: sha, sizeBytes: 0 },
        attachmentCount: 0,
        flaggedAttachmentCount: 0,
        attachmentFlags: [],
        partCount: 0,
        maxDepth: 0,
        headerCount: 0,
      }),
    ).payload;
    expect(empty.textBody).toBeNull();
    expect(empty.htmlBody).toEqual({ s3Key: null, sha256: sha, sizeBytes: 0 });
    const codes = Array.from({ length: 64 }, (_, i) => `code_${i}`);
    expect(
      parse(parsed({ parseStatus: 'parsed_with_defects', defects: codes, attachmentFlags: codes }))
        .payload.attachmentFlags,
    ).toHaveLength(64);
  });

  it('rejects keys that are not organization-prefixed', () => {
    for (const overrides of [
      { emlS3Key: 'eml/2026/11/01/abc.eml' },
      { emlS3Key: 'org/0/eml/abc.eml' },
      { textBody: { s3Key: 'part/1.text', sha256: sha, sizeBytes: 1 } },
      { htmlBody: { s3Key: '/org/42/part/2.html', sha256: sha, sizeBytes: 1 } },
    ]) {
      expect(() => parse(parsed(overrides)), JSON.stringify(overrides)).toThrow();
    }
  });

  it('rejects bad hashes', () => {
    for (const sha256 of ['A'.repeat(64), 'a'.repeat(63), 'a'.repeat(65), 'g'.repeat(64), '']) {
      expect(
        () => parse(parsed({ textBody: { s3Key: null, sha256, sizeBytes: 1 } })),
        sha256,
      ).toThrow();
    }
  });

  it('rejects unknown limit names, duplicates, bad codes and oversized arrays', () => {
    const limitExceeded = { parseStatus: 'parse_limit_exceeded' };
    const tooMany = Array.from({ length: 65 }, (_, i) => `code_${i}`);
    for (const overrides of [
      { ...limitExceeded, limitsExceeded: ['message_bytes'] },
      { ...limitExceeded, limitsExceeded: ['part_count', 'part_count'] },
      { attachmentFlags: ['executable', 'executable'] },
      { parseStatus: 'parsed_with_defects', defects: tooMany },
      { attachmentFlags: tooMany },
      { parseStatus: 'parsed_with_defects', defects: ['Invalid Base64'] },
      { parseStatus: 'parsed_with_defects', defects: ['x'.repeat(49)] },
      { parseStatus: 'parsed_with_defects', defects: [''] },
      { attachmentFlags: ['report.pdf.exe'] },
    ]) {
      expect(() => parse(parsed(overrides)), JSON.stringify(overrides).slice(0, 80)).toThrow();
    }
  });

  it('rejects inconsistent statuses, bad ids, versions and counts', () => {
    for (const overrides of [
      { parseStatus: 'parsing' },
      { parseStatus: 'parse_failed' },
      { parseStatus: 'parse_limit_exceeded' },
      { limitsExceeded: ['body_size'] },
      { parseStatus: 'parsed_with_defects' },
      { defects: ['invalid_base64'] },
      { flaggedAttachmentCount: 3 },
      { messageId: '07' },
      { messageId: 42 },
      { receivedAt: '2026-11-01' },
      { direction: 'sideways' },
      { parserVersion: '' },
      { parserVersion: 'v'.repeat(33) },
      { attachmentCount: -1 },
      { partCount: 1.5 },
      { maxDepth: '2' },
      { headerCount: undefined },
      { textBody: undefined },
      { textBody: { s3Key: null, sha256: sha, sizeBytes: -1 } },
    ]) {
      expect(() => parse(parsed(overrides)), JSON.stringify(overrides)).toThrow();
    }
  });

  it('carries no subject, address, filename or header value', () => {
    const payload = parse(
      parsed({ subject: 'Hello', envelopeFrom: 'a@example.com', filename: 'x.pdf' }),
    ).payload as Record<string, unknown>;
    for (const field of ['subject', 'envelopeFrom', 'filename', 'headerFrom']) {
      expect(payload).not.toHaveProperty(field);
    }
  });
});

describe('mail.message.parse_failed.v1', () => {
  const failed = (overrides: Record<string, unknown> = {}) => ({
    messageId: '9007199254740993',
    receivedAt,
    direction: 'outbound',
    emlS3Key: `org/${organizationId}/eml/2026/11/01/abc.eml`,
    reason: 'integrity_mismatch',
    attempts: 1,
    parserVersion: '1.0.0',
    ...overrides,
  });
  const parse = (payload: unknown) =>
    parseEvent(
      envelope(payload, { eventType: EventTypes.MessageParseFailed }),
      messageParseFailedV1,
    );

  it('accepts every failure reason', () => {
    for (const reason of PARSE_FAILURE_REASONS) {
      expect(parse(failed({ reason, attempts: 6 })).payload.reason).toBe(reason);
    }
  });

  it('carries a null key when the stored key is not organization-prefixed (eml_key_mismatch)', () => {
    expect(
      parse(failed({ reason: 'eml_key_mismatch', emlS3Key: null })).payload.emlS3Key,
    ).toBeNull();
  });

  it('rejects unknown reasons, zero attempts and malformed fields', () => {
    for (const overrides of [
      { reason: 'timeout' },
      { attempts: 0 },
      { attempts: 1.5 },
      { emlS3Key: 'eml/abc.eml' },
      { emlS3Key: undefined },
      { messageId: 'abc' },
      { parserVersion: '' },
      { direction: undefined },
    ]) {
      expect(() => parse(failed(overrides)), JSON.stringify(overrides)).toThrow();
    }
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

describe('lifecycle states and actor roles (step 3.3 L2, L3)', () => {
  it('lists the fifteen states in rank/enum order and the ten actor roles', () => {
    expect(MESSAGE_STATES).toEqual([
      'received',
      'persisted',
      'scanning',
      'scanned',
      'scan_failed',
      'policy_evaluated',
      'approved',
      'quarantined',
      'held_for_review',
      'rejected',
      'delivery_pending',
      'delivery_retry',
      'delivered',
      'archived',
      'expired',
    ]);
    expect(ACTOR_ROLES).toEqual([
      'ingestion',
      'scanner',
      'policy',
      'dev_passthrough',
      'delivery',
      'operator',
      'quarantine',
      'archive',
      'sweeper',
      'recovery',
    ]);
    for (const state of MESSAGE_STATES) expect(messageStateSchema.parse(state)).toBe(state);
    // The step 1.1 values retired by ADR-0025.
    for (const old of ['delivery_queued', 'partially_delivered', 'discarded', 'failed']) {
      expect(messageStateSchema.safeParse(old).success, old).toBe(false);
    }
    expect(actorRoleSchema.safeParse('legacy').success).toBe(false);
  });
});

describe('mail.message.state_changed.v1', () => {
  const changed = (overrides: Record<string, unknown> = {}) => ({
    messageId: '9007199254740993',
    receivedAt,
    direction: 'inbound',
    previousState: 'approved',
    state: 'delivery_pending',
    version: 3,
    lifecycleRound: 0,
    reasonCode: 'delivery_planned',
    actorRole: 'delivery',
    actorType: 'system',
    actorService: 'delivery-worker',
    causationEventId: '01890a5d-ac96-774b-bcce-b302099a8057',
    changedAt: '2026-11-01T10:16:01.000Z',
    ...overrides,
  });
  const parse = (payload: unknown) =>
    parseEvent(
      envelope(payload, { eventType: EventTypes.MessageStateChanged }),
      messageStateChangedV1,
    );

  it('accepts every state, role and actor type, a null previous state and causation', () => {
    for (const state of MESSAGE_STATES) {
      expect(parse(changed({ state, previousState: state })).payload.state).toBe(state);
    }
    for (const actorRole of ACTOR_ROLES) {
      expect(parse(changed({ actorRole })).payload.actorRole).toBe(actorRole);
    }
    for (const actorType of ['system', 'user', 'api_key']) {
      expect(parse(changed({ actorType })).payload.actorType).toBe(actorType);
    }
    const first = parse(changed({ previousState: null, causationEventId: null })).payload;
    expect(first.previousState).toBeNull();
    expect(first.causationEventId).toBeNull();
    expect(parse(changed({ lifecycleRound: 65_535 })).payload.lifecycleRound).toBe(65_535);
    expect(parse(changed({ reasonCode: 'a'.repeat(64) })).payload.reasonCode).toHaveLength(64);
    expect(parse(changed({ actorService: 'x'.repeat(64) })).payload.actorService).toHaveLength(64);
  });

  it('rejects unknown states, roles, codes and malformed fields', () => {
    for (const overrides of [
      { state: 'delivery_queued' },
      { state: 'partially_delivered' },
      { previousState: 'failed' },
      { direction: 'both' },
      { messageId: '0' },
      { version: -1 },
      { version: 1.5 },
      { lifecycleRound: -1 },
      { lifecycleRound: 65_536 },
      { reasonCode: '' },
      { reasonCode: 'Delivery-Planned' },
      { reasonCode: 'a'.repeat(65) },
      { actorRole: 'legacy' },
      { actorType: 'service' },
      { actorService: '' },
      { actorService: 'x'.repeat(65) },
      { causationEventId: 'not-a-uuid' },
      { changedAt: '2026-11-01' },
      { state: undefined },
    ]) {
      expect(() => parse(changed(overrides)), JSON.stringify(overrides).slice(0, 80)).toThrow();
    }
  });
});

describe('mail.message.rescan_requested.v1', () => {
  const rescan = (overrides: Record<string, unknown> = {}) => ({
    messageId: '9007199254740993',
    receivedAt,
    direction: 'outbound',
    emlS3Key: `org/${organizationId}/eml/2026/11/01/abc.eml`,
    lifecycleRound: 1,
    scanKind: 'rescan',
    requestedAt: '2026-11-02T08:00:00.000Z',
    requestedBy: 'api_key',
    ...overrides,
  });
  const parse = (payload: unknown) =>
    parseEvent(
      envelope(payload, { eventType: EventTypes.MessageRescanRequested }),
      messageRescanRequestedV1,
    );

  it('accepts a rescan by a user or an API key with a round of at least 1', () => {
    expect(parse(rescan()).payload).toMatchObject({ scanKind: 'rescan', lifecycleRound: 1 });
    expect(parse(rescan({ requestedBy: 'user' })).payload.requestedBy).toBe('user');
    // Step 4.2 A13: signature-update rescan jobs of the email-worker have no human principal.
    expect(parse(rescan({ requestedBy: 'system' })).payload.requestedBy).toBe('system');
    expect(parse(rescan({ lifecycleRound: 65_535 })).payload.lifecycleRound).toBe(65_535);
  });

  it('rejects round 0, other scan kinds, foreign keys and unknown requesters', () => {
    for (const overrides of [
      { lifecycleRound: 0 },
      { lifecycleRound: 65_536 },
      { scanKind: 'initial' },
      { scanKind: 'retro' },
      { emlS3Key: 'eml/x.eml' },
      { emlS3Key: 'org/0/eml/x.eml' },
      { requestedBy: 'service' },
      { requestedAt: 'now' },
      { direction: 'both' },
      { messageId: 'abc' },
    ]) {
      expect(() => parse(rescan(overrides)), JSON.stringify(overrides).slice(0, 80)).toThrow();
    }
  });
});

describe('mail.message.scanned.v1 (step 4.1 S6)', () => {
  const ok = (overrides: Record<string, unknown>) =>
    messageScannedV1.safeParse(scannedPayload(overrides)).success;
  const failedEngine = (outcome: string, required = true) => [
    { engine: 'rspamd', required, outcome, attempts: 6 },
  ];

  it('has the seven verdicts and the engine outcomes (verdicts + skipped)', () => {
    expect([...SCAN_VERDICT_VALUES]).toEqual([
      'clean',
      'spam',
      'suspicious',
      'malicious',
      'unknown',
      'timeout',
      'error',
    ]);
    expect([...ENGINE_OUTCOME_VALUES]).toEqual([...SCAN_VERDICT_VALUES, 'skipped']);
  });

  it('accepts every definite verdict for a scanned round, initial and rescan', () => {
    for (const verdict of ['clean', 'spam', 'suspicious', 'malicious', 'unknown']) {
      expect(
        ok({
          verdict,
          engines: [{ engine: 'rspamd', required: true, outcome: verdict, attempts: 2 }],
        }),
        verdict,
      ).toBe(true);
    }
    expect(ok({ scanKind: 'rescan', lifecycleRound: 3 })).toBe(true);
    expect(ok({ reasonCodes: [] })).toBe(true);
  });

  it('scanned: no required engine failed and the verdict is not a failure', () => {
    expect(ok({ engines: failedEngine('timeout') })).toBe(false);
    expect(ok({ engines: failedEngine('error') })).toBe(false);
    expect(ok({ verdict: 'timeout' })).toBe(false);
    expect(ok({ verdict: 'error' })).toBe(false);
    // A non-required engine's failure never fails the round.
    expect(
      ok({
        engines: [
          { engine: 'rspamd', required: true, outcome: 'clean', attempts: 1 },
          { engine: 'url', required: false, outcome: 'timeout', attempts: 3 },
        ],
      }),
    ).toBe(true);
  });

  it('scan_failed: at least one required engine ended timeout or error', () => {
    expect(
      ok({ outcome: 'scan_failed', verdict: 'timeout', engines: failedEngine('timeout') }),
    ).toBe(true);
    expect(ok({ outcome: 'scan_failed', verdict: 'error', engines: failedEngine('error') })).toBe(
      true,
    );
    // A malicious finding of another engine stays the verdict of a failed round.
    expect(
      ok({
        outcome: 'scan_failed',
        verdict: 'malicious',
        engines: [
          { engine: 'rspamd', required: true, outcome: 'error', attempts: 6 },
          { engine: 'url', required: false, outcome: 'malicious', attempts: 1 },
        ],
      }),
    ).toBe(true);
    expect(ok({ outcome: 'scan_failed', verdict: 'clean' })).toBe(false);
    expect(
      ok({ outcome: 'scan_failed', verdict: 'timeout', engines: failedEngine('timeout', false) }),
    ).toBe(false);
  });

  it('bounds engines, attempts, rounds and reason codes', () => {
    expect(ok({ engines: [] })).toBe(false);
    expect(
      ok({
        engines: Array.from({ length: 17 }, (_, i) => ({
          engine: `e${i}`,
          required: false,
          outcome: 'skipped',
          attempts: 1,
        })),
      }),
    ).toBe(false);
    expect(
      ok({
        engines: [
          { engine: 'rspamd', required: true, outcome: 'clean', attempts: 1 },
          { engine: 'rspamd', required: false, outcome: 'clean', attempts: 1 },
        ],
      }),
    ).toBe(false);
    expect(
      ok({ engines: [{ engine: 'Rspamd', required: true, outcome: 'clean', attempts: 1 }] }),
    ).toBe(false);
    expect(
      ok({ engines: [{ engine: 'rspamd', required: true, outcome: 'clean', attempts: 0 }] }),
    ).toBe(false);
    expect(
      ok({ engines: [{ engine: 'rspamd', required: true, outcome: 'ok', attempts: 1 }] }),
    ).toBe(false);
    expect(ok({ lifecycleRound: 65_536 })).toBe(false);
    expect(ok({ scanKind: 'retro' })).toBe(false);
    expect(ok({ reasonCodes: Array.from({ length: 33 }, (_, i) => `rule.r${i}`) })).toBe(false);
    expect(ok({ reasonCodes: ['spam.score', 'spam.score'] })).toBe(false);
    expect(ok({ reasonCodes: ['SPAM'] })).toBe(false);
    expect(ok({ reasonCodes: [`a.${'b'.repeat(63)}`] })).toBe(false);
    expect(ok({ emlS3Key: 'eml/7.eml' })).toBe(false);
  });

  it('carries no content: extra fields such as symbols, options, scores or addresses are refused', () => {
    expect(ok({ symbols: [{ name: 'R_SPF_FAIL', options: ['a@example.com'] }] })).toBe(false);
    expect(ok({ score: 12.5 })).toBe(false);
    expect(ok({ envelopeFrom: 'a@example.com' })).toBe(false);
    expect(
      ok({
        engines: [
          {
            engine: 'rspamd',
            required: true,
            outcome: 'clean',
            attempts: 1,
            options: ['http://bad.example/'],
          },
        ],
      }),
    ).toBe(false);
  });
});

describe('mail.attachment.sandbox_requested.v1 (step 4.2 A2)', () => {
  const partKey = `org/${organizationId}/part/2026/11/01/7/3.att`;
  const payload = (overrides: Record<string, unknown> = {}) => ({
    submissionId: '301',
    messageId: '7',
    receivedAt,
    direction: 'inbound',
    scanId: '11',
    lifecycleRound: 1,
    attachment: {
      partIndex: 3,
      sha256: 'c'.repeat(64),
      sizeBytes: 48_213,
      detectedType: 'zip',
      objectKey: partKey,
    },
    attachmentVerdict: 'suspicious',
    reasonCodes: ['archive.encrypted', 'type.mismatch'],
    requestedAt: '2026-11-01T10:15:31.200Z',
    ...overrides,
  });
  const ok = (value: unknown) => attachmentSandboxRequestedV1.safeParse(value).success;
  const withAttachment = (patch: Record<string, unknown>) =>
    payload({ attachment: { ...payload().attachment, ...patch } });

  it('accepts a suspicious or unknown attachment in an envelope', () => {
    const event = parseEvent(
      envelope(payload(), { eventType: EventTypes.AttachmentSandboxRequested }),
      attachmentSandboxRequestedV1,
    );
    expect(event.payload).toEqual(payload());
    expect([...SANDBOX_ATTACHMENT_VERDICT_VALUES]).toEqual(['suspicious', 'unknown']);
    for (const verdict of SANDBOX_ATTACHMENT_VERDICT_VALUES) {
      expect(ok(payload({ attachmentVerdict: verdict }))).toBe(true);
    }
    expect(ok(payload({ lifecycleRound: 0 }))).toBe(true);
    expect(ok(withAttachment({ partIndex: 0, sizeBytes: 0 }))).toBe(true);
  });

  it('never submits a clean or malicious attachment', () => {
    for (const verdict of ['clean', 'malicious', 'spam', 'error']) {
      expect(ok(payload({ attachmentVerdict: verdict })), verdict).toBe(false);
    }
  });

  it('carries no filename and no content (strict objects)', () => {
    expect(ok(payload({ filename: 'invoice.pdf' }))).toBe(false);
    expect(ok(withAttachment({ filename: 'invoice.pdf' }))).toBe(false);
    expect(ok(withAttachment({ originalFilename: 'x' }))).toBe(false);
    expect(ok(withAttachment({ content: 'TVqQAAMAAAAEAAAA' }))).toBe(false);
    expect(ok(withAttachment({ declaredContentType: 'application/pdf' }))).toBe(false);
    expect(ok(payload({ subject: 'Invoice' }))).toBe(false);
  });

  it('requires an organization-prefixed part key without traversal', () => {
    expect(ok(withAttachment({ objectKey: 'org/42/eml/2026/11/01/7.eml' }))).toBe(false);
    expect(ok(withAttachment({ objectKey: 'part/2026/11/01/7/3.att' }))).toBe(false);
    expect(ok(withAttachment({ objectKey: 'org/042/part/x/3.att' }))).toBe(false);
    expect(ok(withAttachment({ objectKey: 'org/42/part/../../43/part/3.att' }))).toBe(false);
    expect(ok(withAttachment({ objectKey: 'org/42/part/a b/3.att' }))).toBe(false);
    expect(ok(withAttachment({ objectKey: `org/42/part/${'a'.repeat(510)}` }))).toBe(false);
    expect(organizationIdOfKey(partKey)).toBe('42');
    expect(organizationIdOfKey('part/x')).toBeNull();
  });

  it('validates the detected type against the A5 vocabulary and bounds the codes', () => {
    expect(ATTACHMENT_FILE_TYPE_VALUES).toContain('unknown');
    expect(new Set(ATTACHMENT_FILE_TYPE_VALUES).size).toBe(ATTACHMENT_FILE_TYPE_VALUES.length);
    for (const type of ATTACHMENT_FILE_TYPE_VALUES) {
      expect(ok(withAttachment({ detectedType: type })), type).toBe(true);
    }
    expect(ok(withAttachment({ detectedType: 'exe' }))).toBe(false);
    expect(ok(withAttachment({ sha256: 'C'.repeat(64) }))).toBe(false);
    expect(ok(withAttachment({ partIndex: 65_536 }))).toBe(false);
    expect(ok(withAttachment({ sizeBytes: -1 }))).toBe(false);
    expect(ok(payload({ reasonCodes: [] }))).toBe(false);
    expect(ok(payload({ reasonCodes: ['type.mismatch', 'type.mismatch'] }))).toBe(false);
    expect(ok(payload({ reasonCodes: ['TYPE'] }))).toBe(false);
    const codes = Array.from({ length: 17 }, (_, i) => `limit.code_${i}`);
    expect(ok(payload({ reasonCodes: codes.slice(0, 16) }))).toBe(true);
    expect(ok(payload({ reasonCodes: codes }))).toBe(false);
  });

  it('rejects malformed ids, rounds and times', () => {
    expect(ok(payload({ submissionId: '0' }))).toBe(false);
    expect(ok(payload({ scanId: 11 }))).toBe(false);
    expect(ok(payload({ messageId: '01' }))).toBe(false);
    expect(ok(payload({ lifecycleRound: 65_536 }))).toBe(false);
    expect(ok(payload({ requestedAt: 'yesterday' }))).toBe(false);
    expect(ok(payload({ direction: 'sideways' }))).toBe(false);
  });
});
