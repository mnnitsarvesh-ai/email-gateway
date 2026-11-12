import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import {
  EventTypes,
  QUARANTINE_APPROVAL_DECISION_VALUES,
  QUARANTINE_NOTIFICATION_KIND_VALUES,
  QUARANTINE_NOTIFICATION_MAX_APPROVAL_REQUESTS,
  QUARANTINE_RELEASE_MAX_ENTRIES,
  QUARANTINE_RELEASE_MODE_VALUES,
  QUARANTINE_REQUESTER_TYPE_VALUES,
  quarantineNotificationRequestedV1,
  quarantineReleaseRequestedV1,
} from './events';
import { EXAMPLE_EVENT_PAYLOADS } from './examples';
import { EVENT_REGISTRY } from './registry';
import { eventRoutingKey, queueDefinition, routeMessage } from './topology';

/**
 * Step 5.3 Q27 (docs/plan/steps/17-quarantine.md): `mail.quarantine.release_requested.v1` and
 * `mail.quarantine.notification_requested.v1` — strict, ids and codes only.
 */
const release = EXAMPLE_EVENT_PAYLOADS['mail.quarantine.release_requested.v1'] as Record<
  string,
  unknown
>;
const notification = EXAMPLE_EVENT_PAYLOADS['mail.quarantine.notification_requested.v1'] as Record<
  string,
  unknown
>;
const uuid = (n: number) => `01890a5d-ac96-774b-bcce-${n.toString(16).padStart(12, '0')}`;
const okRelease = (fields: Record<string, unknown>) =>
  quarantineReleaseRequestedV1.safeParse({ ...release, ...fields }).success;
const okNotification = (fields: Record<string, unknown>) =>
  quarantineNotificationRequestedV1.safeParse({ ...notification, ...fields }).success;
const at = '2026-11-02T08:00:01.000Z';

describe('quarantine vocabularies (step 5.3)', () => {
  it('mirrors the Prisma enums and the design lists', () => {
    expect(QUARANTINE_RELEASE_MODE_VALUES).toEqual(['operator', 'self', 'approved']);
    expect(QUARANTINE_REQUESTER_TYPE_VALUES).toEqual(['user', 'api_key', 'system']);
    expect(QUARANTINE_NOTIFICATION_KIND_VALUES).toEqual([
      'user_digest',
      'approval_requested',
      'approval_decided',
      'release_blocked',
      'admin_alert',
      'sender_rejected',
    ]);
    expect(QUARANTINE_APPROVAL_DECISION_VALUES).toEqual([
      'approved',
      'denied',
      'expired',
      'cancelled',
    ]);
    expect(QUARANTINE_RELEASE_MAX_ENTRIES).toBe(1000);
    expect(QUARANTINE_NOTIFICATION_MAX_APPROVAL_REQUESTS).toBe(50);
  });
});

describe('mail.quarantine.release_requested.v1 (Q13, Q27)', () => {
  const type = EventTypes.QuarantineReleaseRequested;

  it('is registered on email.policy (aggregate message) and routes to the executor queue', () => {
    expect(type).toBe('mail.quarantine.release_requested.v1');
    expect(EVENT_REGISTRY[type]).toMatchObject({
      exchange: 'email.policy',
      aggregateType: 'message',
      version: 1,
    });
    expect(eventRoutingKey('42', type)).toBe('org.42.mail.quarantine.release_requested.v1');
    expect(routeMessage('email.policy', eventRoutingKey('42', type))).toEqual([
      'email.analytics',
      'email.quarantine',
    ]);
    expect(queueDefinition('email.quarantine').consumer).toMatchObject({
      ledgerName: 'policy-engine.quarantine',
    });
  });

  it('has exactly the Q27 fields, is strict and parses in an envelope', () => {
    expect(Object.keys(quarantineReleaseRequestedV1.parse(release)).sort()).toEqual(
      [
        'releaseId',
        'messageId',
        'receivedAt',
        'entryIds',
        'mode',
        'approvalRequestId',
        'requestedBy',
        'requestedAt',
      ].sort(),
    );
    expect(okRelease({ subject: 'x' })).toBe(false);
    expect(okRelease({ requestedBy: { type: 'user', id: uuid(1), email: 'a@b.example' } })).toBe(
      false,
    );
    expect(
      parseEvent(
        {
          eventId: randomUUID(),
          eventType: type,
          occurredAt: at,
          correlationId: 'corr-12345678',
          organizationId: '42',
          payload: release,
        },
        quarantineReleaseRequestedV1,
      ).payload,
    ).toEqual(release);
    for (const field of Object.keys(release)) {
      const rest = { ...release };
      delete rest[field];
      expect(quarantineReleaseRequestedV1.safeParse(rest).success, field).toBe(false);
    }
  });

  it('uses uuid public ids and a decimal message id', () => {
    expect(okRelease({ releaseId: 'not-a-uuid' })).toBe(false);
    expect(okRelease({ entryIds: ['42'] })).toBe(false);
    expect(okRelease({ messageId: 42 })).toBe(false);
    expect(okRelease({ messageId: '0042' })).toBe(false);
    expect(okRelease({ messageId: '18446744073709551615' })).toBe(true);
  });

  it('bounds entryIds to 1…1000 unique ids', () => {
    expect(okRelease({ entryIds: [] })).toBe(false);
    expect(okRelease({ entryIds: [uuid(1), uuid(1)] })).toBe(false);
    expect(okRelease({ entryIds: Array.from({ length: 1000 }, (_, i) => uuid(i + 1)) })).toBe(true);
    expect(okRelease({ entryIds: Array.from({ length: 1001 }, (_, i) => uuid(i + 1)) })).toBe(
      false,
    );
  });

  it('ties mode, approval request and requester together', () => {
    // approved ⇔ approvalRequestId
    expect(okRelease({ mode: 'approved', approvalRequestId: null })).toBe(false);
    expect(okRelease({ mode: 'operator', approvalRequestId: uuid(9) })).toBe(false);
    expect(okRelease({ mode: 'operator', approvalRequestId: null })).toBe(true);
    // system has no id; user/api_key have one
    expect(
      okRelease({
        mode: 'operator',
        approvalRequestId: null,
        requestedBy: { type: 'system', id: null },
      }),
    ).toBe(true);
    expect(
      okRelease({
        mode: 'operator',
        approvalRequestId: null,
        requestedBy: { type: 'system', id: uuid(3) },
      }),
    ).toBe(false);
    expect(
      okRelease({
        mode: 'operator',
        approvalRequestId: null,
        requestedBy: { type: 'api_key', id: null },
      }),
    ).toBe(false);
    expect(
      okRelease({
        mode: 'operator',
        approvalRequestId: null,
        requestedBy: { type: 'api_key', id: uuid(3) },
      }),
    ).toBe(true);
    // self-release only by a user
    expect(
      okRelease({
        mode: 'self',
        approvalRequestId: null,
        requestedBy: { type: 'user', id: uuid(3) },
      }),
    ).toBe(true);
    expect(
      okRelease({
        mode: 'self',
        approvalRequestId: null,
        requestedBy: { type: 'api_key', id: uuid(3) },
      }),
    ).toBe(false);
    expect(okRelease({ mode: 'bulk' })).toBe(false);
  });
});

describe('mail.quarantine.notification_requested.v1 (Q20, Q27)', () => {
  const type = EventTypes.QuarantineNotificationRequested;

  it('is registered on email.policy (aggregate quarantine) and routes to email.notifications', () => {
    expect(type).toBe('mail.quarantine.notification_requested.v1');
    expect(EVENT_REGISTRY[type]).toMatchObject({
      exchange: 'email.policy',
      aggregateType: 'quarantine',
      version: 1,
    });
    expect(routeMessage('email.policy', eventRoutingKey('42', type))).toEqual([
      'email.analytics',
      'email.notifications',
    ]);
  });

  it('is strict at every level and has no content field', () => {
    expect(okNotification({ subject: 'x' })).toBe(false);
    expect(okNotification({ refs: { ...(notification.refs as object), address: 'a@b' } })).toBe(
      false,
    );
    expect(
      okNotification({
        window: { from: '2026-11-01T08:00:00.000Z', to: '2026-11-02T08:00:00.000Z', n: 1 },
      }),
    ).toBe(false);
    expect(okNotification({ requestedAt: undefined })).toBe(false);
    expect(okNotification({ kind: 'webhook' })).toBe(false);
  });

  it('requires the refs of each kind', () => {
    const valid: Record<string, Record<string, unknown>> = {
      user_digest: {
        kind: 'user_digest',
        refs: { userId: uuid(1), digestId: uuid(2) },
        window: { from: '2026-11-01T08:00:00.000Z', to: '2026-11-02T08:00:00.000Z' },
        requestedAt: at,
      },
      approval_requested: {
        kind: 'approval_requested',
        refs: { approvalRequestIds: [uuid(3), uuid(4)], entryId: uuid(5) },
        requestedAt: at,
      },
      approval_decided: {
        kind: 'approval_decided',
        refs: { approvalRequestIds: [uuid(3)], userId: uuid(1) },
        decision: 'denied',
        requestedAt: at,
      },
      release_blocked: {
        kind: 'release_blocked',
        refs: { releaseId: uuid(6), userId: uuid(1) },
        requestedAt: at,
      },
      admin_alert: { kind: 'admin_alert', refs: {}, requestedAt: at },
      sender_rejected: {
        kind: 'sender_rejected',
        refs: { entryId: uuid(5), messageId: '9007199254740993', receivedAt: at },
        requestedAt: at,
      },
    };
    expect(Object.keys(valid)).toEqual([...QUARANTINE_NOTIFICATION_KIND_VALUES]);
    for (const [kind, payload] of Object.entries(valid)) {
      expect(quarantineNotificationRequestedV1.safeParse(payload).success, kind).toBe(true);
      for (const ref of Object.keys(payload.refs as object)) {
        const refs = { ...(payload.refs as Record<string, unknown>) };
        delete refs[ref];
        const required =
          {
            user_digest: ['userId', 'digestId'],
            approval_requested: ['approvalRequestIds'],
            approval_decided: ['approvalRequestIds'],
            release_blocked: ['releaseId'],
            admin_alert: [],
            sender_rejected: ['entryId', 'messageId', 'receivedAt'],
          }[kind] ?? [];
        expect(
          quarantineNotificationRequestedV1.safeParse({ ...payload, refs }).success,
          `${kind} without ${ref}`,
        ).toBe(!required.includes(ref));
      }
    }
    // An admin alert may carry a window; other kinds (but the digest) may not.
    expect(
      quarantineNotificationRequestedV1.safeParse({
        ...valid.admin_alert,
        window: { from: '2026-11-01T08:00:00.000Z', to: '2026-11-01T09:00:00.000Z' },
      }).success,
    ).toBe(true);
    expect(
      quarantineNotificationRequestedV1.safeParse({
        ...valid.release_blocked,
        window: { from: '2026-11-01T08:00:00.000Z', to: '2026-11-01T09:00:00.000Z' },
      }).success,
    ).toBe(false);
    // The digest needs its window, ordered.
    expect(
      quarantineNotificationRequestedV1.safeParse({ ...valid.user_digest, window: undefined })
        .success,
    ).toBe(false);
    expect(
      quarantineNotificationRequestedV1.safeParse({
        ...valid.user_digest,
        window: { from: '2026-11-02T08:00:00.000Z', to: '2026-11-02T08:00:00.000Z' },
      }).success,
    ).toBe(false);
    // decision exactly for approval_decided.
    expect(
      quarantineNotificationRequestedV1.safeParse({
        ...valid.approval_decided,
        decision: undefined,
      }).success,
    ).toBe(false);
    expect(
      quarantineNotificationRequestedV1.safeParse({
        ...valid.approval_requested,
        decision: 'approved',
      }).success,
    ).toBe(false);
    // messageId and receivedAt go together.
    expect(
      quarantineNotificationRequestedV1.safeParse({
        ...valid.admin_alert,
        refs: { messageId: '1' },
      }).success,
    ).toBe(false);
  });

  it('bounds approval request ids to 1…50 unique uuids', () => {
    const payload = (ids: string[]) => ({
      kind: 'approval_requested',
      refs: { approvalRequestIds: ids },
      requestedAt: at,
    });
    const ok = (ids: string[]) => quarantineNotificationRequestedV1.safeParse(payload(ids)).success;
    expect(ok([])).toBe(false);
    expect(ok(Array.from({ length: 50 }, (_, i) => uuid(i + 1)))).toBe(true);
    expect(ok(Array.from({ length: 51 }, (_, i) => uuid(i + 1)))).toBe(false);
    expect(ok([uuid(1), uuid(1)])).toBe(false);
    expect(ok(['12'])).toBe(false);
  });
});
