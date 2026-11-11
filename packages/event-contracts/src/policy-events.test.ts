import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import {
  EventTypes,
  MESSAGE_VERDICT_VALUES,
  messageArchiveRequestedV1,
  POLICY_DECISION_SOURCE_VALUES,
  POLICY_DISPOSITION_VALUES,
  POLICY_FINAL_ACTION_VALUES,
  POLICY_NON_TERMINAL_ACTION_VALUES,
  POLICY_RULE_ID_PATTERN,
  POLICY_RULE_REF_PATTERN,
  POLICY_TRIGGER_VALUES,
  policyDecidedV1,
  policyNotificationRequestedV1,
} from './events';
import { EXAMPLE_EVENT_PAYLOADS } from './examples';
import { EVENT_REGISTRY } from './registry';
import { eventRoutingKey, routeMessage, TOPOLOGY } from './topology';

/**
 * Step 5.2 P15 (docs/plan/steps/16-policy-engine.md): the redefined `mail.policy.decided.v1` and
 * the new `mail.message.archive_requested.v1` and `mail.policy.notification_requested.v1`.
 */
const POLICY_ID = '01890a5d-ac96-774b-bcce-b302099a8090';
const decided = EXAMPLE_EVENT_PAYLOADS['mail.policy.decided.v1'] as Record<string, unknown>;
const archive = EXAMPLE_EVENT_PAYLOADS['mail.message.archive_requested.v1'] as Record<
  string,
  unknown
>;
const notification = EXAMPLE_EVENT_PAYLOADS['mail.policy.notification_requested.v1'] as Record<
  string,
  unknown
>;
const platformDecisive = {
  source: 'platform_default',
  policyId: null,
  versionNo: null,
  ruleId: null,
};
const okDecided = (fields: Record<string, unknown>) =>
  policyDecidedV1.safeParse({ ...decided, ...fields }).success;
const okArchive = (fields: Record<string, unknown>) =>
  messageArchiveRequestedV1.safeParse({ ...archive, ...fields }).success;
const okNotification = (fields: Record<string, unknown>) =>
  policyNotificationRequestedV1.safeParse({ ...notification, ...fields }).success;
const inEnvelope = (type: string, payload: unknown) => ({
  eventId: randomUUID(),
  eventType: type,
  occurredAt: '2026-11-01T10:15:31.900Z',
  correlationId: 'corr-12345678',
  organizationId: '42',
  payload,
});

describe('policy vocabularies (step 5.2)', () => {
  it('mirrors the Prisma enums and the DSL vocabularies', () => {
    expect(POLICY_FINAL_ACTION_VALUES).toEqual([
      'deliver',
      'tag',
      'quarantine',
      'discard',
      'reject',
      'require_approval',
    ]);
    expect(POLICY_DISPOSITION_VALUES).toEqual([
      'allow',
      'require_approval',
      'quarantine',
      'reject',
    ]);
    expect(POLICY_TRIGGER_VALUES).toEqual(['scanned', 'scan_failed', 'parse_failed']);
    expect(POLICY_DECISION_SOURCE_VALUES).toEqual(['tenant_rule', 'platform_default', 'floor']);
    expect(POLICY_NON_TERMINAL_ACTION_VALUES).toEqual([
      'TAG',
      'WARN',
      'URL_REWRITE',
      'ARCHIVE',
      'ALERT',
    ]);
    expect(MESSAGE_VERDICT_VALUES).toEqual([
      'clean',
      'spam',
      'bulk',
      'phishing',
      'malware',
      'bec',
      'dlp_violation',
      'suspicious',
      'unknown',
    ]);
  });

  it('accepts rule ids and rule references of the DSL only', () => {
    for (const id of ['a', 'quarantine-malware-phishing', 'r_1', '0', 'a'.repeat(48)]) {
      expect(POLICY_RULE_ID_PATTERN.test(id), id).toBe(true);
    }
    for (const id of ['', '-a', '_a', 'A', 'a.b', 'a b', 'a'.repeat(49), 'ä']) {
      expect(POLICY_RULE_ID_PATTERN.test(id), id).toBe(false);
    }
    expect(POLICY_RULE_REF_PATTERN.test(`${POLICY_ID}#1/r1`)).toBe(true);
    expect(POLICY_RULE_REF_PATTERN.test(`${POLICY_ID}#4294967295/${'a'.repeat(48)}`)).toBe(true);
    for (const ref of [
      `${POLICY_ID}#0/r1`,
      `${POLICY_ID}#01/r1`,
      `${POLICY_ID}/r1`,
      `${POLICY_ID}#1`,
      `${POLICY_ID.toUpperCase()}#1/r1`,
      `pol-default/1#1/r1`,
      `${POLICY_ID}#1/R1`,
      `${POLICY_ID}#1/r1/extra`,
    ]) {
      expect(POLICY_RULE_REF_PATTERN.test(ref), ref).toBe(false);
    }
  });
});

describe('mail.policy.decided.v1 (step 5.2 P15, redefined in place)', () => {
  const type = 'mail.policy.decided.v1';

  it('is registered on email.policy with aggregate message and parses its example', () => {
    expect(EventTypes.PolicyDecided).toBe(type);
    expect(EVENT_REGISTRY[type]).toMatchObject({
      type,
      version: 1,
      exchange: 'email.policy',
      aggregateType: 'message',
    });
    expect(EVENT_REGISTRY[type].schema).toBe(policyDecidedV1);
    expect(parseEvent(inEnvelope(type, decided), policyDecidedV1).payload).toEqual(decided);
  });

  it('routes to the dormant quarantine queue and the firehose only (topology v9)', () => {
    expect(routeMessage('email.policy', eventRoutingKey('42', type))).toEqual([
      'email.analytics',
      'email.quarantine',
    ]);
  });

  it('has exactly the P15 fields and is strict', () => {
    expect(Object.keys(policyDecidedV1.parse(decided)).sort()).toEqual(
      [
        'messageId',
        'receivedAt',
        'direction',
        'lifecycleRound',
        'scanId',
        'trigger',
        'disposition',
        'finalAction',
        'finalVerdict',
        'riskScore',
        'nonTerminalActions',
        'decisive',
        'overrideApplied',
        'policyGeneration',
        'snapshotSha256',
        'inputSha256',
        'evaluatedAt',
      ].sort(),
    );
    expect(okDecided({ subject: 'Invoice' })).toBe(false);
    expect(okDecided({ envelopeFrom: 'a@example.com' })).toBe(false);
    expect(okDecided({ decisive: { ...(decided.decisive as object), name: 'x' } })).toBe(false);
    // The step 1.1 placeholder fields are gone.
    expect(okDecided({ action: 'quarantine' })).toBe(false);
    expect(okDecided({ archive: true })).toBe(false);
    for (const field of Object.keys(decided)) {
      const { [field]: _omitted, ...rest } = decided;
      expect(policyDecidedV1.safeParse(rest).success, field).toBe(false);
    }
  });

  it('maps every disposition to its final action (P18)', () => {
    const base = { decisive: platformDecisive };
    expect(okDecided({ ...base, disposition: 'allow', finalAction: 'deliver' })).toBe(true);
    expect(okDecided({ ...base, disposition: 'allow', finalAction: 'tag' })).toBe(true);
    expect(okDecided({ ...base, disposition: 'allow', finalAction: 'quarantine' })).toBe(false);
    expect(
      okDecided({ ...base, disposition: 'require_approval', finalAction: 'require_approval' }),
    ).toBe(true);
    expect(okDecided({ ...base, disposition: 'require_approval', finalAction: 'deliver' })).toBe(
      false,
    );
    expect(okDecided({ ...base, disposition: 'quarantine', finalAction: 'quarantine' })).toBe(true);
    // reject: discard inbound, reject outbound/internal.
    expect(
      okDecided({ ...base, direction: 'inbound', disposition: 'reject', finalAction: 'discard' }),
    ).toBe(true);
    expect(
      okDecided({ ...base, direction: 'inbound', disposition: 'reject', finalAction: 'reject' }),
    ).toBe(false);
    for (const direction of ['outbound', 'internal']) {
      expect(okDecided({ ...base, direction, disposition: 'reject', finalAction: 'reject' })).toBe(
        true,
      );
      expect(okDecided({ ...base, direction, disposition: 'reject', finalAction: 'discard' })).toBe(
        false,
      );
    }
    expect(okDecided({ finalAction: 'block' })).toBe(false);
    expect(okDecided({ disposition: 'deliver' })).toBe(false);
  });

  it('ties scanId to the trigger and never allows a failed round (floor, P9.5)', () => {
    expect(okDecided({ trigger: 'scanned', scanId: null })).toBe(false);
    expect(
      okDecided({
        trigger: 'parse_failed',
        scanId: null,
        disposition: 'quarantine',
        finalAction: 'quarantine',
        decisive: { ...platformDecisive, source: 'floor' },
      }),
    ).toBe(true);
    expect(okDecided({ trigger: 'parse_failed', scanId: '11' })).toBe(false);
    expect(
      okDecided({
        trigger: 'scan_failed',
        disposition: 'quarantine',
        finalAction: 'quarantine',
        decisive: { ...platformDecisive, source: 'floor' },
      }),
    ).toBe(true);
    for (const trigger of ['scan_failed', 'parse_failed']) {
      const scanId = trigger === 'parse_failed' ? null : '11';
      expect(
        okDecided({ trigger, scanId, disposition: 'allow', finalAction: 'deliver' }),
        trigger,
      ).toBe(false);
      expect(
        okDecided({
          trigger,
          scanId,
          disposition: 'require_approval',
          finalAction: 'require_approval',
        }),
        trigger,
      ).toBe(false);
      expect(
        okDecided({ trigger, scanId, disposition: 'reject', finalAction: 'discard' }),
        trigger,
      ).toBe(true);
    }
    expect(okDecided({ trigger: 'unknown' })).toBe(false);
  });

  it('names a policy, version and rule exactly for a tenant_rule decision', () => {
    expect(okDecided({ decisive: platformDecisive })).toBe(true);
    expect(okDecided({ decisive: { ...platformDecisive, source: 'floor' } })).toBe(true);
    expect(okDecided({ decisive: { ...platformDecisive, source: 'tenant_rule' } })).toBe(false);
    expect(
      okDecided({
        decisive: { source: 'platform_default', policyId: POLICY_ID, versionNo: 1, ruleId: 'r' },
      }),
    ).toBe(false);
    const tenant = decided.decisive as Record<string, unknown>;
    for (const field of ['policyId', 'versionNo', 'ruleId']) {
      expect(okDecided({ decisive: { ...tenant, [field]: null } }), field).toBe(false);
    }
    expect(okDecided({ decisive: { ...tenant, policyId: '42' } })).toBe(false);
    expect(okDecided({ decisive: { ...tenant, versionNo: 0 } })).toBe(false);
    expect(okDecided({ decisive: { ...tenant, ruleId: 'Bad Rule' } })).toBe(false);
    expect(okDecided({ decisive: { ...tenant, source: 'tenant' } })).toBe(false);
  });

  it('bounds ids, hashes, scores and the non-terminal action list', () => {
    expect(okDecided({ scanId: '011' })).toBe(false);
    expect(okDecided({ messageId: '0' })).toBe(false);
    expect(okDecided({ policyGeneration: '0' })).toBe(true);
    expect(okDecided({ policyGeneration: '-1' })).toBe(false);
    expect(okDecided({ policyGeneration: '01' })).toBe(false);
    expect(okDecided({ policyGeneration: 7 })).toBe(false);
    expect(okDecided({ snapshotSha256: 'D'.repeat(64) })).toBe(false);
    expect(okDecided({ inputSha256: 'e'.repeat(63) })).toBe(false);
    expect(okDecided({ riskScore: null })).toBe(true);
    expect(okDecided({ riskScore: 1000 })).toBe(true);
    expect(okDecided({ riskScore: 1001 })).toBe(false);
    expect(okDecided({ riskScore: 1.5 })).toBe(false);
    expect(okDecided({ finalVerdict: 'unknown' })).toBe(true);
    expect(okDecided({ finalVerdict: 'malicious' })).toBe(false);
    expect(okDecided({ lifecycleRound: 65_536 })).toBe(false);
    expect(okDecided({ nonTerminalActions: [] })).toBe(true);
    expect(okDecided({ nonTerminalActions: [...POLICY_NON_TERMINAL_ACTION_VALUES] })).toBe(true);
    expect(okDecided({ nonTerminalActions: ['TAG', 'TAG'] })).toBe(false);
    expect(okDecided({ nonTerminalActions: ['QUARANTINE'] })).toBe(false);
    expect(okDecided({ nonTerminalActions: ['tag'] })).toBe(false);
  });
});

describe('mail.message.archive_requested.v1 (step 5.2 P15)', () => {
  const type = 'mail.message.archive_requested.v1';

  it('is registered on email.archive with aggregate message and parses its example', () => {
    expect(EventTypes.MessageArchiveRequested).toBe(type);
    expect(EVENT_REGISTRY[type]).toMatchObject({
      type,
      version: 1,
      exchange: 'email.archive',
      aggregateType: 'message',
    });
    expect(EVENT_REGISTRY[type].schema).toBe(messageArchiveRequestedV1);
    expect(parseEvent(inEnvelope(type, archive), messageArchiveRequestedV1).payload).toEqual(
      archive,
    );
  });

  it('reaches the dormant email.archive queue (step 8.1) and the firehose only', () => {
    expect(routeMessage('email.archive', eventRoutingKey('42', type))).toEqual([
      'email.analytics',
      'email.archive',
    ]);
    const archiveQueue = TOPOLOGY.queues.find((q) => q.name === 'email.archive');
    expect(archiveQueue?.role).toBe('dormant');
    expect(archiveQueue?.consumer).toMatchObject({ kind: 'planned', plannedStep: '8.1' });
  });

  it('is strict and carries an organization-prefixed original object key', () => {
    expect(okArchive({ emlS3Key: 'eml/2026/11/01/1.eml' })).toBe(false);
    expect(okArchive({ emlS3Key: 'org/0/eml/1.eml' })).toBe(false);
    expect(okArchive({ ruleRef: null })).toBe(true);
    expect(okArchive({ ruleRef: 'archive-legal' })).toBe(false);
    expect(okArchive({ source: 'tenant_rule' })).toBe(false);
    expect(okArchive({ policyGeneration: '0' })).toBe(true);
    expect(okArchive({ policyGeneration: '' })).toBe(false);
    expect(okArchive({ recipients: ['a@example.com'] })).toBe(false);
    for (const field of Object.keys(archive)) {
      const { [field]: _omitted, ...rest } = archive;
      expect(messageArchiveRequestedV1.safeParse(rest).success, field).toBe(false);
    }
  });
});

describe('mail.policy.notification_requested.v1 (step 5.2 P15, P25)', () => {
  const type = 'mail.policy.notification_requested.v1';

  it('is registered on email.policy with aggregate message and parses its example', () => {
    expect(EventTypes.PolicyNotificationRequested).toBe(type);
    expect(EVENT_REGISTRY[type]).toMatchObject({
      type,
      version: 1,
      exchange: 'email.policy',
      aggregateType: 'message',
    });
    expect(EVENT_REGISTRY[type].schema).toBe(policyNotificationRequestedV1);
    expect(
      parseEvent(inEnvelope(type, notification), policyNotificationRequestedV1).payload,
    ).toEqual(notification);
  });

  it('reaches email.notifications and the firehose only (topology v9)', () => {
    expect(routeMessage('email.policy', eventRoutingKey('42', type))).toEqual([
      'email.analytics',
      'email.notifications',
    ]);
  });

  it('sends a sender non-delivery notice only for a rejected outbound/internal message', () => {
    expect(okNotification({ direction: 'internal' })).toBe(true);
    expect(okNotification({ direction: 'inbound' })).toBe(false);
    expect(okNotification({ disposition: 'quarantine' })).toBe(false);
    // A policy alert may follow any disposition in any direction.
    for (const disposition of POLICY_DISPOSITION_VALUES) {
      for (const direction of ['inbound', 'outbound', 'internal']) {
        expect(
          okNotification({
            kind: 'policy_alert',
            severity: 'critical',
            disposition,
            direction,
            decisive: platformDecisive,
          }),
          `${disposition} ${direction}`,
        ).toBe(true);
      }
    }
    expect(okNotification({ kind: 'digest' })).toBe(false);
    expect(okNotification({ severity: 'high' })).toBe(false);
  });

  it('bounds and de-duplicates rule references and is strict', () => {
    const refs = Array.from({ length: 16 }, (_, i) => `${POLICY_ID}#1/rule-${i}`);
    expect(okNotification({ ruleRefs: refs })).toBe(true);
    expect(okNotification({ ruleRefs: [...refs, `${POLICY_ID}#1/rule-16`] })).toBe(false);
    expect(okNotification({ ruleRefs: [refs[0], refs[0]] })).toBe(false);
    expect(okNotification({ ruleRefs: ['not-a-ref'] })).toBe(false);
    expect(okNotification({ ruleRefs: [] })).toBe(true);
    expect(okNotification({ recipient: 'cfo@example.com' })).toBe(false);
    expect(okNotification({ subject: 'Hello' })).toBe(false);
    expect(okNotification({ decisive: { ...platformDecisive, source: 'tenant_rule' } })).toBe(
      false,
    );
    for (const field of Object.keys(notification)) {
      const { [field]: _omitted, ...rest } = notification;
      expect(policyNotificationRequestedV1.safeParse(rest).success, field).toBe(false);
    }
  });
});
