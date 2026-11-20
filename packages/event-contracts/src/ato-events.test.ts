import { describe, expect, it } from 'vitest';
import {
  ATO_ACCOUNT_CHANGE_ACTIONS,
  ATO_NOTIFICATION_KIND_VALUES,
  atoAccountRiskUpdatedV1,
  atoNotificationRequestedV1,
  atoResponseCompletedV1,
  atoResponseRequestedV1,
  atoRestrictionChangedV1,
  authAccountChangedV1,
  authLoginRecordedV1,
  SECURITY_INCIDENT_STATUS_VALUES,
  securityIncidentCreatedV1,
  securityIncidentUpdatedV1,
  smtpAuthRecordedV1,
  smtpSubmissionRecordedV1,
} from './ato-events';
import { EventTypes } from './events';
import { EXAMPLE_ATO_PROVIDER_UNHEALTHY_PAYLOAD, EXAMPLE_EVENT_PAYLOADS } from './examples';
import { EVENT_REGISTRY, type RegisteredEventType } from './registry';

const example = (type: RegisteredEventType) =>
  structuredClone(EXAMPLE_EVENT_PAYLOADS[type]) as Record<string, unknown>;
const ok = (schema: { safeParse: (v: unknown) => { success: boolean } }, value: unknown) =>
  schema.safeParse(value).success;

const ATO_TYPES = [
  EventTypes.AuthLoginRecorded,
  EventTypes.AuthAccountChanged,
  EventTypes.SmtpAuthRecorded,
  EventTypes.SmtpSubmissionRecorded,
  EventTypes.AtoAccountRiskUpdated,
  EventTypes.SecurityIncidentCreated,
  EventTypes.SecurityIncidentUpdated,
  EventTypes.AtoResponseRequested,
  EventTypes.AtoResponseCompleted,
  EventTypes.AtoRestrictionChanged,
  EventTypes.AtoNotificationRequested,
] as const;

describe('step 8.4 ATO and security incident events (D2)', () => {
  it('registers the eleven events with strict schemas that refuse extra fields', () => {
    expect(ATO_TYPES).toHaveLength(11);
    for (const type of ATO_TYPES) {
      const definition = EVENT_REGISTRY[type];
      expect(definition.version, type).toBe(1);
      expect(ok(definition.schema, example(type)), type).toBe(true);
      // No content can be smuggled in: subjects, addresses, passwords, IPs at the top level.
      for (const field of ['subject', 'address', 'password', 'token', 'body']) {
        expect(ok(definition.schema, { ...example(type), [field]: 'x' }), `${type} ${field}`).toBe(
          false,
        );
      }
    }
  });

  it('exports the account-change allow-list of D2 (21 audit actions after the WP3 correction, unique)', () => {
    expect(ATO_ACCOUNT_CHANGE_ACTIONS).toHaveLength(21);
    expect(new Set(ATO_ACCOUNT_CHANGE_ACTIONS).size).toBe(21);
    expect(ATO_ACCOUNT_CHANGE_ACTIONS).not.toContain('quarantine.entry_released');
    expect(ATO_ACCOUNT_CHANGE_ACTIONS).toEqual(
      expect.arrayContaining([
        'auth.refresh_token_reused',
        'auth.mfa_disabled',
        'smtp_connector.secret_rotated',
        'platform.override_started',
      ]),
    );
    for (const action of ATO_ACCOUNT_CHANGE_ACTIONS) expect(action).toMatch(/^[a-z_]+\.[a-z_]+$/);
  });

  describe('auth.login.recorded.v1', () => {
    const base = example('auth.login.recorded.v1');
    it('ties userId to accountKnown and refuses a failure reason on success', () => {
      expect(ok(authLoginRecordedV1, { ...base, accountKnown: false, userId: null })).toBe(true);
      expect(ok(authLoginRecordedV1, { ...base, accountKnown: false })).toBe(false);
      expect(ok(authLoginRecordedV1, { ...base, userId: null })).toBe(false);
      expect(ok(authLoginRecordedV1, { ...base, outcome: 'success' })).toBe(false);
      expect(ok(authLoginRecordedV1, { ...base, outcome: 'success', failureReason: null })).toBe(
        true,
      );
      expect(ok(authLoginRecordedV1, { ...base, channel: 'smtp' })).toBe(false);
      expect(ok(authLoginRecordedV1, { ...base, failureReason: 'Bad Password!' })).toBe(false);
      expect(ok(authLoginRecordedV1, { ...base, email: 'user@example.com' })).toBe(false);
    });
  });

  describe('auth.account.changed.v1', () => {
    const base = example('auth.account.changed.v1');
    it('accepts only allow-listed actions and no actor for system changes', () => {
      expect(ok(authAccountChangedV1, { ...base, action: 'user.login' })).toBe(false);
      expect(ok(authAccountChangedV1, { ...base, actorType: 'system' })).toBe(false);
      expect(ok(authAccountChangedV1, { ...base, actorType: 'system', actorPublicId: null })).toBe(
        true,
      );
      expect(ok(authAccountChangedV1, { ...base, resourcePublicId: 'has space' })).toBe(false);
      expect(ok(authAccountChangedV1, { ...base, resourcePublicId: null })).toBe(true);
    });
  });

  describe('smtp.auth.recorded.v1', () => {
    const base = example('smtp.auth.recorded.v1');
    const entry = (over: Record<string, unknown>) => ({
      ...base,
      entries: [{ ...(base.entries as Record<string, unknown>[])[0], ...over }],
    });
    it('represents a known username by connectorId only and an unknown one by a keyed hash', () => {
      expect(
        ok(
          smtpAuthRecordedV1,
          entry({
            result: 'fail',
            connectorId: null,
            usernameClass: 'unknown_other',
            usernameHash: '0123456789abcdef',
            failureReason: 'bad_credentials',
          }),
        ),
      ).toBe(true);
      expect(ok(smtpAuthRecordedV1, entry({ usernameHash: '0123456789abcdef' }))).toBe(false);
      expect(ok(smtpAuthRecordedV1, entry({ connectorId: null }))).toBe(false);
      expect(ok(smtpAuthRecordedV1, entry({ usernameHash: 'NOT-HEX' }))).toBe(false);
      expect(ok(smtpAuthRecordedV1, entry({ username: 'egc-abc' }))).toBe(false);
      expect(ok(smtpAuthRecordedV1, entry({ password: 'x' }))).toBe(false);
    });
    it('pairs results with failure reasons (blocked = ato_blocked, throttled = ip_throttled)', () => {
      expect(ok(smtpAuthRecordedV1, entry({ failureReason: 'bad_credentials' }))).toBe(false);
      expect(ok(smtpAuthRecordedV1, entry({ result: 'fail', failureReason: null }))).toBe(false);
      expect(
        ok(smtpAuthRecordedV1, entry({ result: 'blocked', failureReason: 'ato_blocked' })),
      ).toBe(true);
      expect(
        ok(smtpAuthRecordedV1, entry({ result: 'blocked', failureReason: 'bad_credentials' })),
      ).toBe(false);
      expect(
        ok(smtpAuthRecordedV1, entry({ result: 'throttled', failureReason: 'ip_throttled' })),
      ).toBe(true);
      expect(ok(smtpAuthRecordedV1, entry({ result: 'fail', failureReason: 'ip_throttled' }))).toBe(
        false,
      );
    });
    it('accepts canonical IP literals only and bounds the batch', () => {
      expect(ok(smtpAuthRecordedV1, entry({ clientIp: '2001:DB8::7' }))).toBe(false);
      expect(ok(smtpAuthRecordedV1, entry({ clientIp: '192.0.2.010' }))).toBe(false);
      expect(ok(smtpAuthRecordedV1, entry({ clientIp: null }))).toBe(true);
      expect(ok(smtpAuthRecordedV1, { ...base, entries: [] })).toBe(false);
      const one = (base.entries as Record<string, unknown>[])[0]!;
      const many = Array.from({ length: 201 }, (_, seq) => ({ ...one, seq: seq % 200 }));
      expect(ok(smtpAuthRecordedV1, { ...base, entries: many })).toBe(false);
      const full = Array.from({ length: 200 }, (_, seq) => ({ ...one, seq }));
      expect(ok(smtpAuthRecordedV1, { ...base, entries: full })).toBe(true);
      expect(ok(smtpAuthRecordedV1, { ...base, entries: [one, one] })).toBe(false);
    });
  });

  describe('smtp.submission.recorded.v1', () => {
    const base = example('smtp.submission.recorded.v1');
    const entry = (over: Record<string, unknown>) => ({
      ...base,
      entries: [{ ...(base.entries as Record<string, unknown>[])[0], ...over }],
    });
    it('carries the lower-cased sender only, no recipient address', () => {
      expect(ok(smtpSubmissionRecordedV1, entry({ senderAddress: 'Finance@acme.example' }))).toBe(
        false,
      );
      expect(ok(smtpSubmissionRecordedV1, entry({ senderAddress: 'no-at-sign' }))).toBe(false);
      expect(ok(smtpSubmissionRecordedV1, entry({ recipients: ['a@b.example'] }))).toBe(false);
      expect(ok(smtpSubmissionRecordedV1, entry({ recipientCount: 10_001 }))).toBe(false);
      expect(ok(smtpSubmissionRecordedV1, entry({ queueId: 'bad id' }))).toBe(false);
      expect(ok(smtpSubmissionRecordedV1, entry({ connectorId: null }))).toBe(false);
      expect(ok(smtpSubmissionRecordedV1, entry({ context: 'inbound' }))).toBe(false);
    });
  });

  describe('ato.account.risk.updated.v1', () => {
    const base = example('ato.account.risk.updated.v1');
    it('is published only on a level change, with bounded scores', () => {
      expect(ok(atoAccountRiskUpdatedV1, { ...base, previousLevel: 'high' })).toBe(false);
      expect(ok(atoAccountRiskUpdatedV1, { ...base, score: 101 })).toBe(false);
      expect(ok(atoAccountRiskUpdatedV1, { ...base, kind: 'api_key' })).toBe(false);
      expect(ok(atoAccountRiskUpdatedV1, { ...base, trigger: 'decay' })).toBe(true);
    });
  });

  describe('security incident events (D24)', () => {
    const created = example('security.incident.created.v1');
    const updated = example('security.incident.updated.v1');
    it('opens incidents in status open with ≤ 16 unique dotted reason codes', () => {
      expect(ok(securityIncidentCreatedV1, { ...created, status: 'investigating' })).toBe(false);
      expect(
        ok(securityIncidentCreatedV1, {
          ...created,
          reasonCodes: Array.from({ length: 17 }, (_, i) => `ato.rule.r${i}`),
        }),
      ).toBe(false);
      expect(
        ok(securityIncidentCreatedV1, { ...created, reasonCodes: ['ato.a.b', 'ato.a.b'] }),
      ).toBe(false);
      expect(ok(securityIncidentCreatedV1, { ...created, reasonCodes: ['NotACode'] })).toBe(false);
      expect(ok(securityIncidentCreatedV1, { ...created, category: 'message_threat' })).toBe(false);
      expect(ok(securityIncidentCreatedV1, { ...created, origin: 'manual' })).toBe(true);
    });
    it('lists exactly the changed status and severity', () => {
      expect(ok(securityIncidentUpdatedV1, { ...updated, changedFields: ['assignee'] })).toBe(
        false,
      );
      expect(
        ok(securityIncidentUpdatedV1, {
          ...updated,
          status: 'open',
          changedFields: ['assignee'],
        }),
      ).toBe(true);
      expect(
        ok(securityIncidentUpdatedV1, {
          ...updated,
          severity: 'critical',
          changedFields: ['status', 'assignee'],
        }),
      ).toBe(false);
      expect(
        ok(securityIncidentUpdatedV1, {
          ...updated,
          severity: 'critical',
          changedFields: ['status', 'severity', 'assignee'],
        }),
      ).toBe(true);
      expect(
        ok(securityIncidentUpdatedV1, { ...updated, changedFields: ['status', 'status'] }),
      ).toBe(false);
      expect(ok(securityIncidentUpdatedV1, { ...updated, changedFields: [] })).toBe(false);
      expect(SECURITY_INCIDENT_STATUS_VALUES).toEqual([
        'open',
        'investigating',
        'confirmed',
        'false_positive',
        'mitigated',
        'resolved',
      ]);
    });
  });

  describe('responses (D13)', () => {
    const requested = example('ato.response.requested.v1');
    const completed = example('ato.response.completed.v1');
    it('requests provider actions only', () => {
      expect(ok(atoResponseRequestedV1, { ...requested, provider: 'gateway' })).toBe(false);
      expect(ok(atoResponseRequestedV1, { ...requested, provider: 'manual' })).toBe(false);
      expect(ok(atoResponseRequestedV1, { ...requested, provider: 'microsoft_365' })).toBe(true);
      expect(ok(atoResponseRequestedV1, { ...requested, phase: 'confirm' })).toBe(false);
    });
    it('never claims provider success without confirmation', () => {
      const provider = { ...completed, provider: 'fake', actionType: 'revoke_sessions' };
      expect(ok(atoResponseCompletedV1, { ...provider, providerStatus: 'unconfirmed' })).toBe(
        false,
      );
      expect(ok(atoResponseCompletedV1, { ...provider, providerStatus: 'confirmed' })).toBe(true);
      expect(
        ok(atoResponseCompletedV1, { ...provider, status: 'unsupported', providerStatus: null }),
      ).toBe(true);
      // Gateway notifications succeed unconfirmed (queued for delivery).
      expect(
        ok(atoResponseCompletedV1, {
          ...completed,
          actionType: 'alert_tenant_admins',
          providerStatus: 'unconfirmed',
          resultCode: 'queued_for_delivery',
        }),
      ).toBe(true);
    });
    it('attests manual actions only and completes rollbacks in the rollback phase', () => {
      expect(
        ok(atoResponseCompletedV1, {
          ...completed,
          provider: 'manual',
          actionType: 'record_manual_action',
          status: 'attested',
          providerStatus: null,
        }),
      ).toBe(true);
      expect(ok(atoResponseCompletedV1, { ...completed, status: 'attested' })).toBe(false);
      expect(ok(atoResponseCompletedV1, { ...completed, status: 'rolled_back' })).toBe(false);
      expect(
        ok(atoResponseCompletedV1, { ...completed, phase: 'rollback', status: 'rolled_back' }),
      ).toBe(true);
      expect(ok(atoResponseCompletedV1, { ...completed, phase: 'rollback' })).toBe(false);
    });
  });

  describe('ato.restriction.changed.v1 (D14)', () => {
    const base = example('ato.restriction.changed.v1');
    it('matches scopes to kinds and names a mailbox by hash only', () => {
      expect(ok(atoRestrictionChangedV1, { ...base, kind: 'auth_block' })).toBe(false);
      expect(
        ok(atoRestrictionChangedV1, {
          ...base,
          kind: 'auth_block',
          scope: 'connector_ip',
          connectorId: '3',
          mailboxSha256: null,
        }),
      ).toBe(true);
      expect(
        ok(atoRestrictionChangedV1, {
          ...base,
          scope: 'connector',
          connectorId: '3',
        }),
      ).toBe(false);
      expect(ok(atoRestrictionChangedV1, { ...base, mailboxSha256: null })).toBe(false);
      expect(ok(atoRestrictionChangedV1, { ...base, mailboxSha256: 'C'.repeat(64) })).toBe(false);
      expect(ok(atoRestrictionChangedV1, { ...base, mailboxAddress: 'a@b.example' })).toBe(false);
    });
  });

  describe('ato.notification.requested.v1: provider_unhealthy (step 8.5 D11)', () => {
    const unhealthy = EXAMPLE_ATO_PROVIDER_UNHEALTHY_PAYLOAD as Record<string, unknown>;
    it('accepts the example and requires the integration ref for that kind only', () => {
      expect(ok(atoNotificationRequestedV1, unhealthy)).toBe(true);
      expect(ATO_NOTIFICATION_KIND_VALUES.at(-1)).toBe('provider_unhealthy');
      expect(ok(atoNotificationRequestedV1, { ...unhealthy, refs: {} })).toBe(false);
      expect(
        ok(atoNotificationRequestedV1, {
          ...unhealthy,
          refs: { integrationPublicId: 'not-a-uuid' },
        }),
      ).toBe(false);
      const base = example('ato.notification.requested.v1');
      expect(
        ok(atoNotificationRequestedV1, {
          ...base,
          refs: {
            ...(base.refs as object),
            integrationPublicId: '01890a5d-ac96-774b-bcce-b302099a80a5',
          },
        }),
      ).toBe(false);
    });
    it('goes to the tenant audience only and carries no address', () => {
      expect(ok(atoNotificationRequestedV1, { ...unhealthy, audience: 'soc' })).toBe(false);
      expect(
        ok(atoNotificationRequestedV1, {
          ...unhealthy,
          refs: {
            integrationPublicId: '01890a5d-ac96-774b-bcce-b302099a80a5',
            address: 'a@b.example',
          },
        }),
      ).toBe(false);
    });
  });

  describe('ato.notification.requested.v1 (D16)', () => {
    const base = example('ato.notification.requested.v1');
    it('requires the refs, severity and digest period of each kind', () => {
      expect(ok(atoNotificationRequestedV1, { ...base, refs: {} })).toBe(false);
      expect(ok(atoNotificationRequestedV1, { ...base, severity: null })).toBe(false);
      expect(ok(atoNotificationRequestedV1, { ...base, digestPeriod: 'daily' })).toBe(false);
      expect(
        ok(atoNotificationRequestedV1, {
          ...base,
          kind: 'digest',
          severity: null,
          refs: {},
          digestPeriod: 'weekly',
          counts: { suppressedBefore: 0, incidents: 4, pendingApprovals: 1 },
        }),
      ).toBe(true);
      expect(
        ok(atoNotificationRequestedV1, {
          ...base,
          kind: 'approval_requested',
          refs: { incidentPublicId: (base.refs as Record<string, string>).incidentPublicId },
        }),
      ).toBe(false);
    });
    it('sends only critical incident alerts to the platform SOC and orders the window', () => {
      expect(ok(atoNotificationRequestedV1, { ...base, audience: 'platform_soc' })).toBe(false);
      expect(
        ok(atoNotificationRequestedV1, { ...base, audience: 'platform_soc', severity: 'critical' }),
      ).toBe(true);
      expect(
        ok(atoNotificationRequestedV1, {
          ...base,
          window: { from: '2026-11-18T08:15:00.000Z', to: '2026-11-18T08:00:00.000Z' },
        }),
      ).toBe(false);
      expect(
        ok(atoNotificationRequestedV1, {
          ...base,
          refs: { ...(base.refs as object), address: 'a@b.example' },
        }),
      ).toBe(false);
    });
  });
});
