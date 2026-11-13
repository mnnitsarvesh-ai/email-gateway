import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { immediateRunner } from '../../../test/support/api-test-app';
import { RecordingAuditService, WebhooksWorld } from '../../../test/support/webhooks-fixtures';
import type { ApiKeyPrincipal, UserPrincipal } from '../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../database/transaction-runner';
import { NotificationsService, toSettingsView } from './notifications.service';

const ORG = 5n;
const user: UserPrincipal = {
  kind: 'user',
  userId: 11n,
  userPublicId: randomUUID(),
  organizationId: ORG,
  organizationPublicId: randomUUID(),
  organizationKind: 'customer',
  sessionId: randomUUID(),
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(),
};
const client = { ip: null, userAgent: null };

function bed() {
  const world = new WebhooksWorld();
  const audit = new RecordingAuditService();
  const service = new NotificationsService(
    world.notificationsDouble(),
    immediateRunner as unknown as TransactionRunner,
    audit,
    world.quarantineDouble(),
  );
  return { world, audit, service };
}

describe('NotificationsService (step 6.2 N3)', () => {
  it('resolves defaults, flags an invalid stored document and never merges it', () => {
    expect(toSettingsView(null)).toMatchObject({
      rowVersion: 0,
      stored: null,
      invalidStored: false,
    });
    const invalid = toSettingsView({
      settings: { alerts: { threatDetected: { throttleMinutes: 1 } } },
      rowVersion: 3,
      updatedAt: new Date(),
    });
    expect(invalid).toMatchObject({
      rowVersion: 3,
      stored: null,
      invalidStored: true,
      settings: { alerts: { threatDetected: { throttleMinutes: 60 } } },
    });
  });

  it('CAS on expectedRowVersion (0 = none yet), canonical document, changed paths audited', async () => {
    const t = bed();
    const scope = scopeFromPrincipal(user);
    const first = await t.service.putSettings(
      user,
      scope,
      { settings: { alerts: { webhookDisabled: { enabled: false } } }, expectedRowVersion: 0 },
      client,
    );
    expect(first).toMatchObject({
      rowVersion: 1,
      settings: { alerts: { webhookDisabled: { enabled: false } } },
    });
    await expect(
      t.service.putSettings(user, scope, { settings: {}, expectedRowVersion: 0 }, client),
    ).rejects.toMatchObject({
      code: 'notification_settings_conflict',
      details: { currentRowVersion: 1 },
    });
    await expect(
      t.service.putSettings(user, scope, { settings: { x: 1 }, expectedRowVersion: 1 }, client),
    ).rejects.toMatchObject({ code: 'notification_settings_invalid' });
    await expect(t.service.putSettings(user, scope, { settings: {} }, client)).rejects.toThrow();
    expect(t.audit.entries.map((e) => e.metadata?.changedPaths)).toEqual([
      ['alerts.webhookDisabled.enabled'],
    ]);
  });

  it('preferences: members only; digest opt-out needs allowOptOut; opt-outs stored in catalogue order', async () => {
    const t = bed();
    const scope = scopeFromPrincipal(user);
    const res = await t.service.putPreferences(
      user,
      scope,
      { optOut: ['webhook_disabled', 'threat_detected'], quarantineDigestOptOut: true },
      client,
    );
    expect(res.optOut).toEqual(['threat_detected', 'webhook_disabled']);
    expect(t.world.digest.get(11n)!.digestOptOut).toBe(true);
    t.world.allowDigestOptOut = false;
    // Already opted out: keeping it is allowed; opting back in too.
    await t.service.putPreferences(
      user,
      scope,
      { optOut: [], quarantineDigestOptOut: true },
      client,
    );
    await t.service.putPreferences(
      user,
      scope,
      { optOut: [], quarantineDigestOptOut: false },
      client,
    );
    await expect(
      t.service.putPreferences(user, scope, { optOut: [], quarantineDigestOptOut: true }, client),
    ).rejects.toMatchObject({
      response: { message: [expect.stringMatching(/^quarantineDigestOptOut:/)] },
    });
    const key: ApiKeyPrincipal = {
      kind: 'api_key',
      apiKeyId: 1n,
      apiKeyPublicId: randomUUID(),
      organizationId: ORG,
      organizationPublicId: randomUUID(),
      permissions: new Set(),
    };
    await expect(t.service.preferences(key, scopeFromPrincipal(key))).rejects.toThrow(/members/);
    const override: UserPrincipal = {
      ...user,
      override: {
        id: randomUUID(),
        reason: 'support',
        targetOrganizationId: 9n,
        targetOrganizationPublicId: randomUUID(),
        expiresAt: new Date(Date.now() + 60_000),
      },
    };
    await expect(t.service.preferences(override, scopeFromPrincipal(override))).rejects.toThrow(
      /members/,
    );
  });
});
