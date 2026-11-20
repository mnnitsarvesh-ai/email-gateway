import { describe, expect, it } from 'vitest';
import { testUser } from '../../../../test/support/assistant-fixtures';
import { createAssistantHarness } from '../../../../test/support/assistant-harness';
import { changedFields } from './assistant-settings.service';

const ORG = 7001n;
const DAY = 86_400_000;
const body = (overrides: Record<string, unknown> = {}) => ({
  expectedRowVersion: 0,
  enabled: true,
  externalProcessingAcknowledged: true,
  dailyTokenBudget: null,
  retentionDays: 30,
  dataSharing: 'metadata' as const,
  ...overrides,
});

describe('AssistantSettingsService (D13, §4.1)', () => {
  it('answers the platform defaults while no row exists (rowVersion 0)', async () => {
    const h = createAssistantHarness();
    await expect(h.settings.get(h.scope)).resolves.toMatchObject({
      version: 'assistant-settings/1',
      enabled: false,
      externalProcessingAcknowledged: false,
      dailyTokenBudget: null,
      effectiveDailyTokenBudget: 1_000_000,
      retentionDays: 30,
      featureEnabled: false,
      rowVersion: 0,
    });
  });

  it('enables with the acknowledgement and the feature, recording who and when; audited', async () => {
    const h = createAssistantHarness();
    h.world.features.set(ORG, true);
    h.world.users.set(501n, h.user.userPublicId);
    const view = await h.settings.update(
      h.user,
      h.scope,
      body({ dailyTokenBudget: 500 }),
      '198.51.100.7',
    );
    expect(view).toMatchObject({
      enabled: true,
      externalProcessingAcknowledged: true,
      externalProcessingAcknowledgedBy: h.user.userPublicId,
      dailyTokenBudget: 500,
      effectiveDailyTokenBudget: 500,
      rowVersion: 1,
    });
    expect(view.externalProcessingAcknowledgedAt).not.toBeNull();
    expect(h.audit.entries[0]).toMatchObject({
      action: 'assistant.settings_updated',
      resourceType: 'assistant_settings',
      sourceIp: '198.51.100.7',
      metadata: {
        changed: ['enabled', 'externalProcessingAcknowledged', 'dailyTokenBudget', 'retentionDays'],
        enabled: true,
        rowVersion: 1,
      },
    });
    // The acknowledgement keeps its first author and time across later saves.
    const ackAt = view.externalProcessingAcknowledgedAt;
    const other = testUser({ userId: 502n, userPublicId: '0193b000-0000-7000-8000-000000000502' });
    const second = await h.settings.update(
      other,
      h.scope,
      body({ expectedRowVersion: 1, retentionDays: 7 }),
      null,
    );
    expect(second).toMatchObject({
      retentionDays: 7,
      rowVersion: 2,
      externalProcessingAcknowledgedAt: ackAt,
    });
    expect(h.world.settings.get(ORG)!.externalProcessingAckByUserId).toBe(501n);
  });

  it('a lowered retention moves the purge date of existing conversations earlier (D12)', async () => {
    const h = createAssistantHarness();
    h.world.features.set(ORG, true);
    const owner = { scope: h.scope, userId: h.user.userId };
    const lastTurnAt = new Date(Date.now() - 10 * DAY);
    const old = h.world.addConversation(owner, {
      lastTurnAt,
      purgeAfter: new Date(lastTurnAt.getTime() + 30 * DAY),
    });
    const purged = h.world.addConversation(owner, {
      lastTurnAt,
      purgeAfter: new Date(lastTurnAt.getTime() + 30 * DAY),
      contentPurgedAt: new Date(),
    });
    const otherOrg = h.world.addConversation(
      { scope: { ...h.scope, organizationId: 7002n }, userId: 9n },
      { lastTurnAt, purgeAfter: new Date(lastTurnAt.getTime() + 30 * DAY) },
    );
    await h.settings.update(h.user, h.scope, body({ retentionDays: 7 }), null);
    expect(old.purgeAfter).toEqual(new Date(lastTurnAt.getTime() + 7 * DAY));
    expect(purged.purgeAfter).toEqual(new Date(lastTurnAt.getTime() + 30 * DAY));
    expect(otherOrg.purgeAfter).toEqual(new Date(lastTurnAt.getTime() + 30 * DAY));
    // Due now: the next retention run purges it.
    expect(await h.retention.purgeContent(new Date())).toBe(1);
    expect(old.contentPurgedAt).not.toBeNull();

    // A raised retention never moves a purge date later (it applies from the next turn).
    const recent = h.world.addConversation(owner, {
      lastTurnAt,
      purgeAfter: new Date(lastTurnAt.getTime() + 20 * DAY),
    });
    await h.settings.update(
      h.user,
      h.scope,
      body({ expectedRowVersion: 1, retentionDays: 90 }),
      null,
    );
    expect(recent.purgeAfter).toEqual(new Date(lastTurnAt.getTime() + 20 * DAY));
  });

  it('refuses a stale expectedRowVersion (409 with currentRowVersion)', async () => {
    const h = createAssistantHarness();
    h.world.features.set(ORG, true);
    await h.settings.update(h.user, h.scope, body(), null);
    await expect(h.settings.update(h.user, h.scope, body(), null)).rejects.toMatchObject({
      code: 'assistant_settings_conflict',
      details: { currentRowVersion: 1 },
    });
  });

  it('validates: enabling needs the acknowledgement (400), the feature (403), budget ≤ max (400)', async () => {
    const h = createAssistantHarness({ ASSISTANT_TENANT_DAILY_TOKENS_MAX: '2000000' });
    await expect(
      h.settings.update(h.user, h.scope, body({ externalProcessingAcknowledged: false }), null),
    ).rejects.toMatchObject({
      response: { message: [expect.stringContaining('externalProcessingAcknowledged')] },
    });
    await expect(h.settings.update(h.user, h.scope, body(), null)).rejects.toMatchObject({
      code: 'assistant_not_enabled',
    });
    h.world.features.set(ORG, true);
    await expect(
      h.settings.update(h.user, h.scope, body({ dailyTokenBudget: 2_000_001 }), null),
    ).rejects.toMatchObject({
      response: { message: [expect.stringContaining('dailyTokenBudget')] },
    });
    // Disabling without the feature is allowed (and clears the acknowledgement).
    h.world.features.set(ORG, false);
    await expect(
      h.settings.update(
        h.user,
        h.scope,
        body({ enabled: false, externalProcessingAcknowledged: false }),
        null,
      ),
    ).resolves.toMatchObject({ enabled: false, externalProcessingAcknowledged: false });
    expect(h.audit.entries).toHaveLength(1);
  });

  it('lists only the changed field names', () => {
    expect(
      changedFields(null, {
        enabled: false,
        externalProcessingAckAt: null,
        externalProcessingAckByUserId: null,
        dailyTokenBudget: null,
        retentionDays: 30,
        updatedByUserId: 1n,
      }),
    ).toEqual(['retentionDays']);
  });
});
