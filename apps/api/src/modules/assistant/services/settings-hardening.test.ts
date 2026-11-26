import { describe, expect, it } from 'vitest';
import { immediateAssistantRunner } from '../../../../test/support/assistant-fixtures';
import { createAssistantHarness } from '../../../../test/support/assistant-harness';
import type { AssistantConfig } from '../assistant.constants';
import type { SettingsRow, SettingsWrite } from '../repositories/assistant-settings.repository';
import type {
  ProviderKeyRow,
  ProviderKeysRepository,
} from '../repositories/provider-keys.repository';
import { AssistantSettingsService, changedFields } from './assistant-settings.service';
import type { TenantKeyService } from './tenant-key.service';

/** Step AI-6 settings (D1, D3, D7; contracts §35.6): new fields, validation and the view. */

const ORG = 7001n;
const body = (overrides: Record<string, unknown> = {}) => ({
  expectedRowVersion: 0,
  enabled: true,
  externalProcessingAcknowledged: true,
  dailyTokenBudget: 1000,
  retentionDays: 30,
  ...overrides,
});

const KEY: ProviderKeyRow = {
  organizationId: ORG,
  provider: 'anthropic',
  model: 'claude-sonnet-5-5',
  keyKid: 'k1234abc',
  keyFingerprint: '0123456789abcdef',
  keyVersion: 1,
  status: 'valid',
  lastValidatedAt: new Date('2026-11-26T09:00:00.000Z'),
  lastErrorCode: null,
  setByUserId: 501n,
  setAt: new Date('2026-11-26T09:00:00.000Z'),
  rowVersion: 1,
  updatedAt: new Date('2026-11-26T09:00:00.000Z'),
};

function setup(options: { gate?: boolean; key?: ProviderKeyRow | null } = {}) {
  const h = createAssistantHarness();
  h.world.features.set(ORG, true);
  const c = h.config as AssistantConfig;
  const repo = h.world.settingsDouble();
  const writes: SettingsWrite[] = [];
  const create = repo.create.bind(repo);
  const update = repo.update.bind(repo);
  repo.create = (scope, data, tx) => {
    writes.push(data);
    return create(scope, data, tx);
  };
  repo.update = (scope, expected, data, tx) => {
    writes.push(data);
    return update(scope, expected, data, tx);
  };
  const key = options.key === undefined ? KEY : options.key;
  const keys = { find: () => Promise.resolve(key) } as unknown as ProviderKeysRepository;
  const tenantKeys = {
    enabled: options.gate ?? true,
    offered: () => ({ enabled: options.gate ?? true, providers: ['anthropic'], models: ['m-1'] }),
    view: () =>
      Promise.resolve(
        key
          ? {
              provider: key.provider,
              model: key.model,
              fingerprint: key.keyFingerprint,
              status: key.status,
              setAt: key.setAt.toISOString(),
              setBy: null,
              lastValidatedAt: null,
              lastErrorCode: null,
            }
          : null,
      ),
  } as unknown as TenantKeyService;
  const service = new AssistantSettingsService(
    c,
    repo,
    h.world.featuresDouble(),
    h.limits,
    immediateAssistantRunner,
    h.audit,
    h.conversationsRepo,
    keys,
    tenantKeys,
  );
  return { h, service, writes };
}

const coded = async (promise: Promise<unknown>) => {
  try {
    await promise;
  } catch (error) {
    const e = error as { getStatus(): number; code?: string; details?: unknown };
    return { status: e.getStatus(), code: e.code, details: e.details };
  }
  throw new Error('expected an error');
};

describe('AssistantSettingsService (step AI-6)', () => {
  it('shows the new fields, the offered tenant keys and the read-only effective limits', async () => {
    const { h, service } = setup();
    const view = await service.get(h.scope);
    expect(view).toMatchObject({
      dataSharing: 'metadata',
      userDailyTokenBudget: null,
      useTenantKey: false,
      tenantKeyFallbackToPlatform: false,
      tenantKey: null,
      tenantKeysOffered: { enabled: true, providers: ['anthropic'], models: ['m-1'] },
      effectiveLimits: {
        turnsPerUserPerMinute: 6,
        messageMaxChars: 4000,
        platformDailyCapSet: false,
        tenantDailyTokensMax: 5_000_000,
        retentionDays: { min: 1, max: 365 },
      },
    });
    // Without the tenant-key service (the harness) the platform's lists are shown, disabled.
    expect((await h.settings.get(h.scope)).tenantKeysOffered).toMatchObject({ enabled: false });
    h.world.enable(ORG, {
      dataSharing: 'pseudonymized',
      userDailyTokenBudget: 500,
      useTenantKey: true,
    });
    expect(await service.get(h.scope)).toMatchObject({
      dataSharing: 'pseudonymized',
      userDailyTokenBudget: 500,
      useTenantKey: true,
      tenantKey: { fingerprint: '0123456789abcdef', status: 'valid' },
    });
  });

  it('writes the data-sharing level, the user budget and the switches; audits the changed names', async () => {
    const { h, service, writes } = setup();
    await service.update(
      h.user,
      h.scope,
      body({
        dataSharing: 'pseudonymized',
        userDailyTokenBudget: 1000,
        useTenantKey: true,
        tenantKeyFallbackToPlatform: true,
      }),
      null,
    );
    expect(writes[0]).toMatchObject({
      dataSharing: 'pseudonymized',
      userDailyTokenBudget: 1000,
      useTenantKey: true,
      tenantKeyFallbackToPlatform: true,
    });
    expect(h.audit.entries[0]!.metadata).toMatchObject({
      changed: expect.arrayContaining([
        'dataSharing',
        'userDailyTokenBudget',
        'useTenantKey',
        'tenantKeyFallbackToPlatform',
      ]),
      dataSharing: 'pseudonymized',
      useTenantKey: true,
    });
    expect(JSON.stringify(h.audit.entries[0]!.metadata)).not.toContain('apiKey');
  });

  it('refuses a user budget above the effective tenant budget (400)', async () => {
    const { h, service } = setup();
    expect(
      await coded(service.update(h.user, h.scope, body({ userDailyTokenBudget: 1001 }), null)),
    ).toMatchObject({ status: 400 });
    // null = the platform default (1 000 000) is the bound.
    await expect(
      service.update(
        h.user,
        h.scope,
        body({ dailyTokenBudget: null, userDailyTokenBudget: 1_000_000 }),
        null,
      ),
    ).resolves.toMatchObject({ userDailyTokenBudget: null });
  });

  it('allows useTenantKey only with the platform gate and a valid stored key', async () => {
    const off = setup({ gate: false });
    expect(
      await coded(off.service.update(off.h.user, off.h.scope, body({ useTenantKey: true }), null)),
    ).toMatchObject({
      status: 403,
      code: 'assistant_tenant_keys_disabled',
    });
    const none = setup({ key: null });
    expect(
      await coded(
        none.service.update(none.h.user, none.h.scope, body({ useTenantKey: true }), null),
      ),
    ).toMatchObject({
      status: 404,
      code: 'assistant_tenant_key_not_found',
    });
    const invalid = setup({ key: { ...KEY, status: 'invalid' } });
    expect(
      await coded(
        invalid.service.update(invalid.h.user, invalid.h.scope, body({ useTenantKey: true }), null),
      ),
    ).toMatchObject({
      status: 422,
      code: 'assistant_tenant_key_rejected',
      details: { keyStatus: 'invalid' },
    });
    for (const t of [off, none, invalid]) expect(t.writes).toHaveLength(0);
    // Turning it off needs nothing.
    await expect(
      off.service.update(off.h.user, off.h.scope, body({ useTenantKey: false }), null),
    ).resolves.toBeDefined();
  });

  it('changedFields: absent step AI-6 fields are unchanged', () => {
    const current = {
      enabled: true,
      externalProcessingAckAt: new Date(),
      dailyTokenBudget: null,
      retentionDays: 30,
      dataSharing: 'pseudonymized',
      userDailyTokenBudget: 10,
      useTenantKey: true,
      tenantKeyFallbackToPlatform: false,
    } as unknown as SettingsRow;
    const next: SettingsWrite = {
      enabled: true,
      externalProcessingAckAt: new Date(),
      externalProcessingAckByUserId: 1n,
      dailyTokenBudget: null,
      retentionDays: 30,
      updatedByUserId: 1n,
    };
    expect(changedFields(current, next)).toEqual([]);
    expect(changedFields(current, { ...next, userDailyTokenBudget: null })).toEqual([
      'userDailyTokenBudget',
    ]);
  });
});
