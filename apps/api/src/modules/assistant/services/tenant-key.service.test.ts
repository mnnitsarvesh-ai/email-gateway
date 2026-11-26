import { randomBytes } from 'node:crypto';
import { Logger } from '@nestjs/common';
import { createProviderFromSpec, type FetchLike } from '@email-gateway/assistant';
import { MetricsService } from '@email-gateway/common';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  immediateAssistantRunner,
  RecordingAssistantAudit,
  testUser,
} from '../../../../test/support/assistant-fixtures';
import { stubbedApiEnv } from '../../../../test/support/api-test-app';
import { scopeFromPrincipal } from '../../../auth-contracts/tenant-scope';
import { loadApiConfig } from '../../../config';
import { keyKidOf, SecretBoxError } from '../../../crypto/secret-box';
import { type AssistantConfig, tenantKeyAad } from '../assistant.constants';
import type { AssistantSettingsRepository } from '../repositories/assistant-settings.repository';
import type {
  ProviderKeyRow,
  ProviderKeySecretRow,
  ProviderKeysRepository,
  ProviderKeyWrite,
} from '../repositories/provider-keys.repository';
import { AssistantMetrics } from './assistant-metrics';
import { commonProviderOptions } from './llm-provider-factory';
import { keyFingerprint, TenantKeyCipher, TenantKeyService } from './tenant-key.service';

/** A synthetic key that matches no secret-scanner pattern (design §9). */
const API_KEY = 'test-tenant-key-0001-not-a-secret';
const OTHER_KEY = 'test-tenant-key-0002-not-a-secret';
const ORG = 7001n;
const principal = testUser();
const scope = scopeFromPrincipal(principal);

afterEach(() => vi.restoreAllMocks());

function config(env: Record<string, string> = {}): AssistantConfig {
  return loadApiConfig(
    stubbedApiEnv({
      ASSISTANT_ENABLED: 'true',
      ASSISTANT_PROVIDER: 'fake',
      ASSISTANT_TENANT_KEYS_ENABLED: 'true',
      ASSISTANT_TENANT_KEY_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
      ASSISTANT_ANTHROPIC_BASE_URL: 'https://anthropic.llm.invalid',
      ASSISTANT_OPENAI_BASE_URL: 'https://openai.llm.invalid/v1',
      ...env,
    }),
  );
}

/** A local fake of the providers' model endpoints: answers `status` and records the calls. */
function fakeFetch(status: () => number | 'network') {
  const calls: Array<{ url: string; headers: Record<string, string> }> = [];
  const impl: FetchLike = (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((value, key) => (headers[key] = value));
    calls.push({ url, headers });
    const answer = status();
    if (answer === 'network') return Promise.reject(new TypeError('fetch failed'));
    return Promise.resolve(
      new Response(JSON.stringify(answer < 300 ? { id: 'model', type: 'model' } : { error: {} }), {
        status: answer,
        headers: { 'content-type': 'application/json' },
      }),
    );
  };
  return { impl, calls };
}

function harness(env: Record<string, string> = {}, status: () => number | 'network' = () => 200) {
  const c = config(env);
  const rows = new Map<bigint, ProviderKeySecretRow>();
  const settings = { rowVersion: 1, useTenantKey: true };
  const keys = {
    find: (org: bigint) => {
      const row = rows.get(org);
      if (!row) return Promise.resolve(null);
      const { keyCiphertext: _c, ...view } = row;
      return Promise.resolve(view);
    },
    findSecret: (org: bigint) => Promise.resolve(rows.get(org) ?? null),
    put: (org: bigint, expected: number | null, data: ProviderKeyWrite) => {
      const current = rows.get(org);
      if ((current?.keyVersion ?? null) !== expected) return Promise.resolve(false);
      rows.set(org, {
        organizationId: org,
        ...data,
        lastErrorCode: null,
        rowVersion: (current?.rowVersion ?? 0) + 1,
        updatedAt: new Date(),
      });
      return Promise.resolve(true);
    },
    setStatus: (org: bigint, version: number, status: string, code: string | null, at: Date) => {
      const row = rows.get(org);
      if (!row || row.keyVersion !== version) return Promise.resolve(false);
      rows.set(org, {
        ...row,
        status: status as ProviderKeyRow['status'],
        lastErrorCode: code,
        lastValidatedAt: at,
      });
      return Promise.resolve(true);
    },
    remove: (org: bigint) => Promise.resolve(rows.delete(org)),
    setBy: () => Promise.resolve({ id: principal.userPublicId, displayName: 'IT User' }),
  } as unknown as ProviderKeysRepository;
  const settingsRepo = {
    get: () => Promise.resolve({ ...settings, organizationId: ORG }),
    bump: (_s: unknown, expected: number, patch: { useTenantKey?: boolean }) => {
      if (expected !== settings.rowVersion) return Promise.resolve(false);
      settings.rowVersion += 1;
      if (patch.useTenantKey !== undefined) settings.useTenantKey = patch.useTenantKey;
      return Promise.resolve(true);
    },
  } as unknown as AssistantSettingsRepository;
  const audit = new RecordingAssistantAudit();
  const registry = new MetricsService({ service: 'api-test' });
  const fetch = fakeFetch(status);
  const built: string[] = [];
  const service = new TenantKeyService(
    c,
    keys,
    settingsRepo,
    immediateAssistantRunner,
    audit,
    new AssistantMetrics(registry),
    (spec) => {
      built.push(`${spec.role}:${spec.provider}:${spec.model}`);
      return createProviderFromSpec(spec, { ...commonProviderOptions(c), fetch: fetch.impl });
    },
  );
  const logs = [
    vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined),
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined),
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined),
  ];
  const logged = () =>
    JSON.stringify(
      logs.flatMap((spy) => spy.mock.calls),
      (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v),
    );
  return { c, service, rows, settings, audit, registry, fetch, built, logged };
}

const body = (extra: Partial<{ provider: 'anthropic' | 'openai'; model: string }> = {}) => ({
  provider: 'anthropic' as const,
  model: 'claude-sonnet-5-5',
  apiKey: API_KEY,
  expectedRowVersion: 1,
  ...extra,
});

/** JSON with bigints (audit entries carry the organization id). */
const json = (value: unknown): string =>
  JSON.stringify(value, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));

const thrown = async (promise: Promise<unknown>) => {
  try {
    await promise;
  } catch (error) {
    return error as Error & {
      code?: string;
      getStatus?: () => number;
      getResponse?: () => unknown;
    };
  }
  throw new Error('expected an error');
};

describe('TenantKeyCipher (step AI-6 D7, I27)', () => {
  it('binds the ciphertext to the organization and the key version, labels the kid', () => {
    const hex = randomBytes(32).toString('hex');
    const cipher = TenantKeyCipher.fromConfig({
      ASSISTANT_TENANT_KEY_ENCRYPTION_KEY: hex,
      ASSISTANT_TENANT_KEY_ENCRYPTION_KEY_PREVIOUS: undefined,
    })!;
    expect(cipher.kid).toBe(keyKidOf(hex));
    const sealed = cipher.encrypt(ORG, 2, API_KEY);
    expect(sealed).not.toContain(API_KEY);
    expect(sealed.split('.')[1]).toBe(cipher.kid);
    expect(cipher.decrypt(ORG, 2, sealed)).toBe(API_KEY);
    expect(() => cipher.decrypt(ORG, 3, sealed)).toThrow(SecretBoxError);
    expect(() => cipher.decrypt(7002n, 2, sealed)).toThrow(SecretBoxError);
    expect(tenantKeyAad(ORG, 2)).toBe('assistant-provider-key:v1:7001:2');
    expect(
      TenantKeyCipher.fromConfig({
        ASSISTANT_TENANT_KEY_ENCRYPTION_KEY: undefined,
        ASSISTANT_TENANT_KEY_ENCRYPTION_KEY_PREVIOUS: undefined,
      }),
    ).toBeNull();
  });

  it('fingerprints with the first 16 hex characters of SHA-256', () => {
    expect(keyFingerprint(API_KEY)).toMatch(/^[0-9a-f]{16}$/);
    expect(keyFingerprint(API_KEY)).not.toBe(keyFingerprint(OTHER_KEY));
  });
});

describe('TenantKeyService.set (step AI-6 D7)', () => {
  it('probes the key, stores it encrypted (version 1, valid) and returns fingerprint and status only', async () => {
    const t = harness();
    const view = await t.service.set(principal, scope, body(), '198.51.100.7');
    expect(view).toMatchObject({
      provider: 'anthropic',
      model: 'claude-sonnet-5-5',
      fingerprint: keyFingerprint(API_KEY),
      status: 'valid',
      setBy: { id: principal.userPublicId, displayName: 'IT User' },
      lastErrorCode: null,
    });
    // The probe: the platform's Anthropic endpoint, the model, the key as a credential header.
    expect(t.fetch.calls).toHaveLength(1);
    expect(t.fetch.calls[0]!.url).toBe('https://anthropic.llm.invalid/v1/models/claude-sonnet-5-5');
    expect(JSON.stringify(t.fetch.calls[0]!.headers)).toContain(API_KEY);
    const row = t.rows.get(ORG)!;
    expect(row).toMatchObject({
      keyVersion: 1,
      status: 'valid',
      keyFingerprint: keyFingerprint(API_KEY),
    });
    expect(row.keyCiphertext).not.toContain(API_KEY);
    expect(row.keyKid).toBe(keyKidOf(t.c.ASSISTANT_TENANT_KEY_ENCRYPTION_KEY!));
    expect(TenantKeyCipher.fromConfig(t.c)!.decrypt(ORG, 1, row.keyCiphertext)).toBe(API_KEY);
    expect(t.settings.rowVersion).toBe(2);
    expect(t.audit.entries).toEqual([
      expect.objectContaining({
        action: 'assistant.provider_key_set',
        resourceType: 'assistant_provider_key',
        metadata: {
          provider: 'anthropic',
          model: 'claude-sonnet-5-5',
          fingerprint: keyFingerprint(API_KEY),
          outcome: 'valid',
        },
      }),
    ]);
    // A replacement is version 2 (a new AAD).
    await t.service.set(
      principal,
      scope,
      { ...body(), apiKey: OTHER_KEY, expectedRowVersion: 2 },
      null,
    );
    expect(t.rows.get(ORG)!.keyVersion).toBe(2);
    // I27: the plaintext never appears in the views, audit or logs.
    for (const text of [json(view), json(t.audit.entries), t.logged()]) {
      expect(text).not.toContain(API_KEY);
      expect(text).not.toContain(OTHER_KEY);
    }
  });

  it('OpenAI: GET {base}/models/{model}', async () => {
    const t = harness({ ASSISTANT_TENANT_KEY_MODELS: 'gpt-5.5' });
    await t.service.set(principal, scope, body({ provider: 'openai', model: 'gpt-5.5' }), null);
    expect(t.fetch.calls[0]!.url).toBe('https://openai.llm.invalid/v1/models/gpt-5.5');
    expect(t.built).toEqual(['tenant:openai:gpt-5.5']);
  });

  it('refuses a rejected key (422) or an unverifiable one (502); nothing is stored or leaked', async () => {
    for (const [status, code, http] of [
      [401, 'assistant_tenant_key_rejected', 422],
      [403, 'assistant_tenant_key_rejected', 422],
      [404, 'assistant_tenant_key_rejected', 422],
      [503, 'assistant_tenant_key_unverified', 502],
      ['network', 'assistant_tenant_key_unverified', 502],
    ] as const) {
      const t = harness({}, () => status);
      const error = await thrown(t.service.set(principal, scope, body(), null));
      expect([error.code, error.getStatus?.()]).toEqual([code, http]);
      expect(t.rows.size).toBe(0);
      expect(t.settings.rowVersion).toBe(1);
      expect(t.audit.entries).toEqual([]);
      for (const text of [
        error.message,
        JSON.stringify(error.getResponse?.() ?? null),
        String(error.stack),
        t.logged(),
      ]) {
        expect(text).not.toContain(API_KEY);
      }
    }
  });

  it('refuses when the platform gate is off (403), an unoffered provider or model (400) and a stale version (409)', async () => {
    const off = harness({ ASSISTANT_TENANT_KEYS_ENABLED: 'false' });
    expect((await thrown(off.service.set(principal, scope, body(), null))).code).toBe(
      'assistant_tenant_keys_disabled',
    );
    const only = harness({ ASSISTANT_TENANT_KEY_PROVIDERS: 'openai' });
    expect((await thrown(only.service.set(principal, scope, body(), null))).getStatus?.()).toBe(
      400,
    );
    expect(
      (
        await thrown(only.service.set(principal, scope, body({ model: 'other-model' }), null))
      ).getStatus?.(),
    ).toBe(400);
    const stale = harness();
    const error = await thrown(
      stale.service.set(principal, scope, { ...body(), expectedRowVersion: 7 }, null),
    );
    expect(error.code).toBe('assistant_settings_conflict');
    expect(stale.fetch.calls).toHaveLength(0);
    for (const t of [off, only, stale]) expect(t.rows.size).toBe(0);
  });
});

describe('TenantKeyService: remove, validate, client, invalidate (step AI-6 D6/D7)', () => {
  it('removes the key and turns useTenantKey off; 404 when none', async () => {
    const t = harness();
    await t.service.set(principal, scope, body(), null);
    await t.service.remove(principal, scope, 2, null);
    expect(t.rows.size).toBe(0);
    expect(t.settings).toMatchObject({ rowVersion: 3, useTenantKey: false });
    expect(t.audit.entries.at(-1)).toMatchObject({
      action: 'assistant.provider_key_removed',
      metadata: { provider: 'anthropic', outcome: 'removed' },
    });
    expect((await thrown(t.service.remove(principal, scope, 3, null))).code).toBe(
      'assistant_tenant_key_not_found',
    );
  });

  it('re-validates the stored key and records the outcome (status only)', async () => {
    let status: number | 'network' = 200;
    const t = harness({}, () => status);
    await t.service.set(principal, scope, body(), null);
    status = 401;
    expect(await t.service.validate(principal, scope, null)).toMatchObject({
      status: 'invalid',
      lastErrorCode: 'provider_auth',
    });
    status = 'network';
    expect(await t.service.validate(principal, scope, null)).toMatchObject({
      status: 'unverified',
      lastErrorCode: 'provider_connection',
    });
    status = 200;
    expect(await t.service.validate(principal, scope, null)).toMatchObject({
      status: 'valid',
      lastErrorCode: null,
    });
    expect(t.audit.entries.map((e) => [e.action, e.metadata?.outcome])).toEqual([
      ['assistant.provider_key_set', 'valid'],
      ['assistant.provider_key_validated', 'rejected'],
      ['assistant.provider_key_validated', 'unverified'],
      ['assistant.provider_key_validated', 'valid'],
    ]);
    expect(await t.registry.metrics()).toContain(
      'assistant_tenant_key_validations_total{outcome="rejected",service="api-test"} 1',
    );
    expect(json(t.audit.entries) + t.logged()).not.toContain(API_KEY);
  });

  it('builds the routing client once per key version, none for a key that is not valid', async () => {
    const t = harness();
    expect(await t.service.client(ORG, scope.organizationId.toString())).toBeNull();
    await t.service.set(principal, scope, body(), null);
    const first = await t.service.client(ORG, '0193b000-0000-7000-8000-000000007001');
    expect(first).toMatchObject({
      providerId: 'anthropic',
      model: 'claude-sonnet-5-5',
      keyVersion: 1,
    });
    expect(await t.service.client(ORG, '0193b000-0000-7000-8000-000000007001')).toBe(first);
    await t.service.invalidate(principal, scope, 1);
    expect(t.rows.get(ORG)).toMatchObject({ status: 'invalid', lastErrorCode: 'provider_auth' });
    expect(t.audit.entries.at(-1)).toMatchObject({
      action: 'assistant.provider_key_invalidated',
      metadata: { outcome: 'invalid', fingerprint: keyFingerprint(API_KEY) },
    });
    expect(await t.service.client(ORG, '0193b000-0000-7000-8000-000000007001')).toBeNull();
    // An invalidation of an older version leaves a replaced key alone.
    await t.service.set(principal, scope, { ...body(), expectedRowVersion: 2 }, null);
    await t.service.invalidate(principal, scope, 1);
    expect(t.rows.get(ORG)).toMatchObject({ keyVersion: 2, status: 'valid' });
    expect(t.logged()).not.toContain(API_KEY);
  });
});
