import { createPrivateKey } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { resolveProviderEndpoints, type ProviderEndpoints } from '../endpoints';
import { ProviderRequestError } from '../errors';
import {
  GOOGLE_MAIL_FLOW_PROFILE,
  M365_MAIL_FLOW_PROFILE,
  registerPermissionProfiles,
} from '../profiles';
import { FakeProviderServer } from '../testing/fake-provider-server';
import {
  StaticGrantSource,
  generateTestRsaKey,
  testClientSecret,
  testGuid,
  testServiceAccountKey,
} from '../testing/helpers';
import type { GrantRef } from '../types';
import { platformCredentialsFromEnv, PlatformCredentialConfigError } from './platform-credentials';
import { ProviderTokenService, type GrantTokenRecord } from './token-service';

// A test ATO profile (8.5 registers its own; R1 `o365_management` is allowed only for ato_*).
registerPermissionProfiles([
  {
    key: 'm365.ato_token_test',
    version: 1,
    provider: 'microsoft_365',
    purpose: 'ato_telemetry',
    readOnly: true,
    permissions: ['ActivityFeed.Read'],
    authMethods: ['platform_app', 'customer_app_secret'],
    platformApp: { clientIdKey: 'PROVIDER_M365_ATO_TEST_CLIENT_ID' },
    title: 'ATO token test',
    description: 'Test profile for the management resource.',
  },
]);

const fake = new FakeProviderServer();
let endpoints: ProviderEndpoints;
const tenantId = testGuid();
const clientId = testGuid();
const secret = testClientSecret();
const org = 77n;
const m365Ref: GrantRef = {
  organizationId: org,
  connectionPublicId: testGuid(),
  profile: 'm365.mail_flow',
};
const googleRef: GrantRef = {
  organizationId: org,
  connectionPublicId: testGuid(),
  profile: 'google.mail_flow',
};
let grants: StaticGrantSource;

const m365Record = (overrides: Partial<GrantTokenRecord> = {}): GrantTokenRecord => ({
  grantPublicId: 'grant-m365',
  profile: 'm365.mail_flow',
  authMethod: 'customer_app_secret',
  status: 'active',
  credentialVersion: 1,
  tenantId,
  clientId,
  subjectEmail: null,
  credential: { method: 'customer_app_secret', clientSecret: secret },
  ...overrides,
});

beforeAll(async () => {
  await fake.start();
  endpoints = resolveProviderEndpoints(fake.endpoints());
});
afterAll(() => fake.stop());

beforeEach(() => {
  fake.reset();
  fake.addMicrosoftTenant({ tenantId, displayName: 'T', domains: [] });
  fake.addMicrosoftApp({ clientId, secret });
  fake.consent(tenantId, clientId, [...M365_MAIL_FLOW_PROFILE.permissions]);
  grants = new StaticGrantSource();
  grants.set(m365Ref, m365Record());
});

const signal = () => AbortSignal.timeout(10_000);

describe('ProviderTokenService: Microsoft', () => {
  it('acquires a client-credentials token with the secret for the claimed tenant', async () => {
    const service = new ProviderTokenService({ grants, endpoints });
    const token = await service.getAccessToken(m365Ref, signal());
    expect(token.observedPermissions).toEqual(['Domain.Read.All', 'Organization.Read.All']);
    const log = fake.requests.filter((r) => r.endpoint === 'm365.token');
    expect(log).toHaveLength(1);
    expect(log[0]).toMatchObject({
      tenantId,
      clientId,
      scope: 'https://graph.microsoft.com/.default',
      status: 200,
    });
    expect(JSON.stringify(fake.requests)).not.toContain(secret);
  });

  it('signs a certificate assertion the fake verifies (claims, x5t, lifetime)', async () => {
    const key = generateTestRsaKey();
    const platformClient = testGuid();
    fake.addMicrosoftApp({
      clientId: platformClient,
      certificate: { publicKeyPem: key.publicKeyPem, thumbprint: key.thumbprint },
    });
    fake.consent(tenantId, platformClient, [...M365_MAIL_FLOW_PROFILE.permissions]);
    grants.set(
      m365Ref,
      m365Record({ authMethod: 'platform_app', clientId: null, credential: null }),
    );
    const service = new ProviderTokenService({
      grants,
      endpoints,
      platform: {
        microsoft: new Map([
          [
            'm365.mail_flow',
            {
              clientId: platformClient,
              certificate: {
                privateKey: createPrivateKey(key.privateKeyPem),
                thumbprint: key.thumbprint,
              },
            },
          ],
        ]),
        google: new Map(),
      },
    });
    await service.getAccessToken(m365Ref, signal());
    const claims = fake.assertions.microsoft.at(-1)!;
    expect(claims.iss).toBe(platformClient);
    expect(claims.sub).toBe(platformClient);
    expect(claims.aud).toBe(`${fake.baseUrl}/m365/login/${tenantId}/oauth2/v2.0/token`);
    expect(claims.exp! - claims.iat!).toBeLessThanOrEqual(600);
    expect(typeof claims.jti).toBe('string');
  });

  it('caches per (grant, credential version, resource, subject) until 5 minutes before expiry', async () => {
    let now = new Date('2026-11-18T10:00:00Z');
    const service = new ProviderTokenService({ grants, endpoints, now: () => now });
    const tokenRequests = () => fake.requests.filter((r) => r.endpoint === 'm365.token').length;
    const first = await service.getAccessToken(m365Ref, signal());
    const second = await service.getAccessToken(m365Ref, signal());
    expect(second.token).toBe(first.token);
    expect(tokenRequests()).toBe(1);
    // 54 minutes later: still more than 5 minutes left of the 60-minute token.
    now = new Date(now.getTime() + 54 * 60_000);
    await service.getAccessToken(m365Ref, signal());
    expect(tokenRequests()).toBe(1);
    // 56 minutes after issue: inside the refresh margin.
    now = new Date(now.getTime() + 2 * 60_000);
    await service.getAccessToken(m365Ref, signal());
    expect(tokenRequests()).toBe(2);
    // A new credential version is a new cache key.
    grants.set(m365Ref, m365Record({ credentialVersion: 2 }));
    await service.getAccessToken(m365Ref, signal());
    expect(tokenRequests()).toBe(3);
    service.invalidate('grant-m365');
    expect(service.cacheSize).toBe(0);
  });

  it('bounds the cache (LRU) and shares one request for concurrent callers', async () => {
    const service = new ProviderTokenService({ grants, endpoints, cacheMax: 2 });
    const refs = [1, 2, 3].map((i) => ({ ...m365Ref, connectionPublicId: `conn-${i}` }));
    refs.forEach((ref, i) => grants.set(ref, m365Record({ grantPublicId: `g${i}` })));
    await Promise.all([
      service.getAccessToken(refs[0]!, signal()),
      service.getAccessToken(refs[0]!, signal()),
    ]);
    expect(fake.requests.filter((r) => r.endpoint === 'm365.token')).toHaveLength(1);
    await service.getAccessToken(refs[1]!, signal());
    await service.getAccessToken(refs[0]!, signal()); // refresh recency of g0
    await service.getAccessToken(refs[2]!, signal()); // evicts g1
    expect(service.cacheSize).toBe(2);
    const before = fake.requests.length;
    await service.getAccessToken(refs[0]!, signal());
    expect(fake.requests.length).toBe(before);
    await service.getAccessToken(refs[1]!, signal());
    expect(fake.requests.length).toBe(before + 1);
  });

  it('R1: o365_management only for ato_* profiles, mapped to the management origin', async () => {
    const service = new ProviderTokenService({ grants, endpoints });
    await expect(
      service.getAccessToken(m365Ref, signal(), { resource: 'o365_management' }),
    ).rejects.toMatchObject({
      code: 'credential_unavailable',
    });
    await expect(
      service.getAccessToken(m365Ref, signal(), { resource: 'google' }),
    ).rejects.toMatchObject({
      code: 'credential_unavailable',
    });
    await expect(
      service.getAccessToken(m365Ref, signal(), { subject: 'x@y.test' }),
    ).rejects.toMatchObject({
      code: 'credential_unavailable',
    });
    const atoRef = { ...m365Ref, profile: 'm365.ato_token_test' };
    grants.set(atoRef, m365Record({ grantPublicId: 'grant-ato', profile: 'm365.ato_token_test' }));
    fake.consent(tenantId, clientId, ['ActivityFeed.Read'], 'https://manage.office.com');
    const token = await service.getAccessToken(atoRef, signal(), { resource: 'o365_management' });
    expect(token.observedPermissions).toEqual(['ActivityFeed.Read']);
    expect(fake.requests.at(-1)).toMatchObject({ scope: 'https://manage.office.com/.default' });
  });

  it('refuses grants it may not use', async () => {
    const service = new ProviderTokenService({ grants, endpoints });
    for (const overrides of [
      { status: 'revoked' as const },
      { status: 'pending_consent' as const },
      { tenantId: null },
      { credential: null },
      { authMethod: 'customer_service_account' as const },
      { profile: 'google.mail_flow' },
    ]) {
      grants.set(m365Ref, m365Record(overrides));
      await expect(
        service.getAccessToken(m365Ref, signal()),
        JSON.stringify(overrides),
      ).rejects.toMatchObject({
        code: 'credential_unavailable',
      });
    }
    // platform_app without a configured platform app
    grants.set(m365Ref, m365Record({ authMethod: 'platform_app', credential: null }));
    await expect(service.getAccessToken(m365Ref, signal())).rejects.toBeInstanceOf(
      ProviderRequestError,
    );
  });

  it('reports token requests for metrics without tokens', async () => {
    const onTokenRequest = vi.fn();
    const service = new ProviderTokenService({ grants, endpoints, onTokenRequest });
    await service.getAccessToken(m365Ref, signal());
    await service.getAccessToken(m365Ref, signal());
    expect(onTokenRequest.mock.calls.map((c) => (c[0] as { result: string }).result)).toEqual([
      'ok',
      'cache_hit',
    ]);
  });
});

describe('ProviderTokenService: Google', () => {
  const customerId = 'C0token01';
  const adminEmail = 'admin@token-google.test';
  let sa: ReturnType<typeof testServiceAccountKey>;

  beforeEach(() => {
    sa = testServiceAccountKey('gw@proj.iam.gserviceaccount.test', endpoints.googleToken.href);
    fake.addGoogleServiceAccount(sa.account);
    fake.addGoogleCustomer({
      customerId,
      primaryDomain: 'token-google.test',
      domains: [{ domainName: 'token-google.test', verified: true, isPrimary: true }],
      admins: [adminEmail],
    });
    fake.delegate(customerId, sa.account.clientId, [...GOOGLE_MAIL_FLOW_PROFILE.permissions]);
    grants.set(googleRef, {
      grantPublicId: 'grant-google',
      profile: 'google.mail_flow',
      authMethod: 'customer_service_account',
      status: 'verifying',
      credentialVersion: 1,
      tenantId: null,
      clientId: null,
      subjectEmail: adminEmail,
      credential: { method: 'customer_service_account', key: sa.document },
    });
  });

  it('signs a JWT bearer assertion with sub, scope, aud and ≤ 1 h lifetime', async () => {
    const service = new ProviderTokenService({ grants, endpoints });
    const token = await service.getAccessToken(googleRef, signal());
    expect(token.observedPermissions).toEqual([...GOOGLE_MAIL_FLOW_PROFILE.permissions].sort());
    const claims = fake.assertions.google.at(-1)!;
    expect(claims).toMatchObject({
      iss: 'gw@proj.iam.gserviceaccount.test',
      sub: adminEmail,
      aud: `${fake.baseUrl}/google/token`,
      scope: GOOGLE_MAIL_FLOW_PROFILE.permissions.join(' '),
      kid: sa.key.keyId,
    });
    expect(claims.exp! - claims.iat!).toBe(3600);
  });

  it('R1: subject option impersonates another user, cached separately', async () => {
    const service = new ProviderTokenService({ grants, endpoints });
    await service.getAccessToken(googleRef, signal());
    await service.getAccessToken(googleRef, signal(), { subject: 'User@token-google.test' });
    expect(fake.assertions.google.map((c) => c.sub)).toEqual([
      adminEmail,
      'user@token-google.test',
    ]);
    expect(service.cacheSize).toBe(2);
    await expect(
      service.getAccessToken(googleRef, signal(), { resource: 'graph' }),
    ).rejects.toMatchObject({
      code: 'credential_unavailable',
    });
  });

  it('platform service account from configuration', async () => {
    const platformSa = testServiceAccountKey(
      'platform@proj.iam.gserviceaccount.test',
      endpoints.googleToken.href,
    );
    fake.addGoogleServiceAccount(platformSa.account);
    fake.delegate(customerId, platformSa.account.clientId, [
      ...GOOGLE_MAIL_FLOW_PROFILE.permissions,
    ]);
    const files = new Map([['/run/secrets/sa.json', JSON.stringify(platformSa.document)]]);
    const platform = platformCredentialsFromEnv(
      {
        PROVIDER_GOOGLE_MAILFLOW_SA_KEY_PATH: '/run/secrets/sa.json',
        PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID: platformSa.account.clientId,
      },
      [GOOGLE_MAIL_FLOW_PROFILE],
      {
        readFile: (p) => files.get(p)!,
        googleTokenUrl: endpoints.googleToken.href,
        allowPlatformSecret: false,
      },
    );
    grants.set(googleRef, {
      ...(await grants.loadForToken(googleRef)),
      authMethod: 'platform_service_account',
      credential: null,
    });
    const service = new ProviderTokenService({ grants, endpoints, platform });
    await service.getAccessToken(googleRef, signal());
    expect(fake.assertions.google.at(-1)!.iss).toBe('platform@proj.iam.gserviceaccount.test');
  });
});

describe('platformCredentialsFromEnv', () => {
  const opts = {
    readFile: () => '',
    googleTokenUrl: 'https://oauth2.googleapis.com/token',
    allowPlatformSecret: false,
  };

  it('skips profiles without a client id and refuses a platform secret unless allowed', () => {
    expect(platformCredentialsFromEnv({}, [M365_MAIL_FLOW_PROFILE], opts).microsoft.size).toBe(0);
    const env = {
      PROVIDER_M365_MAILFLOW_APP_CLIENT_ID: testGuid(),
      PROVIDER_M365_MAILFLOW_APP_CLIENT_SECRET: 'fakeSecretValue1',
    };
    expect(() => platformCredentialsFromEnv(env, [M365_MAIL_FLOW_PROFILE], opts)).toThrow(
      PlatformCredentialConfigError,
    );
    const allowed = platformCredentialsFromEnv(env, [M365_MAIL_FLOW_PROFILE], {
      ...opts,
      allowPlatformSecret: true,
    });
    expect(allowed.microsoft.get('m365.mail_flow')?.secret).toBe('fakeSecretValue1');
    try {
      platformCredentialsFromEnv(env, [M365_MAIL_FLOW_PROFILE], opts);
    } catch (error) {
      expect((error as Error).message).toContain('PROVIDER_M365_MAILFLOW_APP_CLIENT_SECRET');
      expect((error as Error).message).not.toContain('fakeSecretValue1');
    }
  });

  it('loads a certificate and validates the thumbprint', () => {
    const key = generateTestRsaKey();
    const env = {
      PROVIDER_M365_MAILFLOW_APP_CLIENT_ID: testGuid(),
      PROVIDER_M365_MAILFLOW_APP_CERT_PATH: '/certs/app.pem',
      PROVIDER_M365_MAILFLOW_APP_CERT_THUMBPRINT: key.thumbprint,
    };
    const loaded = platformCredentialsFromEnv(env, [M365_MAIL_FLOW_PROFILE], {
      ...opts,
      readFile: () => key.privateKeyPem,
    });
    expect(loaded.microsoft.get('m365.mail_flow')?.certificate?.thumbprint).toBe(key.thumbprint);
    expect(() =>
      platformCredentialsFromEnv(
        { ...env, PROVIDER_M365_MAILFLOW_APP_CERT_THUMBPRINT: 'nothex' },
        [M365_MAIL_FLOW_PROFILE],
        {
          ...opts,
          readFile: () => key.privateKeyPem,
        },
      ),
    ).toThrow(/THUMBPRINT/);
    expect(() =>
      platformCredentialsFromEnv(
        { PROVIDER_M365_MAILFLOW_APP_CLIENT_ID: testGuid() },
        [M365_MAIL_FLOW_PROFILE],
        opts,
      ),
    ).toThrow(/neither a certificate nor a client secret/);
  });

  it('refuses an unusable service-account key file', () => {
    expect(() =>
      platformCredentialsFromEnv(
        { PROVIDER_GOOGLE_MAILFLOW_SA_KEY_PATH: '/x.json' },
        [GOOGLE_MAIL_FLOW_PROFILE],
        {
          ...opts,
          readFile: () => '{"type":"service_account"}',
        },
      ),
    ).toThrow(/PROVIDER_GOOGLE_MAILFLOW_SA_KEY_PATH/);
  });
});
