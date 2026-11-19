import { randomBytes, randomUUID } from 'node:crypto';
import { Logger } from '@nestjs/common';
import { ProviderCredentialCipher } from '@email-gateway/provider-integrations';
import { beforeEach, describe, expect, it } from 'vitest';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { IdempotencyService } from '../../../http/idempotency/idempotency.service';
import { ProviderWorld, sha256 } from '../../../../test/support/provider-fixtures';
import type { ProviderConnectionsService } from './provider-connections.service';
import {
  delegationSteps,
  providerCleanupSteps,
  providerRemovalSteps,
  ProviderGrantsService,
} from './provider-grants.service';

Logger.overrideLogger(false);

const ORG = 42n;
const SCOPE = systemScope(ORG);
const KEY = randomBytes(32).toString('hex');
const SECRET = 'unit-client-secret-value-0123456789';
const M365_APP_ID = '11111111-2222-3333-4444-555555555555';

function user(userId = 10n): UserPrincipal {
  return {
    kind: 'user',
    userId,
    userPublicId: randomUUID(),
    organizationId: ORG,
    organizationPublicId: randomUUID(),
    organizationKind: 'customer',
    sessionId: randomUUID(),
    mfaAuthenticated: true,
    mfaEnrollmentRequired: false,
    permissions: new Set(['integration:read', 'integration:manage']),
  };
}

function bed(env: { appEnv?: string } = {}) {
  const world = new ProviderWorld();
  const audit: Array<{ action: string; metadata: Record<string, unknown> }> = [];
  const base = {
    availableAuthMethods: () =>
      new Set(['platform_app', 'customer_app_secret', 'customer_service_account']),
    record: (
      _tx: unknown,
      _p: unknown,
      _s: unknown,
      _ip: unknown,
      e: { action: string; metadata: Record<string, unknown> },
    ) => {
      audit.push({ action: e.action, metadata: e.metadata });
      return Promise.resolve();
    },
  } as unknown as ProviderConnectionsService;
  const idempotency = {
    execute: async (
      _req: unknown,
      fn: (tx: unknown) => Promise<{ statusCode: number; body: unknown }>,
    ) => ({ ...(await fn({})), replayed: false }),
  } as unknown as IdempotencyService;
  const service = new ProviderGrantsService(
    {
      PROVIDER_CREDENTIAL_ENCRYPTION_KEY: KEY,
      PROVIDER_IMPACT_TOKEN_KEY: randomBytes(32).toString('hex'),
      PROVIDER_M365_LOGIN_URL: 'https://login.microsoftonline.com',
      PROVIDER_GOOGLE_TOKEN_URL: 'https://oauth2.googleapis.com/token',
      PROVIDER_ALLOW_HTTP_ENDPOINTS: false,
      PROVIDER_M365_MAILFLOW_APP_CLIENT_ID: M365_APP_ID,
      PROVIDER_CONSENT_STATE_TTL_SECONDS: 600,
      PORTAL_PUBLIC_URL:
        env.appEnv === 'production' ? 'https://portal.example' : 'http://localhost:3001',
      APP_ENV: env.appEnv ?? 'local',
    } as never,
    world.connectionsDouble(),
    world.grantsDouble(),
    idempotency,
    base,
  );
  return { world, audit, service };
}

const codeOf = async (p: Promise<unknown>): Promise<string> => {
  const err = await p.then(
    () => null,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(Error);
  return (err as { code: string }).code;
};

describe('ProviderGrantsService (step 8.2 D3, D5)', () => {
  let b: ReturnType<typeof bed>;
  beforeEach(() => {
    b = bed();
  });

  it('platform_app: a consent URL with a fresh state; only its SHA-256 is stored, bound to the user', async () => {
    const c = b.world.addConnection(ORG);
    const principal = user();
    const res = await b.service.create(
      principal,
      SCOPE,
      {
        id: c.publicId,
        idempotencyKey: randomUUID(),
        body: { profile: 'm365.mail_flow', authMethod: 'platform_app' },
      },
      null,
    );
    const url = new URL(res.body.consent!.consentUrl!);
    expect(url.origin).toBe('https://login.microsoftonline.com');
    expect(url.searchParams.get('redirect_uri')).toBe(
      'http://localhost:3001/integrations/providers/consent-callback',
    );
    const state = url.searchParams.get('state')!;
    expect(b.world.consentStates).toHaveLength(1);
    expect(b.world.consentStates[0]).toMatchObject({ stateSha256: sha256(state), userId: 10n });
    expect(JSON.stringify(b.audit)).not.toContain(state);

    // Another user of the organization cannot complete it; the owner can, once.
    const complete = (who: UserPrincipal) =>
      b.service.completeConsent(
        who,
        SCOPE,
        {
          idempotencyKey: randomUUID(),
          body: { state, tenant: '22222222-3333-4444-5555-666666666666', adminConsent: true },
        },
        null,
      );
    expect(await codeOf(complete(user(11n)))).toBe('consent_state_invalid');
    const done = await complete(principal);
    expect(done.body.status).toBe('verifying');
    expect(b.world.grants[0]).toMatchObject({
      status: 'verifying',
      claimedTenantId: '22222222-3333-4444-5555-666666666666',
    });
    expect(await codeOf(complete(principal))).toBe('consent_state_invalid');
  });

  it('an expired consent state is refused', async () => {
    const c = b.world.addConnection(ORG);
    const principal = user();
    const res = await b.service.create(
      principal,
      SCOPE,
      {
        id: c.publicId,
        idempotencyKey: randomUUID(),
        body: { profile: 'm365.mail_flow', authMethod: 'platform_app' },
      },
      null,
    );
    const state = new URL(res.body.consent!.consentUrl!).searchParams.get('state')!;
    const later = new Date(Date.now() + 601_000);
    b.service.now = () => later;
    expect(
      await codeOf(
        b.service.completeConsent(
          principal,
          SCOPE,
          {
            idempotencyKey: randomUUID(),
            body: { state, tenant: '22222222-3333-4444-5555-666666666666', adminConsent: true },
          },
          null,
        ),
      ),
    ).toBe('consent_state_invalid');
  });

  it('production consent URLs never fall back to http', async () => {
    const prod = bed({ appEnv: 'production' });
    const c = prod.world.addConnection(ORG);
    const res = await prod.service.create(
      user(),
      SCOPE,
      {
        id: c.publicId,
        idempotencyKey: randomUUID(),
        body: { profile: 'm365.mail_flow', authMethod: 'platform_app' },
      },
      null,
    );
    expect(new URL(res.body.consent!.consentUrl!).searchParams.get('redirect_uri')).toBe(
      'https://portal.example/integrations/providers/consent-callback',
    );
  });

  it('customer_app_secret: encrypted under the row-bound AAD (worker decrypts), never echoed', async () => {
    const c = b.world.addConnection(ORG);
    const grant = b.world.addGrant(c, { authMethod: 'customer_app_secret' });
    const res = await b.service.setCredentials(
      user(),
      SCOPE,
      {
        id: c.publicId,
        profile: 'm365.mail_flow',
        idempotencyKey: randomUUID(),
        body: {
          tenantId: '22222222-3333-4444-5555-666666666666',
          clientId: '33333333-4444-5555-6666-777777777777',
          clientSecret: SECRET,
        },
      },
      null,
    );
    expect(res.body.credentialFingerprint).toMatch(/^[0-9a-f]{12}$/);
    expect(JSON.stringify(res.body)).not.toContain(SECRET);
    expect(JSON.stringify(b.audit)).not.toContain(SECRET);
    const stored = b.world.grants.find((g) => g.id === grant.id)!;
    expect(stored.credentialCiphertext).toMatch(/^v1\./);
    expect(stored.credentialCiphertext).not.toContain(SECRET);
    // Custody: only a holder of the key (the integration-worker) decrypts, for THIS row only.
    const worker = new ProviderCredentialCipher({ key: KEY });
    const parts = {
      organizationId: ORG,
      connectionPublicId: c.publicId,
      grantPublicId: grant.publicId,
      credentialVersion: 1,
    };
    expect(worker.decryptCredential(stored.credentialCiphertext!, parts).credential).toMatchObject({
      clientSecret: SECRET,
    });
    expect(() =>
      worker.decryptCredential(stored.credentialCiphertext!, {
        ...parts,
        grantPublicId: randomUUID(),
      }),
    ).toThrow();
    expect(() =>
      worker.decryptCredential(stored.credentialCiphertext!, { ...parts, credentialVersion: 2 }),
    ).toThrow();
  });

  it('a customer credential on a platform grant is 422 auth_method_not_allowed; schema errors name the field', async () => {
    const c = b.world.addConnection(ORG);
    b.world.addGrant(c, { authMethod: 'platform_app' });
    const put = (body: unknown) =>
      b.service.setCredentials(
        user(),
        SCOPE,
        { id: c.publicId, profile: 'm365.mail_flow', idempotencyKey: randomUUID(), body },
        null,
      );
    expect(
      await codeOf(
        put({
          tenantId: '22222222-3333-4444-5555-666666666666',
          clientId: '33333333-4444-5555-6666-777777777777',
          clientSecret: SECRET,
        }),
      ),
    ).toBe('auth_method_not_allowed');
  });

  it('removal and cleanup steps name the provider-side objects (the gateway cannot revoke, I3)', () => {
    expect(providerRemovalSteps('microsoft_365', 'platform_app')[0]).toMatch(
      /Enterprise applications/,
    );
    expect(providerRemovalSteps('microsoft_365', 'customer_app_secret')[0]).toMatch(
      /App registrations/,
    );
    expect(providerRemovalSteps('google_workspace', 'platform_service_account')[0]).toMatch(
      /Domain-wide delegation/,
    );
    expect(providerCleanupSteps('microsoft_365').join(' ')).toMatch(/Connectors/);
    expect(providerCleanupSteps('google_workspace').join(' ')).toMatch(/Gmail/);
    expect(delegationSteps('123456789012345678901', ['scope-a', 'scope-b'])[2]).toBe(
      'Add new: client ID 123456789012345678901, OAuth scopes scope-a,scope-b.',
    );
  });
});
