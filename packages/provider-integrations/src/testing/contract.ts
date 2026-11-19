import assert from 'node:assert/strict';
import { createPrivateKey } from 'node:crypto';
import { resolveProviderEndpoints, type ProviderEndpoints } from '../endpoints';
import { ProviderRequestError, type ProviderErrorCode } from '../errors';
import { GoogleAdminClient } from '../google/admin-client';
import { GoogleDirectory } from '../google/directory';
import { MicrosoftDirectory } from '../microsoft/directory';
import { MicrosoftGraphClient } from '../microsoft/graph-client';
import { GOOGLE_MAIL_FLOW_PROFILE, M365_MAIL_FLOW_PROFILE } from '../profiles/mail-flow';
import { ProviderTokenService } from '../tokens/token-service';
import type { GrantRef } from '../types';
import { fakeEndpointsFor } from './fake-provider-server';
import {
  FakeProviderAdminClient,
  StaticGrantSource,
  generateTestRsaKey,
  testClientSecret,
  testGuid,
  testServiceAccountKey,
} from './helpers';

/** The test-runner functions the suite needs (Vitest's or any compatible runner's). */
export interface ContractTestApi {
  describe: (name: string, fn: () => void) => void;
  it: (name: string, fn: () => Promise<void>, timeout?: number) => void;
  beforeAll: (fn: () => Promise<void>, timeout?: number) => void;
  afterAll: (fn: () => Promise<void>, timeout?: number) => void;
  beforeEach: (fn: () => Promise<void>, timeout?: number) => void;
}

/** A running fake: in-process (`FakeProviderServer`) or the Compose `provider-fake`. */
export interface ContractTarget {
  baseUrl: string;
  adminToken: string;
  close?: () => Promise<void>;
}

async function expectCode(promise: Promise<unknown>, code: ProviderErrorCode): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof ProviderRequestError, 'a classified ProviderRequestError');
    assert.equal(error.code, code);
    return true;
  });
}

/**
 * The provider-client contract (§10.1): the library's token service, Graph and Admin SDK
 * clients and directories against a fake reached only by base URL and admin token. WP2 runs it
 * against the in-process fake; WP4 runs the same suite against the Compose `provider-fake`, so
 * both behave identically for the scripted scenarios. Assertions use `node:assert`; the runner
 * functions are injected so the library has no test-runner dependency.
 */
export function describeProviderClientContract(
  t: ContractTestApi,
  name: string,
  connect: () => Promise<ContractTarget>,
): void {
  t.describe(`provider client contract: ${name}`, () => {
    let target: ContractTarget;
    let admin: FakeProviderAdminClient;
    let endpoints: ProviderEndpoints;
    let grants: StaticGrantSource;
    let tokens: ProviderTokenService;
    let graph: MicrosoftGraphClient;
    let microsoft: MicrosoftDirectory;
    let google: GoogleDirectory;

    const org = 9_000_001n;
    const tenantId = testGuid();
    const clientId = testGuid();
    let secret: string;
    const customerId = 'C0fake01x';
    const adminEmail = 'reader@contract-google.test';

    const m365Ref: GrantRef = {
      organizationId: org,
      connectionPublicId: testGuid(),
      profile: M365_MAIL_FLOW_PROFILE.key,
    };
    const googleRef: GrantRef = {
      organizationId: org,
      connectionPublicId: testGuid(),
      profile: GOOGLE_MAIL_FLOW_PROFILE.key,
    };

    t.beforeAll(async () => {
      target = await connect();
      admin = new FakeProviderAdminClient(target.baseUrl, target.adminToken);
      endpoints = resolveProviderEndpoints(fakeEndpointsFor(target.baseUrl));
    }, 60_000);

    t.afterAll(async () => {
      await admin?.reset().catch(() => undefined);
      await target?.close?.();
    });

    t.beforeEach(async () => {
      await admin.reset();
      secret = testClientSecret();
      grants = new StaticGrantSource();
      tokens = new ProviderTokenService({ grants, endpoints });
      const retry = { retries: 2, baseDelayMs: 5, maxDelayMs: 50 };
      graph = new MicrosoftGraphClient({
        graphUrl: endpoints.m365Graph,
        tokens,
        http: { allowHttp: true },
        retry,
      });
      microsoft = new MicrosoftDirectory(graph);
      google = new GoogleDirectory(
        new GoogleAdminClient({
          adminUrl: endpoints.googleAdmin,
          tokens,
          http: { allowHttp: true },
          retry,
        }),
      );
      await admin.addMicrosoftTenant({
        tenantId,
        displayName: 'Contract Tenant',
        domains: [
          {
            name: 'verified.contract.test',
            isVerified: true,
            isDefault: true,
            mxHost: 'verified-contract-test.mail.protection.outlook.com',
          },
          { name: 'pending.contract.test', isVerified: false, mxHost: null },
          { name: 'contracttenant.onmicrosoft.com', isVerified: true },
        ],
      });
      await admin.addMicrosoftApp({ clientId, secret, homeTenantId: tenantId });
      await admin.consent(tenantId, clientId, [...M365_MAIL_FLOW_PROFILE.permissions]);
      grants.set(m365Ref, {
        grantPublicId: testGuid(),
        profile: M365_MAIL_FLOW_PROFILE.key,
        authMethod: 'customer_app_secret',
        status: 'verifying',
        credentialVersion: 1,
        tenantId,
        clientId,
        subjectEmail: null,
        credential: { method: 'customer_app_secret', clientSecret: secret },
      });
    });

    const setupGoogle = async (opts: { delegate?: boolean } = {}) => {
      const sa = testServiceAccountKey(
        'gateway@contract-project.iam.gserviceaccount.test',
        endpoints.googleToken.href.replace(/\/+$/, ''),
      );
      await admin.addGoogleServiceAccount(sa.account);
      await admin.addGoogleCustomer({
        customerId,
        primaryDomain: 'primary.google-contract.test',
        organizationName: 'Contract Org',
        domains: [
          {
            domainName: 'primary.google-contract.test',
            verified: true,
            isPrimary: true,
            aliases: [{ name: 'alias.google-contract.test', verified: true }],
          },
          { domainName: 'secondary.google-contract.test', verified: false },
          { domainName: 'contract-google.test', verified: true },
        ],
        admins: [adminEmail],
      });
      if (opts.delegate !== false)
        await admin.delegate(customerId, sa.account.clientId, [
          ...GOOGLE_MAIL_FLOW_PROFILE.permissions,
        ]);
      grants.set(googleRef, {
        grantPublicId: testGuid(),
        profile: GOOGLE_MAIL_FLOW_PROFILE.key,
        authMethod: 'customer_service_account',
        status: 'verifying',
        credentialVersion: 1,
        tenantId: null,
        clientId: null,
        subjectEmail: adminEmail,
        credential: { method: 'customer_service_account', key: sa.document },
      });
      return sa;
    };

    const signal = () => AbortSignal.timeout(20_000);

    t.it(
      'Microsoft: client-secret token carries the consented application permissions',
      async () => {
        const token = await tokens.getAccessToken(m365Ref, signal());
        assert.deepEqual(token.observedPermissions, [...M365_MAIL_FLOW_PROFILE.permissions].sort());
        assert.ok(token.expiresAt.getTime() > Date.now());
      },
    );

    t.it('Microsoft: tenant identity and verified domains', async () => {
      const identity = await microsoft.tenant(m365Ref, signal());
      assert.equal(identity.tenantId, tenantId);
      assert.equal(identity.displayName, 'Contract Tenant');
      assert.deepEqual(identity.verifiedDomains.map((d) => d.name).sort(), [
        'contracttenant.onmicrosoft.com',
        'verified.contract.test',
      ]);
    });

    t.it('Microsoft: domain status mapping and MX target', async () => {
      assert.deepEqual(await microsoft.domain(m365Ref, 'verified.contract.test', signal()), {
        status: 'verified',
        mxHost: 'verified-contract-test.mail.protection.outlook.com',
      });
      assert.deepEqual(await microsoft.domain(m365Ref, 'pending.contract.test', signal()), {
        status: 'unverified',
        mxHost: null,
      });
      assert.deepEqual(await microsoft.domain(m365Ref, 'missing.contract.test', signal()), {
        status: 'absent',
        mxHost: null,
      });
    });

    t.it('Microsoft: paging follows nextLink on the configured origin only', async () => {
      await admin.setPaging({ graphPageSize: 1 });
      const status = await microsoft.domain(m365Ref, 'verified.contract.test', signal());
      assert.equal(status.mxHost, 'verified-contract-test.mail.protection.outlook.com');
      await admin.setPaging({ graphPageSize: 1, foreignNextLink: true });
      await expectCode(
        microsoft.domain(m365Ref, 'verified.contract.test', signal()),
        'bad_response',
      );
    });

    t.it('Microsoft: certificate assertion', async () => {
      const key = generateTestRsaKey();
      const certClient = testGuid();
      await admin.addMicrosoftApp({
        clientId: certClient,
        certificate: { publicKeyPem: key.publicKeyPem, thumbprint: key.thumbprint },
      });
      await admin.consent(tenantId, certClient, [...M365_MAIL_FLOW_PROFILE.permissions]);
      const platformTokens = new ProviderTokenService({
        grants,
        endpoints,
        platform: {
          microsoft: new Map([
            [
              M365_MAIL_FLOW_PROFILE.key,
              {
                clientId: certClient,
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
      const ref = { ...m365Ref, connectionPublicId: testGuid() };
      grants.set(ref, {
        grantPublicId: testGuid(),
        profile: M365_MAIL_FLOW_PROFILE.key,
        authMethod: 'platform_app',
        status: 'verifying',
        credentialVersion: 0,
        tenantId,
        clientId: null,
        subjectEmail: null,
        credential: null,
      });
      const token = await platformTokens.getAccessToken(ref, signal());
      assert.deepEqual(token.observedPermissions, [...M365_MAIL_FLOW_PROFILE.permissions].sort());
    });

    t.it('Microsoft: classified token failures', async () => {
      const wrong = new ProviderTokenService({ grants, endpoints });
      grants.set(m365Ref, {
        ...(await grants.loadForToken(m365Ref)),
        credential: { method: 'customer_app_secret', clientSecret: testClientSecret() },
      });
      await expectCode(wrong.getAccessToken(m365Ref, signal()), 'invalid_client');
      grants.set(m365Ref, {
        ...(await grants.loadForToken(m365Ref)),
        credential: { method: 'customer_app_secret', clientSecret: secret },
        tenantId: testGuid(),
      });
      await expectCode(wrong.getAccessToken(m365Ref, signal()), 'tenant_not_found');
      grants.set(m365Ref, { ...(await grants.loadForToken(m365Ref)), tenantId });
      await admin.revokeConsent(tenantId, clientId);
      await expectCode(wrong.getAccessToken(m365Ref, signal()), 'consent_missing');
    });

    t.it('Microsoft: a missing permission is forbidden at Graph', async () => {
      await admin.consent(tenantId, clientId, ['Organization.Read.All']);
      await expectCode(microsoft.domain(m365Ref, 'verified.contract.test', signal()), 'forbidden');
    });

    t.it(
      'Microsoft: throttling is retried after Retry-After, persistent throttling surfaces',
      async () => {
        await admin.failNext({
          endpoint: 'm365.graph',
          status: 429,
          headers: { 'retry-after': '0' },
          body: { error: { code: 'TooManyRequests' } },
        });
        assert.equal((await microsoft.tenant(m365Ref, signal())).tenantId, tenantId);
        await admin.failNext({
          endpoint: 'm365.graph',
          status: 429,
          headers: { 'retry-after': '0' },
          times: 5,
        });
        await expectCode(microsoft.tenant(m365Ref, signal()), 'throttled');
        await admin.failNext({ endpoint: 'm365.graph', status: 503, times: 5 });
        await expectCode(microsoft.tenant(m365Ref, signal()), 'unavailable');
      },
    );

    t.it('Google: JWT bearer token, customer identity and domains', async () => {
      await setupGoogle();
      const identity = await google.tenant(googleRef, signal());
      assert.equal(identity.tenantId, customerId);
      assert.equal(identity.displayName, 'Contract Org');
      assert.deepEqual(identity.verifiedDomains, [
        { name: 'primary.google-contract.test', isDefault: true },
        { name: 'contract-google.test', isDefault: false },
      ]);
      assert.deepEqual(await google.domain(googleRef, 'primary.google-contract.test', signal()), {
        status: 'verified',
        mxHost: null,
      });
      assert.deepEqual(await google.domain(googleRef, 'secondary.google-contract.test', signal()), {
        status: 'unverified',
        mxHost: null,
      });
      assert.deepEqual(await google.domain(googleRef, 'alias.google-contract.test', signal()), {
        status: 'alias',
        mxHost: null,
      });
      assert.deepEqual(await google.domain(googleRef, 'other.google-contract.test', signal()), {
        status: 'absent',
        mxHost: null,
      });
    });

    t.it('Google: domains are paged with pageToken', async () => {
      await setupGoogle();
      await admin.setPaging({ googlePageSize: 1 });
      assert.equal(
        (await google.domain(googleRef, 'contract-google.test', signal())).status,
        'verified',
      );
    });

    t.it('Google: missing delegation, unknown subject and non-admin subject', async () => {
      await setupGoogle({ delegate: false });
      await expectCode(google.tenant(googleRef, signal()), 'consent_missing');
      await setupGoogle();
      await expectCode(
        tokens.getAccessToken(googleRef, signal(), { subject: 'someone@unrelated.test' }),
        'invalid_client',
      );
      const userRef = { ...googleRef, connectionPublicId: testGuid() };
      const record = await grants.loadForToken(googleRef);
      grants.set(userRef, {
        ...record,
        grantPublicId: testGuid(),
        subjectEmail: 'user@contract-google.test',
      });
      // Any user of a customer domain can be impersonated (8.5 R4) ...
      const userToken = await tokens.getAccessToken(userRef, signal());
      assert.deepEqual(
        userToken.observedPermissions,
        [...GOOGLE_MAIL_FLOW_PROFILE.permissions].sort(),
      );
      // ... but only administrators read the directory.
      await expectCode(google.tenant(userRef, signal()), 'forbidden');
    });
  });
}
