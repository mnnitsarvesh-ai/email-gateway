import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startSimulators, type RunningSimulators } from '@email-gateway/idp-adapters/testing';
import {
  GOOGLE_MAILBOX_REMEDIATION_PROFILE,
  M365_MAILBOX_REMEDIATION_PROFILE,
  ProviderCredentialCipher,
  testing,
  type ProviderCredential,
} from '@email-gateway/provider-integrations';
import { createMailboxAccessTokens, GrantTokenSource } from '../src/runtime/provider-runtime';
import { Fixtures, silent, type TestConnection, type TestOrg } from './support/harness';

/**
 * Credential custody (D4 "Use", ADR-0099): the mailbox-worker decrypts the active
 * `*.mailbox_remediation` grant with `PROVIDER_CREDENTIAL_ENCRYPTION_KEY` through 8.2's
 * `ProviderGrantStore` and obtains tokens through `ProviderTokenService` (Microsoft: client
 * credentials for the bound tenant, resource `graph`; Google: JWT bearer with the mailbox or the
 * delegated administrator as subject), against 8.2's TEST-ONLY fake provider. A key generated for
 * the run encrypts the fixtures; nothing is printed.
 */
const fx = new Fixtures();
const key = randomBytes(32).toString('hex');
const cipher = ProviderCredentialCipher.fromConfig({ PROVIDER_CREDENTIAL_ENCRYPTION_KEY: key });
const fake = new testing.FakeProviderServer();
let sims: RunningSimulators;
let org: TestOrg;

async function seal(conn: TestConnection, credential: ProviderCredential, clientId: string | null) {
  const grant = await fx.prisma.providerConnectionGrant.findUniqueOrThrow({
    where: { id: conn.grantId },
  });
  const sealed = cipher.encryptCredential(credential, {
    organizationId: org.id,
    connectionPublicId: conn.providerConnectionPublicId,
    grantPublicId: grant.publicId,
    credentialVersion: 1,
  });
  await fx.prisma.providerConnectionGrant.update({
    where: { id: conn.grantId },
    data: {
      credentialCiphertext: sealed.ciphertext,
      credentialKeyId: sealed.keyId,
      credentialVersion: 1,
      clientId,
    },
  });
  return grant.publicId;
}

function tokensFor() {
  const endpoints = fake.endpoints();
  const config = fx.config(sims, {
    PROVIDER_CREDENTIAL_ENCRYPTION_KEY: key,
    PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS: '',
    PROVIDER_M365_LOGIN_URL: endpoints.m365LoginUrl,
    PROVIDER_M365_GRAPH_URL: endpoints.m365GraphUrl,
    PROVIDER_GOOGLE_TOKEN_URL: endpoints.googleTokenUrl,
    PROVIDER_GOOGLE_ADMIN_URL: endpoints.googleAdminUrl,
    PROVIDER_ALLOW_HTTP_ENDPOINTS: 'true',
    PROVIDER_M365_MAILBOX_APP_CLIENT_ID: '',
    PROVIDER_GOOGLE_MAILBOX_SA_CLIENT_ID: '',
    PROVIDER_GOOGLE_MAILBOX_SA_KEY_PATH: '',
  });
  return createMailboxAccessTokens(config, {
    prisma: fx.prisma,
    logger: silent,
    now: () => new Date(),
  });
}

beforeAll(async () => {
  await fake.start();
  sims = await startSimulators({ dataset: {} });
  org = await fx.organization('custody');
});

afterAll(async () => {
  await sims?.stop();
  await fake.stop();
  await fx.cleanup();
});

describe('mailbox grant custody (ADR-0099)', () => {
  it('Microsoft: decrypts the customer app secret and gets a Graph token for the bound tenant', async () => {
    const tenantId = testing.testGuid();
    const clientId = testing.testGuid();
    const secret = testing.testClientSecret();
    const domain = `m365-${fx.suffix}.it-apimode.example`;
    await fx.domain(org, domain, 'api');
    fake.addMicrosoftTenant({
      tenantId,
      displayName: 'Custody tenant',
      domains: [{ name: domain, isVerified: true, mxHost: 'example.mail.protection.outlook.com' }],
    });
    fake.addMicrosoftApp({ clientId, secret, homeTenantId: tenantId });
    fake.consent(tenantId, clientId, [...M365_MAILBOX_REMEDIATION_PROFILE.permissions]);
    const conn = await fx.connection(org, 'microsoft_365', { tenantId, domains: [domain] });
    const grantPublicId = await seal(
      conn,
      { method: 'customer_app_secret', clientSecret: secret },
      clientId,
    );
    const tokens = tokensFor();
    const ref = {
      organizationId: org.id,
      connectionPublicId: conn.providerConnectionPublicId,
      profile: M365_MAILBOX_REMEDIATION_PROFILE.key,
    };
    const source = new GrantTokenSource(tokens, ref, grantPublicId, { resource: 'graph' });
    const token = await source.get(new AbortController().signal);
    expect(token.length).toBeGreaterThan(20);
    expect(
      fake.requests.some(
        (r) => r.tenantId === tenantId && r.clientId === clientId && r.status === 200,
      ),
    ).toBe(true);
    // A revoked grant gets no token (classified, never the provider text).
    await fx.prisma.providerConnectionGrant.update({
      where: { id: conn.grantId },
      data: { status: 'revoked' },
    });
    tokens.invalidate(grantPublicId);
    await expect(source.get(new AbortController().signal)).rejects.toMatchObject({
      name: 'ConnectionAccessError',
      code: 'credentials_invalid',
    });
  });

  it('Google: impersonates the mailbox (Gmail) and the delegated administrator (Directory)', async () => {
    const domain = `gws-${fx.suffix}.it-apimode.example`;
    const admin = `admin@${domain}`;
    const customerId = `C0${fx.suffix.replace(/[^0-9a-z]/g, '').slice(0, 6)}x`;
    await fx.domain(org, domain, 'api');
    const sa = testing.testServiceAccountKey(
      `reader@sa-${fx.suffix}.it-apimode.example`,
      fake.endpoints().googleTokenUrl,
    );
    fake.addGoogleCustomer({
      customerId,
      primaryDomain: domain,
      domains: [{ domainName: domain, verified: true, isPrimary: true }],
      admins: [admin],
    });
    fake.addGoogleServiceAccount(sa.account);
    fake.delegate(customerId, sa.account.clientId, [
      ...GOOGLE_MAILBOX_REMEDIATION_PROFILE.permissions,
    ]);
    const conn = await fx.connection(org, 'google_workspace', {
      tenantId: customerId,
      domains: [domain],
      subjectEmail: admin,
    });
    const grantPublicId = await seal(
      conn,
      { method: 'customer_service_account', key: sa.document },
      null,
    );
    const tokens = tokensFor();
    const ref = {
      organizationId: org.id,
      connectionPublicId: conn.providerConnectionPublicId,
      profile: GOOGLE_MAILBOX_REMEDIATION_PROFILE.key,
    };
    const mailbox = `alex@${domain}`;
    await new GrantTokenSource(tokens, ref, grantPublicId, {
      resource: 'google',
      subject: mailbox,
    }).get(new AbortController().signal);
    await new GrantTokenSource(tokens, ref, grantPublicId, {
      resource: 'google',
      subject: admin,
    }).get(new AbortController().signal);
    const subjects = fake.requests
      .filter((r) => r.endpoint === 'google.token' && r.status === 200)
      .map((r) => r.subject);
    expect(subjects).toEqual(expect.arrayContaining([mailbox, admin]));
  });
});
