import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  credentialFingerprint,
  M365_MAIL_FLOW_PROFILE,
  MicrosoftDirectory,
  MicrosoftGraphClient,
  ProviderConnectionReader,
  ProviderCredentialCipher,
  ProviderGrantStore,
  ProviderTokenService,
  resolveProviderEndpoints,
  testing,
  type GrantRef,
} from '../src';
import { Fixtures } from './support/fixtures';

/**
 * ProviderGrantStore and ProviderConnectionReader against the real MySQL writer of the 8.2
 * MySQL writer (§10.1), with the token service and Graph client against the
 * in-process fake: writer reads with the decrypted credential, row_version CAS, key-rotation
 * re-encryption, tenant isolation and the 8.5 connection view.
 */
const fx = new Fixtures();
const fake = new testing.FakeProviderServer();
const oldKey = randomBytes(32).toString('hex');
const newKey = randomBytes(32).toString('hex');
const tenantId = testing.testGuid();
const clientId = testing.testGuid();
const secret = testing.testClientSecret();

let orgA: bigint;
let orgB: bigint;
let connection: { id: bigint; publicId: string };
let grant: { id: bigint; publicId: string };
let ref: GrantRef;

beforeAll(async () => {
  await fake.start();
  fake.addMicrosoftTenant({
    tenantId,
    displayName: 'Integration Tenant',
    domains: [
      { name: fx.name('a'), isVerified: true, mxHost: 'it-prov.mail.protection.outlook.com' },
    ],
  });
  fake.addMicrosoftApp({ clientId, secret, homeTenantId: tenantId });
  fake.consent(tenantId, clientId, [...M365_MAIL_FLOW_PROFILE.permissions]);

  orgA = await fx.organization('a');
  orgB = await fx.organization('b');
  const domain = await fx.domain(orgA, fx.name('a'));
  const created = await fx.prisma.providerConnection.create({
    data: {
      organizationId: orgA,
      provider: 'microsoft_365',
      displayName: 'Primary tenant',
      status: 'connecting',
    },
  });
  connection = { id: created.id, publicId: created.publicId };
  await fx.prisma.providerConnectionDomain.create({
    data: {
      organizationId: orgA,
      connectionId: created.id,
      domainId: domain.id,
      providerVerification: 'verified',
    },
  });
  const g = await fx.prisma.providerConnectionGrant.create({
    data: {
      organizationId: orgA,
      connectionId: created.id,
      profile: M365_MAIL_FLOW_PROFILE.key,
      profileVersion: M365_MAIL_FLOW_PROFILE.version,
      authMethod: 'customer_app_secret',
      status: 'verifying',
      clientId,
      claimedTenantId: tenantId,
      requestedPermissions: [...M365_MAIL_FLOW_PROFILE.permissions],
      credentialVersion: 1,
    },
  });
  grant = { id: g.id, publicId: g.publicId };
  // The api's side (D5): encrypt with the row-bound AAD (here under the OLD key, rotated below).
  const sealed = new ProviderCredentialCipher({ key: oldKey }).encryptCredential(
    { method: 'customer_app_secret', clientSecret: secret },
    {
      organizationId: orgA,
      connectionPublicId: created.publicId,
      grantPublicId: g.publicId,
      credentialVersion: 1,
    },
  );
  await fx.prisma.providerConnectionGrant.update({
    where: { id: g.id },
    data: {
      credentialCiphertext: sealed.ciphertext,
      credentialKeyId: sealed.keyId,
      credentialFingerprint: credentialFingerprint({ clientId, credentialVersion: 1 }),
      credentialSetAt: new Date(),
    },
  });
  ref = {
    organizationId: orgA,
    connectionPublicId: created.publicId,
    profile: M365_MAIL_FLOW_PROFILE.key,
  };
}, 60_000);

afterAll(async () => {
  await fake.stop();
  await fx.cleanup();
});

describe('ProviderGrantStore', () => {
  it('reads a grant with its decrypted credential, scoped by organization', async () => {
    const store = new ProviderGrantStore(fx.prisma, new ProviderCredentialCipher({ key: oldKey }));
    const loaded = await store.loadGrant(ref);
    expect(loaded).toMatchObject({
      publicId: grant.publicId,
      status: 'verifying',
      hasCredential: true,
      credential: { method: 'customer_app_secret', clientSecret: secret },
      credentialUnderPreviousKey: false,
      connection: { publicId: connection.publicId, provider: 'microsoft_365' },
    });
    const found = await store.findGrant(ref);
    expect(Object.keys(found!)).not.toContain('credentialCiphertext');
    expect(
      JSON.stringify(found, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)),
    ).not.toContain('v1.k');
    expect(await store.loadGrant({ ...ref, organizationId: orgB })).toBeNull();
    expect(await store.loadGrant({ ...ref, profile: 'google.mail_flow' })).toBeNull();
    // The api holds no decrypting cipher.
    await expect(new ProviderGrantStore(fx.prisma).loadGrant(ref)).rejects.toMatchObject({
      code: 'credential_unavailable',
    });
    // A different key never decrypts.
    await expect(
      new ProviderGrantStore(
        fx.prisma,
        new ProviderCredentialCipher({ key: randomBytes(32).toString('hex') }),
      ).loadGrant(ref),
    ).rejects.toMatchObject({ code: 'credential_unavailable' });
  });

  it('feeds the token service and the Graph directory end to end (in-process fake)', async () => {
    const store = new ProviderGrantStore(fx.prisma, new ProviderCredentialCipher({ key: oldKey }));
    const endpoints = resolveProviderEndpoints(fake.endpoints());
    const tokens = new ProviderTokenService({ grants: store, endpoints });
    const directory = new MicrosoftDirectory(
      new MicrosoftGraphClient({
        graphUrl: endpoints.m365Graph,
        tokens,
        http: { allowHttp: true },
      }),
    );
    const identity = await directory.tenant(ref, AbortSignal.timeout(10_000));
    expect(identity.tenantId).toBe(tenantId);
    expect(await directory.domain(ref, fx.name('a'), AbortSignal.timeout(10_000))).toEqual({
      status: 'verified',
      mxHost: 'it-prov.mail.protection.outlook.com',
    });
  });

  it('updates status with row_version compare-and-set', async () => {
    const store = new ProviderGrantStore(fx.prisma, new ProviderCredentialCipher({ key: oldKey }));
    const current = (await store.findGrant(ref))!;
    const next = await store.updateGrantStatus(current.id, current.rowVersion, {
      status: 'active',
      observedPermissions: ['Domain.Read.All', 'Organization.Read.All'],
      missingPermissions: [],
      excessPermissions: null,
      verifiedAt: new Date(),
      lastErrorCode: null,
      consecutiveFailures: 'increment',
    });
    expect(next).toBe(current.rowVersion + 1);
    // The stale version loses.
    expect(
      await store.updateGrantStatus(current.id, current.rowVersion, { status: 'error' }),
    ).toBeNull();
    const after = (await store.findGrant(ref))!;
    expect(after).toMatchObject({
      status: 'active',
      rowVersion: next,
      consecutiveFailures: 1,
      observedPermissions: ['Domain.Read.All', 'Organization.Read.All'],
    });
    const row = await fx.prisma.providerConnectionGrant.findUniqueOrThrow({
      where: { id: current.id },
    });
    expect(row.excessPermissions).toBeNull();
    expect(await store.updateGrantStatus(current.id, next!, { consecutiveFailures: 'reset' })).toBe(
      next! + 1,
    );

    const conn = await fx.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    const v = await store.updateConnectionStatus(conn.id, conn.rowVersion, {
      status: 'configuring',
      externalTenantId: tenantId,
      externalTenantName: 'Integration Tenant',
      tenantVerifiedAt: new Date(),
      activeTenantKey: `microsoft_365:${tenantId}`,
    });
    expect(v).toBe(conn.rowVersion + 1);
    expect(
      await store.updateConnectionStatus(conn.id, conn.rowVersion, { status: 'active' }),
    ).toBeNull();
  });

  it('re-encrypts under the new key after rotation (idempotent, counts only)', async () => {
    const rotated = new ProviderCredentialCipher({ key: newKey, previousKey: oldKey });
    const store = new ProviderGrantStore(fx.prisma, rotated);
    expect((await store.loadGrant(ref))!.credentialUnderPreviousKey).toBe(true);
    const first = await store.reencryptBatch({ limit: 100 });
    expect(first).toMatchObject({ reencrypted: 1, failed: 0 });
    const second = await store.reencryptBatch({ limit: 100 });
    expect(second.reencrypted).toBe(0);
    const row = await fx.prisma.providerConnectionGrant.findUniqueOrThrow({
      where: { id: grant.id },
    });
    expect(row.credentialKeyId).toBe(rotated.currentKeyId);
    // Only the new key is needed now.
    const fresh = new ProviderGrantStore(fx.prisma, new ProviderCredentialCipher({ key: newKey }));
    expect((await fresh.loadGrant(ref))!.credential).toEqual({
      method: 'customer_app_secret',
      clientSecret: secret,
    });
  });

  it('a ciphertext copied to another grant row does not decrypt', async () => {
    const source = await fx.prisma.providerConnectionGrant.findUniqueOrThrow({
      where: { id: grant.id },
    });
    const other = await fx.prisma.providerConnectionGrant.create({
      data: {
        organizationId: orgA,
        connectionId: connection.id,
        profile: 'm365.copied_test',
        profileVersion: 1,
        authMethod: 'customer_app_secret',
        status: 'verifying',
        requestedPermissions: [],
        credentialVersion: source.credentialVersion,
        credentialCiphertext: source.credentialCiphertext,
        credentialKeyId: source.credentialKeyId,
      },
    });
    try {
      const store = new ProviderGrantStore(
        fx.prisma,
        new ProviderCredentialCipher({ key: newKey }),
      );
      await expect(store.loadGrant({ ...ref, profile: 'm365.copied_test' })).rejects.toMatchObject({
        code: 'credential_unavailable',
      });
      const summary = await store.reencryptBatch({ fromKeyId: source.credentialKeyId! });
      expect(summary.reencrypted).toBe(0);
    } finally {
      await fx.prisma.providerConnectionGrant.delete({ where: { id: other.id } });
    }
  });
});

describe('ProviderConnectionReader', () => {
  it('returns the 8.5 connection view without ciphertext, scoped by organization', async () => {
    const reader = new ProviderConnectionReader(fx.prisma);
    const view = await reader.get(orgA, connection.publicId);
    expect(view).toMatchObject({
      publicId: connection.publicId,
      organizationId: orgA.toString(),
      provider: 'microsoft_365',
      displayName: 'Primary tenant',
      status: 'configuring',
      externalTenantId: tenantId,
      linkedDomains: [{ name: fx.name('a'), providerVerified: true }],
      grants: [
        {
          publicId: grant.publicId,
          profile: 'm365.mail_flow',
          status: 'active',
          observedPermissions: ['Domain.Read.All', 'Organization.Read.All'],
          subjectEmail: null,
        },
      ],
    });
    expect(view!.updatedAt).toBeInstanceOf(Date);
    const text = JSON.stringify(view);
    expect(text).not.toContain('v1.k');
    expect(text).not.toContain(secret);
    expect(await reader.get(orgB, connection.publicId)).toBeNull();
    expect(await reader.listForOrganization(orgB)).toEqual([]);
    expect((await reader.listForOrganization(orgA)).map((c) => c.publicId)).toEqual([
      connection.publicId,
    ]);
  });
});
