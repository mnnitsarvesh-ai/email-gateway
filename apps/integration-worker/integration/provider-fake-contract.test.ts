import { randomBytes } from 'node:crypto';
import { Resolver } from 'node:dns/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { testing } from '@email-gateway/provider-integrations';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

/**
 * The provider-client contract (§10.1/§10.3) against the deployable `provider-fake`
 * (infrastructure/provider-fake): the Compose service when `PROVIDER_FAKE_URL` is set (e.g.
 * `http://127.0.0.1:${PROVIDER_FAKE_HOST_PORT}` with the smtp-test profile up, admin token
 * `PROVIDER_FAKE_ADMIN_TOKEN`), otherwise the same server file started in-process on ephemeral
 * loopback ports. Plus the provider-fake's own additions: health, admin authentication, the
 * admin-consent redirect and the relay-proof.test DNS responder.
 */
const repoRoot = resolve(__dirname, '../../..');
const composeUrl = process.env.PROVIDER_FAKE_URL?.replace(/\/+$/, '');
const composeDns = process.env.PROVIDER_FAKE_DNS; // e.g. 127.0.0.1:1053 (dns-sink, forwards the zone)

interface Running {
  baseUrl: string;
  adminToken: string;
  dns: string | null;
  close: () => Promise<void>;
}

let running: Running | null = null;

async function startFake(): Promise<Running> {
  if (running) return running;
  if (composeUrl) {
    running = {
      baseUrl: composeUrl,
      adminToken: process.env.PROVIDER_FAKE_ADMIN_TOKEN ?? '',
      dns: composeDns ?? null,
      close: () => Promise.resolve(),
    };
    return running;
  }
  const module = (await import(
    pathToFileURL(resolve(repoRoot, 'infrastructure/provider-fake/server.mjs')).href
  )) as {
    startProviderFake: (env: Record<string, string>) => Promise<{
      ports: { http: number; dns: number };
      close: () => Promise<void>;
    }>;
  };
  const adminToken = randomBytes(24).toString('base64url');
  const fake = await module.startProviderFake({
    PROVIDER_FAKE_ADMIN_TOKEN: adminToken,
    PROVIDER_FAKE_HOST: '127.0.0.1',
    PROVIDER_FAKE_HTTP_PORT: '0',
    PROVIDER_FAKE_DNS_PORT: '0',
    PROVIDER_FAKE_LIB: resolve(
      repoRoot,
      'packages/provider-integrations/dist/testing/fake-provider-server.js',
    ),
  });
  running = {
    baseUrl: `http://127.0.0.1:${fake.ports.http}`,
    adminToken,
    dns: `127.0.0.1:${fake.ports.dns}`,
    close: fake.close,
  };
  return running;
}

afterAll(async () => {
  await running?.close();
});

testing.describeProviderClientContract(
  { describe, it, beforeAll, afterAll, beforeEach },
  composeUrl ? 'Compose provider-fake' : 'provider-fake server (in-process)',
  async () => {
    const fake = await startFake();
    return { baseUrl: fake.baseUrl, adminToken: fake.adminToken };
  },
);

describe('provider-fake additions', () => {
  let fake: Running;
  const admin = (path: string, body: unknown, token = fake.adminToken) =>
    fetch(`${fake.baseUrl}${path}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });

  beforeAll(async () => {
    fake = await startFake();
  });

  it('answers /health', async () => {
    const response = await fetch(`${fake.baseUrl}/health`);
    expect(response.status).toBe(200);
  });

  it('protects the admin API with the admin token', async () => {
    expect(
      (await admin('/_fake/m365/consent-tenant', { tenantId: null }, 'wrong-token-value')).status,
    ).toBe(401);
    expect(
      (await admin('/_fake/dns/txt', { name: 'x.relay-proof.test', values: ['v'] }, 'nope')).status,
    ).toBe(401);
  });

  it('simulates the Microsoft admin-consent redirect', async () => {
    const tenantId = testing.testGuid();
    const clientId = testing.testGuid();
    await admin('/_fake/m365/tenants', { tenantId, displayName: 'Consent', domains: [] });
    await admin('/_fake/m365/apps', {
      clientId,
      secret: testing.testClientSecret(),
      requiredRoles: ['Organization.Read.All'],
    });
    await admin('/_fake/m365/consent-tenant', { tenantId });
    const url = new URL(`${fake.baseUrl}/m365/login/organizations/v2.0/adminconsent`);
    url.searchParams.set('client_id', clientId);
    url.searchParams.set(
      'redirect_uri',
      'https://portal.example.test/integrations/providers/consent-callback',
    );
    url.searchParams.set('state', 'state-value');
    const response = await fetch(url, { redirect: 'manual' });
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('location')!);
    expect(location.searchParams.get('tenant')).toBe(tenantId);
    expect(location.searchParams.get('admin_consent')).toBe('True');
    expect(location.searchParams.get('state')).toBe('state-value');
  });

  it('serves TXT records of relay-proof.test registered at runtime', async () => {
    if (!fake.dns) return;
    const name = `sel${randomBytes(3).toString('hex')}._domainkey.it-prov.relay-proof.test`;
    const key = `v=DKIM1; k=rsa; p=${randomBytes(300).toString('base64')}`;
    expect((await admin('/_fake/dns/txt', { name, values: [key] })).status).toBe(204);
    const resolver = new Resolver({ timeout: 2_000, tries: 2 });
    resolver.setServers([fake.dns]);
    const records = await resolver.resolveTxt(name);
    expect(records.map((chunks) => chunks.join(''))).toEqual([key]);
    await expect(resolver.resolveTxt(`missing.${name}`)).rejects.toMatchObject({
      code: 'ENOTFOUND',
    });
    expect((await admin('/_fake/dns/txt/delete', { name })).status).toBe(204);
    await expect(resolver.resolveTxt(name)).rejects.toBeTruthy();
    expect(
      (await admin('/_fake/dns/txt', { name: 'outside.example.com', values: ['x'] })).status,
    ).toBe(400);
  });
});
