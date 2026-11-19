import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { describeProviderClientContract } from './contract';
import { FakeProviderServer } from './fake-provider-server';
import { FakeProviderAdminClient } from './helpers';

// The provider-client contract against the in-process fake (§10.1); WP4 runs the same suite
// against the Compose `provider-fake`.
describeProviderClientContract(
  { describe, it, beforeAll, afterAll, beforeEach },
  'in-process FakeProviderServer',
  async () => {
    const adminToken = randomBytes(24).toString('base64url');
    const fake = await new FakeProviderServer({ adminToken }).start();
    return { baseUrl: fake.baseUrl, adminToken, close: () => fake.stop() };
  },
);

describe('FakeProviderServer admin API', () => {
  it('requires the admin token and is disabled without one', async () => {
    const adminToken = randomBytes(24).toString('base64url');
    const fake = await new FakeProviderServer({ adminToken }).start();
    const open = await new FakeProviderServer().start();
    try {
      const wrong = await fetch(`${fake.baseUrl}/_fake/reset`, {
        method: 'POST',
        headers: { authorization: 'Bearer nope' },
      });
      expect(wrong.status).toBe(401);
      const none = await fetch(`${open.baseUrl}/_fake/reset`, {
        method: 'POST',
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(none.status).toBe(401);
      const admin = new FakeProviderAdminClient(fake.baseUrl, adminToken);
      await admin.reset();
      expect((await admin.requests()).some((r) => r.endpoint === 'admin')).toBe(true);
    } finally {
      await fake.stop();
      await open.stop();
    }
  });

  it('simulates the admin-consent redirect', async () => {
    const fake = await new FakeProviderServer().start();
    try {
      const clientId = '11111111-2222-3333-4444-555555555555';
      const tenantId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
      fake.addMicrosoftApp({
        clientId,
        secret: 'fakeSecretValue1',
        requiredRoles: ['Domain.Read.All'],
      });
      fake.setConsentTenant(tenantId);
      const url = `${fake.baseUrl}/m365/login/organizations/v2.0/adminconsent?client_id=${clientId}&redirect_uri=${encodeURIComponent('https://portal.example.test/cb')}&state=abc`;
      const res = await fetch(url, { redirect: 'manual' });
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get('location')!);
      expect(Object.fromEntries(location.searchParams)).toEqual({
        tenant: tenantId,
        admin_consent: 'True',
        state: 'abc',
      });
      fake.setConsentTenant(tenantId, true);
      const declined = new URL((await fetch(url, { redirect: 'manual' })).headers.get('location')!);
      expect(declined.searchParams.get('error')).toBe('access_denied');
    } finally {
      await fake.stop();
    }
  });
});
