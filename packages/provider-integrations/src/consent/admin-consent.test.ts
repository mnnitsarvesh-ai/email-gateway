import { describe, expect, it } from 'vitest';
import {
  buildAdminConsentUrl,
  ConsentUrlError,
  createConsentState,
  hashConsentState,
  isConsentStateShape,
  sanitizeProviderErrorDescription,
} from './admin-consent';

const clientId = '11111111-2222-3333-4444-555555555555';

describe('admin consent', () => {
  it('builds the D3.1 admin-consent URL from configuration and the state', () => {
    const { state, sha256 } = createConsentState();
    expect(isConsentStateShape(state)).toBe(true);
    expect(sha256).toBe(hashConsentState(state));
    expect(sha256).toMatch(/^[0-9a-f]{64}$/);
    const url = new URL(
      buildAdminConsentUrl({
        loginUrl: 'https://login.microsoftonline.com',
        clientId,
        redirectUri: 'https://portal.example.com/integrations/providers/consent-callback',
        state,
      }),
    );
    expect(url.origin + url.pathname).toBe(
      'https://login.microsoftonline.com/organizations/v2.0/adminconsent',
    );
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: clientId,
      scope: 'https://graph.microsoft.com/.default',
      redirect_uri: 'https://portal.example.com/integrations/providers/consent-callback',
      state,
    });
  });

  it('keeps a base path of the login URL (local fake) and allows http only when told', () => {
    const { state } = createConsentState();
    const input = {
      loginUrl: 'http://127.0.0.1:18093/m365/login',
      clientId,
      redirectUri: 'http://localhost:3000/cb',
      state,
    };
    expect(() => buildAdminConsentUrl(input)).toThrow(ConsentUrlError);
    expect(new URL(buildAdminConsentUrl({ ...input, allowHttp: true })).pathname).toBe(
      '/m365/login/organizations/v2.0/adminconsent',
    );
  });

  it('refuses bad client ids, states and URLs', () => {
    const { state } = createConsentState();
    const ok = {
      loginUrl: 'https://login.microsoftonline.com',
      clientId,
      redirectUri: 'https://p.example.com/cb',
      state,
    };
    for (const bad of [
      { clientId: 'not-a-guid' },
      { state: 'short' },
      { state: `${state}&x=1` },
      { loginUrl: 'login.microsoftonline.com' },
      { redirectUri: 'https://user:pw@p.example.com/cb' },
      { redirectUri: 'javascript:alert(1)' },
    ]) {
      expect(() => buildAdminConsentUrl({ ...ok, ...bad }), JSON.stringify(bad)).toThrow(
        ConsentUrlError,
      );
    }
    expect(createConsentState().state).not.toBe(state);
  });

  it('sanitizes provider error descriptions to 256 characters without control characters', () => {
    expect(sanitizeProviderErrorDescription('AADSTS65004:\r\nUser declined\u0000 consent')).toBe(
      'AADSTS65004: User declined consent',
    );
    expect(sanitizeProviderErrorDescription('x'.repeat(400))).toHaveLength(256);
    expect(sanitizeProviderErrorDescription(42)).toBeNull();
    expect(sanitizeProviderErrorDescription('  ')).toBeNull();
  });
});
