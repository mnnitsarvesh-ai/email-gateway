import { describe, expect, it } from 'vitest';
import { fromGoogleUser, fromGraphUser, inScope, normalizeAddress } from './directory';

describe('inventory directory normalization (D11.1)', () => {
  it('normalizes addresses', () => {
    expect(normalizeAddress(' Alex@Contoso-IT.example. ')).toBe('alex@contoso-it.example');
    expect(normalizeAddress('not an address')).toBeNull();
    expect(normalizeAddress(null)).toBeNull();
  });

  it('reads Graph users: SMTP primary, smtp aliases, mail, disabled accounts', () => {
    expect(
      fromGraphUser({
        id: 'u1',
        mail: null,
        userPrincipalName: 'erin@contoso-it.example',
        proxyAddresses: [
          'SMTP:erin@contoso-it.example',
          'smtp:erin.alias@contoso-it.example',
          'SIP:erin@contoso-it.example',
        ],
        accountEnabled: true,
      }),
    ).toEqual({
      providerUserId: 'u1',
      primary: 'erin@contoso-it.example',
      aliases: ['erin.alias@contoso-it.example'],
      enabled: true,
    });
    expect(
      fromGraphUser({
        id: 'u2',
        mail: 'Gale@contoso-it.example',
        userPrincipalName: null,
        proxyAddresses: [],
        accountEnabled: false,
      }),
    ).toEqual({
      providerUserId: 'u2',
      primary: 'gale@contoso-it.example',
      aliases: [],
      enabled: false,
    });
    expect(
      fromGraphUser({
        id: 'u3',
        mail: null,
        userPrincipalName: null,
        proxyAddresses: [],
        accountEnabled: null,
      }),
    ).toBeNull();
  });

  it('reads Google users: suspended or archived are disabled', () => {
    expect(
      fromGoogleUser({
        id: 'g1',
        primaryEmail: 'Erin@Fabrikam-IT.example',
        aliases: ['erin.alias@fabrikam-it.example', 'erin@fabrikam-it.example'],
        suspended: false,
        archived: false,
      }),
    ).toEqual({
      providerUserId: 'g1',
      primary: 'erin@fabrikam-it.example',
      aliases: ['erin.alias@fabrikam-it.example'],
      enabled: true,
    });
    expect(
      fromGoogleUser({
        id: 'g2',
        primaryEmail: 'a@b.example',
        aliases: [],
        suspended: true,
        archived: false,
      })?.enabled,
    ).toBe(false);
  });

  it('keeps users with a primary or alias on a linked domain', () => {
    const linked = new Set(['contoso-it.example']);
    const user = {
      providerUserId: 'x',
      primary: 'frank@partner-org.example',
      aliases: [],
      enabled: true,
    };
    expect(inScope(user, linked)).toBe(false);
    expect(inScope({ ...user, aliases: ['frank@contoso-it.example'] }, linked)).toBe(true);
  });
});
